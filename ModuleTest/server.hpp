#pragma once
#include "log_config.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <thread>
#include <typeinfo>
#include <unistd.h>
#include <unordered_map>
#include <vector>

class Socket {
private:
    int _socketfd;

public:
    Socket()
            : _socketfd(-1) {}
    Socket(int fd)
            : _socketfd(fd) {}
    ~Socket() { Close(); }
    // 创建socket
    bool Create() {
        _socketfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (_socketfd < 0) {
            LOG_ERROR("SOCKET CREATE ERROR");
            return false;
        }
        return true;
    }
    // 绑定ip和端口
    bool Bind(const std::string &ip, uint16_t port) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
        if (bind(_socketfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            LOG_ERROR("SOCKET BIND ERROR");
            return false;
        }
        return true;
    }
    // 设置为监听模式
    bool Listen(int backlog = DefaultBackLog) {
        int ret = listen(_socketfd, backlog);
        if (ret < 0) {
            LOG_ERROR("SOCKET LISTEN ERROR");
            return false;
        }
        return true;
    }
    // 建立连接
    bool Connect(const std::string &ip, uint16_t port) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
        int ret = connect(_socketfd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            LOG_ERROR("SOCKET CONNECT ERROR");
            return false;
        }
        return true;
    }
    // 获取新连接并返回新的连接描述符
    int Accept() {
        // 不关心客户端的ip和端口信息
        int newfd = accept(_socketfd, nullptr, nullptr);
        if (newfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                LOG_DEBUG("SOCKET ACCEPT ERROR AGAIN");
            } else {
                LOG_ERROR("SOCKET ACCEPT ERROR");
            }
        }
        return newfd;
    }
    ssize_t Recv(void *buffer, size_t len, int flag = 0) {
        ssize_t ret = recv(_socketfd, buffer, len, flag);
        if (ret < 0)  // 出错或者对端关闭连接
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                LOG_DEBUG("SOCKET RECV ERROR AGAIN");
                return -1;
            } else {
                LOG_ERROR("SOCKET RECV ERROR errno=%d(%s)", errno, strerror(errno));
                return -2;
            }
        }
        return ret;
    }
    ssize_t NonBlockRecv(void *buffer, size_t len) { return Recv(buffer, len, MSG_DONTWAIT); }
    ssize_t Send(const void *buffer, size_t len, int flag = 0) {
        ssize_t ret = send(_socketfd, buffer, len, flag);
        if (ret <= 0)  // 出错或者对端关闭连接
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return 0;
            LOG_ERROR("SOCKET SEND ERROR errno=%d(%s)", errno, strerror(errno));
            return -1;
        }
        return ret;
    }
    ssize_t NonBlockSend(void *buffer, size_t len) { return Send(buffer, len, MSG_DONTWAIT); }
    bool CreateServer(uint16_t port, const std::string &ip = "0.0.0.0", bool flag = 0) {
        // 1.创建socket
        if (Create() == false)
            return false;
        // 复用地址
        ReuseAddress();
        // 2.绑定ip和端口
        if (Bind(ip, port) == false)
            return false;
        // 3.设置为监听模式
        if (Listen() == false)
            return false;
        // 设置套接字为非阻塞
        // if (flag)
        // SetNonBlock();
        return true;
    }
    bool CreateClient(uint16_t port, const std::string &ip) {
        // 1.创建socket
        if (Create() == false)
            return false;
        // 无需手动绑定ip和端口号，系统自动分配从而防止端口号冲突
        // 2.连接服务器
        if (Connect(ip, port) == false)
            return false;
        return true;
    }
    bool Close() {
        if (_socketfd != -1) {
            close(_socketfd);
            _socketfd = -1;
        }
        return true;
    }
    void ReuseAddress() {
        int opt = 1;
        setsockopt(_socketfd, SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt));
        opt = 1;
        setsockopt(_socketfd, SOL_SOCKET, SO_REUSEPORT, (void *)&opt, sizeof(opt));
    }
    void SetNonBlock() {
        int flags = fcntl(_socketfd, F_GETFL, 0);
        fcntl(_socketfd, F_SETFL, flags | O_NONBLOCK);
    }
    int Fd() { return _socketfd; }
};

#define DefaultBufferSize 1024
class Buffer {
private:
    std::vector<char> _buffer;  // 使用vector来充当缓冲区
    size_t _reader_idx;         // 读下标
    size_t _writer_idx;         // 写下标
public:
    Buffer() {
        _buffer.resize(DefaultBufferSize);
        _reader_idx = 0;
        _writer_idx = 0;
    }
    char *Begin() { return &*_buffer.begin(); }
    // 获取当前读出起始地址
    char *ReadPosition() { return Begin() + _reader_idx; }
    // 获取当前写入起始地址
    char *WritePosition() { return Begin() + _writer_idx; }

    // 获取缓冲区前部空闲空间大小
    size_t HeadIdleSize() { return _reader_idx; }
    // 获取缓冲区后部空闲空间大小
    size_t TailIdleSize() { return _buffer.size() - _writer_idx; }

    // 获取可读数据大小
    size_t ReadAbleSize() { return _writer_idx - _reader_idx; }

    // 将读下标向后移动特定距离
    void MoveReadOffset(size_t len) {
        assert(len <= ReadAbleSize());  // 确保读取数据不越界
        _reader_idx += len;
    }
    // 将写下标向后移动特定距离
    void MoveWriteOffset(size_t len) {
        assert(len <= TailIdleSize());  // 确保能够放得下数据
        _writer_idx += len;
    }
    // 确保空间足够（如果空间足够就将数据前移，不够就直接扩容）
    void EnsureEnoughSpace(size_t len) {
        if (len <= TailIdleSize())  // 缓冲区后部的空闲空间足够
            return;
        if (len <= HeadIdleSize() + TailIdleSize())  // 缓冲区总体空闲空间足够
        {
            // 将数据拷贝到数组的起始位置
            std::copy(ReadPosition(), ReadPosition() + ReadAbleSize(), Begin());
            _writer_idx = ReadAbleSize();
            _reader_idx = 0;  // 注意_writer_idx与_reader_idx顺序！
            return;
        }
        // 说明数组中空闲区域的位置不足，此时直接扩容但不移动数据
        _buffer.resize(_buffer.size() + len);
        return;
    }
    // 写入数据
    void Write(const void *data, size_t len) {
        EnsureEnoughSpace(len);
        char *str = (char *)data;
        std::copy(str, str + len, WritePosition());
    }
    void WriteString(const std::string &str) { Write(&str[0], str.size()); }
    void WriteBuffer(Buffer &buffer) {
        Write(buffer.ReadPosition(), buffer.ReadAbleSize());  //?
    }
    void WriteAndPush(const void *data, size_t len) {
        Write(data, len);
        MoveWriteOffset(len);
    }
    void WriteStringAndPush(const std::string &str) {
        WriteString(str);
        MoveWriteOffset(str.size());
    }
    void WriteBufferAndPush(Buffer &buffer) {
        WriteBuffer(buffer);
        MoveWriteOffset(buffer.ReadAbleSize());
    }
    // 读取数据
    void Read(void *buffer, size_t len) {
        assert(len <= ReadAbleSize());
        std::copy(ReadPosition(), ReadPosition() + len, (char *)buffer);
    }
    void ReadAndPop(void *buf, size_t len) {
        Read(buf, len);
        MoveReadOffset(len);
    }
    std::string ReadAsString(size_t len) {
        assert(len <= ReadAbleSize());
        std::string str;
        str.resize(len);
        Read(&str[0], len);  //?
        return str;
    }
    std::string ReadAsStringAndPop(size_t len) {
        std::string str = ReadAsString(len);
        MoveReadOffset(len);
        return str;
    }

    char *GetCRLF() {
        char *res = (char *)memchr(ReadPosition(), '\n', ReadAbleSize());
        return res;
    }
    std::string GetLine() {
        char *crlf = GetCRLF();
        if (crlf) {
            size_t len = crlf - ReadPosition() + 1;  // 将\n也读出来
            return ReadAsString(len);
        }
        return "";
    }
    std::string GetLineAndPop() {
        std::string line = GetLine();
        MoveReadOffset(line.size());
        return line;
    }
};

class Any {
private:
    class holder {
    public:
        virtual ~holder() {}
        virtual const std::type_info &type() = 0;
        virtual holder *clone() = 0;
    };
    template<class T>
    class placeholder : public holder {
    public:
        placeholder(const T &val)
                : _val(val) {}
        // 获取子类对象保存的数据类型
        virtual const std::type_info &type() { return typeid(T); }
        // 针对当前的对象自身，克隆出一个新的子类对象
        virtual holder *clone() { return new placeholder(_val); }

    public:
        T _val;
    };

    holder *_content;  // 父类指针，可以指向子类的对象（多态）
public:
    Any()
            : _content(nullptr) {}
    ~Any() {
        if (_content)
            delete _content;
    }
    template<class T>
    Any(const T &val) {
        _content = new placeholder<T>(val);
    }
    Any(const Any &other) { _content = (other._content ? other._content->clone() : nullptr); }
    Any &swap(Any &other) {
        std::swap(_content, other._content);
        return *this;
    }
    // 返回子类对象保存数据的指针
    template<class T>
    T *get() {
        // 目的数据类型必须与保存数据的类型一致
        assert(typeid(T) == _content->type());
        return &(static_cast<placeholder<T> *>(_content)->_val);
    }
    //=运算符重载
    template<class T>
    Any &operator=(const T &val) {
        // 为val构造一个临时对象，然后与当前对象进行交换，当临时对象析构的时候，释放当前对象原有的内容
        Any(val).swap(*this);
        return *this;
    }
    Any &operator=(const Any &other) {
        Any(other).swap(*this);
        return *this;
    }
};

class Poller;
class Channel;
class EventLoop;

class Channel {
    using EventCallBack = std::function<void()>;

private:
    int _fd;                  // 该Channel所绑定的文件描述符
    EventLoop *_loop;         // 该Channel所属的事件循环器
    uint32_t _events;         // 监控的事件
    uint32_t _revents;        // 发生的事件
    EventCallBack _read_cb;   // 读事件被触发的回调函数
    EventCallBack _write_cb;  // 写事件被触发的回调函数
    EventCallBack _error_cb;  // 错误事件被触发的回调函数
    EventCallBack _close_cb;  // 断开事件被触发的回调函数
    EventCallBack _event_cb;  // 任意事件被触发的回调函数
public:
    Channel(int fd, EventLoop *loop)
            : _fd(fd)
            , _loop(loop)
            , _events(0)
            , _revents(0) {}
    // 获取文件描述符
    int Fd() { return _fd; }
    // 获取监控的事件
    uint32_t Events() { return _events; }
    // 被触发的事件
    void SetREvents(uint32_t revents) { _revents = revents; }
    // 设置读事件的回调函数
    void SetReadCallback(EventCallBack read_cb) { _read_cb = read_cb; }
    // 设置写事件的回调函数
    void SetWriteCallback(EventCallBack write_cb) { _write_cb = write_cb; }
    // 设置错误事件的回调函数
    void SetErrorCallback(EventCallBack error_cb) { _error_cb = error_cb; }
    // 设置断开事件的回调函数
    void SetCloseCallback(EventCallBack close_cb) { _close_cb = close_cb; }
    // 设置任意事件的回调函数
    void SetEventCallback(EventCallBack event_cb) { _event_cb = event_cb; }
    // 是否可读
    bool ReadAble() { return _events & EPOLLIN; }
    // 是否可写
    bool WriteAble() { return _events & EPOLLOUT; }
    // 开启读事件监控
    void EnableRead() {
        _events |= (EPOLLIN | EPOLLRDHUP);
        Update();
    }
    // 开启写事件监控
    void EnableWrite() {
        _events |= EPOLLOUT;
        Update();
    }
    // 关闭读事件监控
    void DisableRead() {
        _events &= ~EPOLLIN;
        Update();
    }
    // 关闭写事件监控
    void DisableWrite() {
        _events &= ~EPOLLOUT;
        Update();
    }
    // 关闭所有事件监控
    void DisableAll() {
        _events = 0;
        Update();
    }
    // 从EventLoop中移除该Channel
    void Remove();
    void Update();
    void Handler() {
        if ((_revents & EPOLLIN) || (_revents & EPOLLPRI) || (_revents & EPOLLRDHUP)) {
            if (_read_cb)
                _read_cb();
            // 事件处理完毕后刷新活跃度
        }
        // 有可能释放连接的事件，一次只处理一个（保证安全）
        if (_revents & EPOLLOUT) {
            if (_write_cb)
                _write_cb();
            // 事件处理完毕后刷新活跃度
        }
        if (_revents & EPOLLERR) {
            if (_error_cb)
                _error_cb();
        }
        if (_revents & EPOLLHUP) {
            if (_close_cb)
                _close_cb();
        }
        if (_event_cb) {
            _event_cb();
        }
    }
};

#define MAXEVENTS 1024
class Poller {
private:
    int _epfd;
    struct epoll_event _events[MAXEVENTS];
    std::unordered_map<int, Channel *> _channels;

private:
    void Update(Channel *channel, int op) {
        struct epoll_event ev;
        ev.data.fd = channel->Fd();
        ev.events = channel->Events();
        if (epoll_ctl(_epfd, op, channel->Fd(), &ev) < 0) {
            if (op & EPOLL_CTL_ADD)
                LOG_ERROR("EPOLL CTL ADD ERROR");
            LOG_ERROR("EPOLL CTL ERROR");
        }
    }
    bool CheckChannel(Channel *channel) {
        int fd = channel->Fd();
        auto it = _channels.find(fd);
        if (it == _channels.end()) {
            return false;
        }
        return true;
    }

public:
    Poller() {
        _epfd = epoll_create(MAXEVENTS);
        if (_epfd < 0) {
            LOG_ERROR("EPOLL CREATE ERROR");
        }
    }
    ~Poller() { close(_epfd); }
    void UpdateEvent(Channel *channel) {
        int fd = channel->Fd();
        if (fd < 0)
            return;
        bool exists = CheckChannel(channel);
        uint32_t evs = channel->Events();
        if (evs == 0) {
            if (exists) {
                // 删除channel
                Update(channel, EPOLL_CTL_DEL);
                _channels.erase(fd);
            }
            return;
        }
        if (!exists) {
            // 新增channel
            Update(channel, EPOLL_CTL_ADD);
            _channels[fd] = channel;
        } else {
            // 修改channel
            Update(channel, EPOLL_CTL_MOD);
        }
        // if (CheckChannel(channel) == false) {
        //     // 新增channel

        //     Update(channel, EPOLL_CTL_ADD);
        //     _channels[channel->Fd()] = channel;
        // } else {
        //     // 修改channel
        //     Update(channel, EPOLL_CTL_MOD);
        // }
    }
    void RemoveEvent(Channel *channel) {
        if (CheckChannel(channel) == false) {
            return;
        }
        Update(channel, EPOLL_CTL_DEL);
        _channels.erase(channel->Fd());
    }
    void Poll(std::vector<Channel *> *actvie) {
        int nfds = epoll_wait(_epfd, _events, MAXEVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) {
                return;
            }
            LOG_ERROR("EPOLL WAIT ERROR,%s\n", strerror(errno));
            abort();
        }
        for (int i = 0; i < nfds; ++i) {
            int fd = _events[i].data.fd;
            auto it = _channels.find(fd);
            assert(it != _channels.end());
            Channel *channel = it->second;
            channel->SetREvents(_events[i].events);
            actvie->push_back(channel);
        }
    }
};

using TaskFunc = std::function<void()>;
using ReleaseFunc = std::function<void()>;
class Timer {
private:
    uint64_t _id;  // Timer的_id是由主base线程进行统一分配，防止多线程中有_id重复从而导致哈希表中的信息错乱
    uint32_t _timeout;
    bool _cancel;
    TaskFunc _task_cb;
    ReleaseFunc _release_cb;

public:
    Timer(uint64_t id, uint32_t timeout, const TaskFunc &cb)
            : _id(id)
            , _timeout(timeout)
            , _task_cb(cb)
            , _cancel(false) {}
    void SetRelease(const ReleaseFunc &cb) { _release_cb = cb; }
    void Cancel() { _cancel = true; }
    ~Timer() {
        if (!_cancel)  // 任务未取消才执行
            _task_cb();
        _release_cb();
    }
    uint32_t GetTimeout() { return _timeout; }
};

class TimeWheel {
    using PtrTask = std::shared_ptr<Timer>;
    using WeakTask = std::weak_ptr<Timer>;

private:
    int _tick;                                 // 当前的秒针，走到哪个位置就释放哪个位置
    int _capacity;                             // 表盘的大小
    std::vector<std::vector<PtrTask>> _wheel;  // 存储表盘中的内容
    std::unordered_map<uint64_t, WeakTask>
        _timers;  // 将Timer存入到哈希表中方便我们寻找到对应的事件进行更新操作
                  // 此处使用weak_ptr是防止_wheel中的内容引用计数无法减到零从而无法析构的问题

    EventLoop *_loop;
    int _timefd;  // 用于定时触发时间轮转动的文件描述符
                  // 设置为每秒钟触发一次，将其加入到epoll监视的事件中，如果触发则通过回调函数让时间轮转动
    std::unique_ptr<Channel> _timer_channel;
    void RemoveTimer(uint64_t id)  // 从unordered_map中移除Timer信息
    {
        auto it = _timers.find(id);
        if (it == _timers.end()) {
            return;
        }
        _timers.erase(it);
    }

public:
    int CreateTimerFd() {
        int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (tfd < 0) {
            LOG_ERROR("TIMERFD CREATE ERROR");
            abort();
        }
        struct itimerspec new_value;
        memset(&new_value, 0, sizeof(new_value));
        new_value.it_value.tv_sec = 1;     // 1秒后开始触发
        new_value.it_interval.tv_sec = 1;  // 每隔1秒触发一次
        if (timerfd_settime(tfd, 0, &new_value, NULL) < 0) {
            LOG_ERROR("TIMERFD SETTIME ERROR");
            abort();
        }
        return tfd;
    }
    int ReadTimeFd() {
        uint64_t times;
        int ret = read(_timefd, &times, sizeof(uint64_t));
        if (ret < 0) {
            LOG_ERROR("TIMERFD READ ERROR");
            abort();
        }
        return times;
    }
    void TimerAddInLoop(uint64_t id, uint32_t delay, const TaskFunc &cb) {
        PtrTask pt(new Timer(id, delay, cb));  // 创建一个Timer对象
        // 将Timer对象添加到表盘中
        int pos = (_tick + delay) % _capacity;
        _wheel[pos].push_back(pt);
        // 将Timer对象添加到哈希表中方便管理
        _timers[id] = WeakTask(pt);  // 构造一个匿名的WeakTask对象然后再赋值，简化为直接构造
        // 当Timer对象释放的时候需要将其对应的信息从unordered_map中移除，绑定回调函数
        pt->SetRelease(std::bind(&TimeWheel::RemoveTimer, this, id));
    }
    void TimerRefreshInLoop(uint64_t id) {
        // 通过id寻找到对应的weak_ptr从而形成一个新的shared_ptr对象存储到表盘中，此时之前的shared_ptr对象释放时候Timer对象就不会被析构了，这样就达到了更新生命周期的目的
        auto it = _timers.find(id);
        if (it == _timers.end()) {
            return;
        }
        // 说明寻找到了相应的weak_ptr
        PtrTask pt = it->second.lock();
        int pos = (_tick + pt->GetTimeout()) % _capacity;
        _wheel[pos].push_back(pt);
    }
    void TimerCancelInLoop(uint64_t id) {
        auto it = _timers.find(id);
        if (it == _timers.end()) {
            return;
        }
        PtrTask pt = it->second.lock();
        if (pt)
            pt->Cancel();  // 取消该任务
    }
    // 存在线程安全问题，仅在EventLoop线程内调用
    bool TimerCheck(uint64_t id) {
        auto it = _timers.find(id);
        if (it == _timers.end()) {
            return false;
        }
        return true;
    }

public:
    TimeWheel(EventLoop *loop)
            : _tick(0)
            , _capacity(60)
            , _wheel(_capacity)
            , _loop(loop)
            , _timefd(CreateTimerFd())
            , _timer_channel(new Channel(_timefd, loop)) {
        _timer_channel->SetReadCallback(std::bind(&TimeWheel::OnTime, this));
        _timer_channel->EnableRead();
    }

    // 定时器中有_timer成员，定时器信息的操作可能在多线程中进行，因此需要考虑线程安全的问题，我们需要将这些操作放到EventLoop线程中执行
    void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc &cb);
    void TimerRefresh(uint64_t id);
    void TimerCancel(uint64_t id);

    void RunTimerTask() {
        _tick = (_tick + 1) % _capacity;
        _wheel[_tick].clear();
    }
    void OnTime() {
        int times = ReadTimeFd();
        for (int i = 0; i < times; ++i) { RunTimerTask(); }
    }
};

class EventLoop {
private:
    using Functor = std::function<void()>;
    std::thread::id _thread_id;               // 事件循环所属线程的id
    int _event_fd;                            // 用于唤醒事件循环的文件描述符
    Poller _poller;                           // 事件监控
    std::unique_ptr<Channel> _event_channel;  // 用于监听_event_fd的Channel
    std::vector<Functor> _task;               // 任务队列
    std::mutex _mutex;
    TimeWheel _time_wheel;

public:
    static int CreateEventFd() {
        int evtfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (evtfd < 0) {
            LOG_ERROR("EVENTFD CREATE ERROR");
            abort();
        }
        return evtfd;
    }

public:
    EventLoop()
            : _thread_id(std::this_thread::get_id())
            , _event_fd(CreateEventFd())
            , _poller()
            , _event_channel(new Channel(_event_fd, this))
            , _time_wheel(this) {
        _event_channel->SetReadCallback(std::bind(&EventLoop::ReadEventFd, this));
        _event_channel->EnableRead();
    }
    void ReadEventFd()  // 读取_event_fd中的数据，防止一直触发可读事件
    {
        uint64_t value;
        ssize_t ret = read(_event_fd, &value, sizeof(value));
        if (ret < 0) {
            if (errno == EAGAIN)
                return;

            LOG_ERROR("EVENTFD READ ERROR");
            abort();
        }
    }
    void WeakUpEventFd()  // 写入数据到_event_fd，唤醒事件循环
    {
        uint64_t value = 1;
        int ret = write(_event_fd, &value, sizeof(value));
        if (ret < 0) {
            if (errno == EAGAIN)
                return;
            LOG_ERROR("EVENTFD WRITE ERROR");
            abort();
        }
    }
    // 事件监控 -> 就绪事件处理 -> 执行任务
    void Start() {
        while (true) {
            std::vector<Channel *> actives;
            _poller.Poll(&actives);
            for (auto channel : actives) { channel->Handler(); }
            RunAllTasks();
        }
    }
    void RunAllTasks() {
        std::vector<Functor> tasks;
        {
            std::unique_lock<std::mutex> lock(_mutex);
            tasks.swap(_task);
        }
        if (tasks.empty())
            return;
        for (const Functor &task : tasks) { task(); }
    }
    void RunInLoop(const Functor cb) {
        if (IsInLoop()) {
            return cb();
        }
        return QueueInLoop(cb);
    }
    // 将任务压入任务队列
    void QueueInLoop(const Functor cb) {
        {
            std::unique_lock<std::mutex> lock(_mutex);
            _task.push_back(cb);
        }
        // 有可能因为没有事件触发导致epoll一直等待，因此我们需要使用EventFd唤醒它
        // 使用EventFd写入数据来触发可读事件
        WeakUpEventFd();
    }
    bool IsInLoop()  // 判断是否属于EventLoop线程
    {
        return _thread_id == std::this_thread::get_id();
    }
    void AssertInLoop() { return assert(_thread_id == std::this_thread::get_id()); }
    void UpdateEvent(Channel *channel)  // 更新Channel事件
    {
        _poller.UpdateEvent(channel);
    }
    void RemoveEvent(Channel *channel)  // 移除Channel事件
    {
        _poller.RemoveEvent(channel);
    }
    void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc &cb) { _time_wheel.TimerAdd(id, delay, cb); }
    void TimerRefresh(uint64_t id) { _time_wheel.TimerRefresh(id); }
    void TimerCancel(uint64_t id) { _time_wheel.TimerCancel(id); }
    bool TimerCheck(uint64_t id) { return _time_wheel.TimerCheck(id); }
    bool HasTimer(uint64_t id) { return _time_wheel.TimerCheck(id); }
};

typedef enum { CONNECTED, CONNECTING, DISCONNECTED, DISCONNECTING } ConnectionStatus;
class Connection : public std::enable_shared_from_this<Connection> {
    using PTRConnection = std::shared_ptr<Connection>;

private:
    uint64_t _conn_id;              // 连接的id，用来唯一标识该连接
    uint64_t _timer_id;             // 定时器的id，用来唯一标识定时器，为了方便我们将其与_conn_id的值设置一致
    bool _enable_inactive_release;  // 是否启用不活跃连接释放
    int _sockfd;                    // 连接对应的文件描述符
    EventLoop *_loop;               // 连接关联的对应EventLoop线程
    ConnectionStatus _conn_status;  // 连接的当前状态
    Socket _socket;                 // 管理连接套接字
    Channel _channel;               // 管理连接事件
    Buffer _in_buffer;              // 接收缓冲区
    Buffer _out_buffer;             // 发送缓冲区
    Any _context;                   // 请求的上下文
    // 由组件使用者自定义的回调函数
    using ConnectionCallback = std::function<void(const PTRConnection &)>;
    using MessageCallback = std::function<void(const PTRConnection &, Buffer *)>;
    using CloseCallback = std::function<void(const PTRConnection &)>;
    using AnyEventCallback = std::function<void(const PTRConnection &)>;
    ConnectionCallback _conn_cb;  // 连接建立回调函数
    MessageCallback _msg_cb;      // 消息到达回调函数
    CloseCallback _close_cb;      // 连接关闭回调函数
    AnyEventCallback _event_cb;   // 任何事件触发回调函数
    // 组件内关闭连接所用的回调函数，服务器将所有连接管理起来，当连接关闭时需要将其从服务器的连接列表中移除
    CloseCallback _server_close_cb;

private:
    // 处理从socket套接字读取数据事件，需要将数据从socket中取出然后放入到接收缓冲区中
    void HandleRead() {
        char buffer[65536];
        int ret = _socket.NonBlockRecv(buffer, sizeof(buffer));
        if (ret <= 0) {
            if (ret == 0)
                return Release();
            if (ret == -1)
                return;
            return ShutdownInLoop();
        }
        // 将读取到的数据放入到接收缓冲区中
        buffer[ret] = '\0';
        _in_buffer.WriteAndPush(buffer, ret);
        // 调用消息到达回调函数
        if (_msg_cb)
            _msg_cb(shared_from_this(), &_in_buffer);
    }
    // 处理向socket套接字写入数据事件，需要将发送缓冲区中的数据发送到socket中
    void HandleWrite() {
        ssize_t ret = _socket.NonBlockSend(_out_buffer.ReadPosition(), _out_buffer.ReadAbleSize());
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                // 无法发送数据，等待下一次写事件触发
                return;
            }
            // 发送数据出错，关闭连接
            return Release();
        }
        _out_buffer.MoveReadOffset(ret);
        // 判断发送缓冲区中是否还有数据需要发送
        if (_out_buffer.ReadAbleSize() == 0) {
            // 关闭写事件的监控，否则会一致触发写事件因为存在空闲区域
            _channel.DisableWrite();
            if (_conn_status == DISCONNECTING) {
                // 说明是用户调用了关闭连接操作，并且数据已经发送完毕，可以关闭连接了
                return Release();
            }
        }
    }
    void HandleClose() {
        // 处理剩余未处理数据
        if (_in_buffer.ReadAbleSize() > 0) {
            _msg_cb(shared_from_this(), &_in_buffer);
        }
        // 调用EventLoop内释放函数
        return Release();
    }
    void HandleError() { return HandleClose(); }
    void HandleEvent() {
        // 刷新事件活跃度
        if (_enable_inactive_release == true)
            _loop->TimerRefresh(_timer_id);
        // 调用用户设置的任意事件回调函数
        if (_event_cb)
            _event_cb(shared_from_this());
    }
    void EstablishInLoop() {
        // 1.修改连接状态 2.启动读事件 3.调用连接建立回调函数
        _conn_status = CONNECTED;
        _channel.EnableRead();
        if (_conn_cb)
            _conn_cb(shared_from_this());
    }
    // 真正的释放连接
    void ReleaseInLoop() {
        // 1.修改连接状态 2.移除连接的事件监控 3.关闭socket文件描述符 4.如果有定时器就将其移除 5.调用连接关闭回调函数
        // 6.调用服务器的关闭连接回调函数
        if (_conn_status == DISCONNECTED)
            return;
        _conn_status = DISCONNECTED;
        _channel.Remove();
        _socket.Close();
        if (_loop->HasTimer(_timer_id))
            _loop->TimerCancel(_timer_id);
        if (_close_cb)
            _close_cb(shared_from_this());
        if (_server_close_cb) {  // _server_close_cb
            _server_close_cb(shared_from_this());
        }
        // 在这里打印
    }
    // 不是实际的发送，而是将数据放入发送缓冲区并且启动写事件监控
    void SendInLoop(const char *data, size_t len) {
        // 1.将数据放入发送缓冲区 2.启动写事件监控
        // 防止数据是临时数据，及时将数据进行保存
        Buffer buf;
        buf.WriteAndPush(data, len);
        _out_buffer.WriteBufferAndPush(buf);
        _channel.EnableWrite();
    }
    // 不是实际的关闭连接，而是修改连接状态并且等待发送缓冲区的数据发送完毕和接收缓冲区的数据处理完毕后再关闭连接
    void ShutdownInLoop() {
        // 1.设置连接状态 2.处理接收缓冲区数据 3.处理发送缓冲区数据
        if (_conn_status == DISCONNECTING || _conn_status == DISCONNECTED)
            return;
        _conn_status = DISCONNECTING;
        if (_in_buffer.ReadAbleSize() > 0)
            _msg_cb(shared_from_this(), &_in_buffer);
        if (_out_buffer.ReadAbleSize() == 0)
            Release();  // 说明发送缓冲区没有数据可以发送，直接关闭连接
        else
            _channel.EnableWrite();  // 说明发送缓冲区还有数据需要发送，启动写事件监控
    }
    // 启动非活跃连接释放定时器
    void EnableInactiveReleaseInLoop(int sec) {
        // 1.修改对应的标志位 2.如果存在定时器就刷新 3.如果不存在就直接新增
        _enable_inactive_release = true;
        if (_loop->TimerCheck(_timer_id)) {
            _loop->TimerRefresh(_timer_id);
        } else {
            _loop->TimerAdd(_timer_id, sec, std::bind(&Connection::ReleaseInLoop, this));
        }
    }
    void CancelInactiveReleaseInLoop() {
        // 1.修改对应的标志位 2.如果存在定时器就取消
        _enable_inactive_release = false;
        if (_loop->TimerCheck(_timer_id)) {
            _loop->TimerCancel(_timer_id);
        }
    }
    void UpgradeInLoop(
        const Any &context, const ConnectionCallback &conn_cb, const MessageCallback &msg_cb,
        const CloseCallback &close_cb, const AnyEventCallback &event_cb) {
        _context = context;
        _conn_cb = conn_cb;
        _msg_cb = msg_cb;
        _close_cb = close_cb;
        _event_cb = event_cb;
    }

public:
    Connection(EventLoop *loop, uint64_t conn_id, int sockfd)
            : _conn_id(conn_id)
            , _timer_id(conn_id)
            , _enable_inactive_release(false)
            , _sockfd(sockfd)
            , _loop(loop)
            , _conn_status(CONNECTING)
            , _socket(sockfd)
            , _channel(sockfd, loop) {
        _channel.SetReadCallback(std::bind(&Connection::HandleRead, this));
        _channel.SetWriteCallback(std::bind(&Connection::HandleWrite, this));
        _channel.SetCloseCallback(std::bind(&Connection::HandleClose, this));
        _channel.SetErrorCallback(std::bind(&Connection::HandleError, this));
        _channel.SetEventCallback(std::bind(&Connection::HandleEvent, this));
    }
    ~Connection() { LOG_INFO("Connection %lu destructed", _conn_id); }
    int Fd() { return _sockfd; }
    uint64_t GetConnId() { return _conn_id; }
    bool Connected() { return _conn_status == CONNECTED; }
    void SetContext(const Any &context) { _context = context; }
    Any *GetContext() { return &_context; }
    void SetConnectionCallback(const ConnectionCallback &cb) { _conn_cb = cb; }
    void SetMessageCallback(const MessageCallback &cb) { _msg_cb = cb; }
    void SetCloseCallback(const CloseCallback &cb) { _close_cb = cb; }
    void SetAnyEventCallback(const AnyEventCallback &cb) { _event_cb = cb; }
    void SetSvrCloseCallback(const CloseCallback &cb) { _server_close_cb = cb; }
    void Established() { _loop->RunInLoop(std::bind(&Connection::EstablishInLoop, this)); }
    void Send(const char *data, size_t len) {
        _loop->RunInLoop(std::bind(&Connection::SendInLoop, this, data, len));
    }
    void ShutDown()  // 关闭连接，但需要检查是否有数据未发送完毕
    {
        _loop->RunInLoop(std::bind(&Connection::ShutdownInLoop, this));
    }
    // 确保连接释后事件事件不在会被触发，防止前面的事件为定时器事件然后导致连接被释放从而影响后面连接事件触发时候访问非法内存
    void Release() { _loop->QueueInLoop(std::bind(&Connection::ReleaseInLoop, this)); }
    void EnableInactiveRelease(int sec) {
        _loop->RunInLoop(std::bind(&Connection::EnableInactiveReleaseInLoop, this, sec));
    }
    void CancelInactiveRelease() {
        _loop->RunInLoop(std::bind(&Connection::CancelInactiveReleaseInLoop, this));
    }
    // 协议切换——重置上下文和回调函数，该函数必须在对应的EventLoop线程中调用
    // 防备新事件触发时候切换任务还未执行，从而导致数据和协议不对等！
    void Upgrade(
        const Any &context, const ConnectionCallback &conn_cb, const MessageCallback &msg_cb,
        const CloseCallback &close_cb, const AnyEventCallback &event_cb) {
        _loop->AssertInLoop();
        _loop->RunInLoop(
            std::bind(&Connection::UpgradeInLoop, this, context, conn_cb, msg_cb, close_cb, event_cb));
    }
};

class Acceptor {
private:
    Socket _listenfd;
    EventLoop *_loop;
    Channel _channel;

    using AccptorCallback = std::function<void(int)>;
    AccptorCallback _accept_cb;

private:
    int CreateSvrFd(uint16_t port) {
        bool ret = _listenfd.CreateServer(port);
        assert(ret == true);
        return _listenfd.Fd();
    }
    void HandleRead() {
        while (true) {
            //_listenfd.SetNonBlock();
            int newfd = _listenfd.Accept();
            if (newfd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    // 没有新的连接请求
                    break;
                }
                LOG_ERROR("ACCEPT ERROR,%s", strerror(errno));
                break;
            }
            if (_accept_cb)
                _accept_cb(newfd);
        }
    }

public:
    Acceptor(EventLoop *loop, uint16_t port)
            : _listenfd(CreateSvrFd(port))
            , _loop(loop)
            , _channel(_listenfd.Fd(), loop) {
        _channel.SetReadCallback(std::bind(&Acceptor::HandleRead, this));
    }
    void SetAcceptCallback(AccptorCallback cb) { _accept_cb = cb; }
    // Listen函数是确保在设置好回调函数后才开始监听连接请求，防止因为没有设置好回调函数而错过连接请求并且会有资源浪费（新的连接没有close）
    void Listen() { _channel.EnableRead(); }
};

class LoopThread {
private:
    std::mutex _mutex;              // 互斥锁
    std::condition_variable _cond;  // 条件变量
    EventLoop *_loop;               // 事件循环指针
    std::thread _thread;            // 线程对象 新线程的入口函数
public:
    void ThreadFunc() {
        EventLoop loop;
        {
            std::unique_lock<std::mutex> lock(_mutex);
            _loop = &loop;
            // 有可能_loop还没有实例化就GetLoop被调用了，因此需要通知其创建成功
            _cond.notify_one();  // 通知创建成功
        }
        loop.Start();  // 启动事件循环
    }

public:
    LoopThread()
            : _loop(nullptr)
            , _thread(std::thread(&LoopThread::ThreadFunc, this)) {}
    EventLoop *GetLoop() {
        EventLoop *loop = nullptr;
        {
            std::unique_lock<std::mutex> lock(_mutex);
            _cond.wait(lock, [&]() { return _loop != nullptr; });
            loop = _loop;
        }
        return loop;
    }
};

class LoopThreadPool {
private:
    int _thread_count;
    EventLoop *_base_loop;               // 主线程的事件循环
    std::vector<LoopThread *> _threads;  // 存储子线程对象
    std::vector<EventLoop *> _loops;     // 存储子线程的事件循环
    int _next_idx;                       // 下一个被选中的线程索引
public:
    LoopThreadPool(EventLoop *base_loop)
            : _base_loop(base_loop)
            , _thread_count(0)
            , _next_idx(0) {}
    void SetThreadCount(int thread_count) { _thread_count = thread_count; }
    // 创建从属线程
    void CreateDependedLoops() {
        if (_thread_count > 0) {
            _threads.resize(_thread_count);
            _loops.resize(_thread_count);
            for (int i = 0; i < _thread_count; ++i) {
                _threads[i] = new LoopThread();
                _loops[i] = _threads[i]->GetLoop();
            }
        }
    }
    // RR轮转获取下一个从属线程
    EventLoop *GetNextLoop() {
        if (_thread_count == 0) {
            return _base_loop;
        }
        _next_idx = (_next_idx + 1) % _thread_count;
        return _loops[_next_idx];
    }
};

class TcpServer {
    using PTRConnection = std::shared_ptr<Connection>;

private:
    int _next_id;
    int _thread_count;
    int _timeout;  // 非活跃连接释放时间
    bool _enable_inactive_release;
    uint16_t _port;
    EventLoop _base_loop;
    Acceptor _acceptor;
    LoopThreadPool _pool;
    std::unordered_map<uint64_t, PTRConnection> _conns;
    using ConnectionCallback = std::function<void(const PTRConnection &)>;
    using MessageCallback = std::function<void(const PTRConnection &, Buffer *)>;
    using CloseCallback = std::function<void(const PTRConnection &)>;
    using AnyEventCallback = std::function<void(const PTRConnection &)>;
    ConnectionCallback _conn_cb;  // 连接建立回调函数
    MessageCallback _msg_cb;      // 消息到达回调函数
    CloseCallback _close_cb;      // 连接关闭回调函数
    AnyEventCallback _event_cb;   // 任何事件触发回调函数
    using Functor = std::function<void()>;

private:
    void RunAfterInLoop(const Functor &cb, uint32_t delay) {
        _next_id++;
        _base_loop.TimerAdd(0, delay, cb);
    }
    void HandleNewConnection(int sockfd) {
        uint64_t conn_id = _next_id++;
        EventLoop *loop = _pool.GetNextLoop();
        PTRConnection conn(new Connection(loop, conn_id, sockfd));
        conn->SetConnectionCallback(_conn_cb);
        conn->SetMessageCallback(_msg_cb);
        conn->SetCloseCallback(_close_cb);
        conn->SetAnyEventCallback(_event_cb);
        conn->SetSvrCloseCallback(std::bind(&TcpServer::RemoveConnectionInLoop, this, std::placeholders::_1));
        if (_enable_inactive_release)
            conn->EnableInactiveRelease(_timeout);
        _conns.emplace(conn_id, conn);
        conn->Established();
    }
    void RemoveConnectionInLoop(const PTRConnection &conn) {
        LOG_DEBUG("RemoveConnectionInLoop called");
        uint64_t id = conn->GetConnId();
        if (_conns.find(id) == _conns.end()) {
            return;
        }
        _conns.erase(id);
    }
    void RemoveConnection(const PTRConnection &conn) {
        LOG_DEBUG("RemoveConnection called");
        _base_loop.RunInLoop(std::bind(&TcpServer::RemoveConnectionInLoop, this, conn));
    }

public:
    TcpServer(uint16_t port)
            : _next_id(0)
            , _thread_count(0)
            , _timeout(0)
            , _enable_inactive_release(false)
            , _port(port)
            , _base_loop()
            , _acceptor(&_base_loop, port)
            , _pool(&_base_loop) {
        _acceptor.SetAcceptCallback(std::bind(&TcpServer::HandleNewConnection, this, std::placeholders::_1));
    }
    void SetThreadCount(int thread_count) {
        _thread_count = thread_count;
        _pool.SetThreadCount(thread_count);
    }
    void SetInactiveReleaseTime(int timeout) {
        _enable_inactive_release = true;
        _timeout = timeout;
    }
    void SetConnectionCallback(const ConnectionCallback &cb) { _conn_cb = cb; }
    void SetMessageCallback(const MessageCallback &cb) { _msg_cb = cb; }
    void SetCloseCallback(const CloseCallback &cb) { _close_cb = cb; }
    void SetAnyEventCallback(const AnyEventCallback &cb) { _event_cb = cb; }
    void EnableInactiveRelease(int timeout) {
        _timeout = timeout;
        _enable_inactive_release = true;
    }
    // 添加定时任务
    void RunAfter(const Functor &cb, uint32_t delay) {
        _base_loop.RunInLoop(std::bind(&TcpServer::RunAfterInLoop, this, cb, delay));
    }
    void Start() {
        LOG_INFO("Server starting...");
        _pool.CreateDependedLoops();
        _acceptor.Listen();
        _base_loop.Start();
    }
};

void Channel::Remove() {
    // 调用EventLoop中的函数将该Channel从epoll中移除
    _loop->RemoveEvent(this);
}
void Channel::Update() { _loop->UpdateEvent(this); }

void TimeWheel::TimerAdd(uint64_t id, uint32_t delay, const TaskFunc &cb) {
    // 由于时间轮可能会被多个线程操作，因此我们需要将添加任务的操作放入到时间轮所属的EventLoop线程中执行
    _loop->RunInLoop(std::bind(&TimeWheel::TimerAddInLoop, this, id, delay, cb));
}
void TimeWheel::TimerRefresh(uint64_t id) {
    // 由于时间轮可能会被多个线程操作，因此我们需要将刷新任务的操作放入到时间轮所属的EventLoop线程中执行
    _loop->RunInLoop(std::bind(&TimeWheel::TimerRefreshInLoop, this, id));
}
void TimeWheel::TimerCancel(uint64_t id) {
    // 由于时间轮可能会被多个线程操作，因此我们需要将取消任务的操作放入到时间轮所属的EventLoop线程中执行
    _loop->RunInLoop(std::bind(&TimeWheel::TimerCancelInLoop, this, id));
}

// 为了避免在网络编程中，当向一个已经关闭的连接写入数据时，导致整个进程意外退出。
class NetWork {
public:
    NetWork() {
        LOG_INFO("Ignore SIGPIPE signal");
        signal(SIGPIPE, SIG_IGN);
    }
};

static NetWork nw;