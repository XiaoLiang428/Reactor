#pragma once
#include "Poller.hpp"
#include <cstdint>
#include <functional>
#include <sys/epoll.h>
class Poller;
class Channel {
    using EventCallBack = std::function<void()>;

private:
    int _fd;                  // 该Channel所绑定的文件描述符
    Poller *_poller;          // 该Channel所属的事件循环器
    uint32_t _events;         // 监控的事件
    uint32_t _revents;        // 发生的事件
    EventCallBack _read_cb;   // 读事件被触发的回调函数
    EventCallBack _write_cb;  // 写事件被触发的回调函数
    EventCallBack _error_cb;  // 错误事件被触发的回调函数
    EventCallBack _close_cb;  // 断开事件被触发的回调函数
    EventCallBack _event_cb;  // 任意事件被触发的回调函数
public:
    Channel(int fd, Poller *poller)
            : _fd(fd)
            , _poller(poller)
            , _events(0)
            , _revents(0) {}
    // 获取文件描述符
    int Fd() { return _fd; }
    // 获取监控的事件
    uint32_t Events() { return _events; }
    // 被触发的事件
    void SetREvents(uint32_t revents) { _revents = revents; }
    // 设置读事件的回调函数
    void SetReadAble(EventCallBack read_cb) { _read_cb = read_cb; }
    // 设置写事件的回调函数
    void SetWriteAble(EventCallBack write_cb) { _write_cb = write_cb; }
    // 设置错误事件的回调函数
    void SetErrorAble(EventCallBack error_cb) { _error_cb = error_cb; }
    // 设置断开事件的回调函数
    void SetCloseAble(EventCallBack close_cb) { _close_cb = close_cb; }
    // 设置任意事件的回调函数
    void SetEventAble(EventCallBack event_cb) { _event_cb = event_cb; }
    // 是否可读
    bool ReadAble() { return _events & EPOLLIN; }
    // 是否可写
    bool WriteAble() { return _events & EPOLLOUT; }
    // 开启读事件监控
    void EnableRead() {
        _events |= EPOLLIN;
        _poller->UpdateEvent(this);
    }
    // 开启写事件监控
    void EnableWrite() {
        _events |= EPOLLOUT;
        _poller->UpdateEvent(this);
    }
    // 关闭读事件监控
    void DisableRead() {
        _events &= ~EPOLLIN;
        _poller->UpdateEvent(this);
    }
    // 关闭写事件监控
    void DisableWrite() {
        _events &= ~EPOLLOUT;
        _poller->UpdateEvent(this);
    }
    // 关闭所有事件监控
    void DisableAll() {
        _events = 0;
        _poller->UpdateEvent(this);
    }
    // 从EventLoop中移除该Channel
    void Remove() {
        // 调用EventLoop中的函数将该Channel从epoll中移除
        _poller->RemoveEvent(this);
    }
    void Handler() {
        if ((_revents & EPOLLIN) || (_revents & EPOLLRDHUP) || (_revents & EPOLLPRI)) {
            if (_read_cb)
                _read_cb();
            // 不管任何事件发生都调用该回调函数
            if (_event_cb)
                _event_cb();
            // 事件处理完毕后刷新活跃度
        }
        // 有可能释放连接的事件，一次只处理一个（保证安全）
        if (_revents & EPOLLOUT) {
            if (_write_cb)
                _write_cb();
            // 不管任何事件发生都调用该回调函数
            if (_event_cb)
                _event_cb();
            // 事件处理完毕后刷新活跃度
        } else if (_revents & EPOLLERR) {
            if (_event_cb)
                _event_cb();
            if (_error_cb)
                _error_cb();  // 一旦出错就会释放连接，再调用_event_cb没有意义
        } else if (_revents & EPOLLHUP) {
            if (_event_cb)
                _event_cb();
            if (_close_cb)
                _close_cb();  // 一旦断开就会释放连接，再调用_event_cb没有意义
        }
    }
};