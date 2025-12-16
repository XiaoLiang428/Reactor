#pragma once
#include <stdint.h>
#include <functional>
#include <vector>
#include <unordered_map>
#include <memory>
#include <unistd.h>

using TaskFunc = std::function<void()>;
using ReleaseFunc = std::function<void()>;
class Timer
{
private:
    uint64_t _id; // Timer的_id是由主base线程进行统一分配，防止多线程中有_id重复从而导致哈希表中的信息错乱
    uint32_t _timeout;
    bool _cancel;
    TaskFunc _task_cb;
    ReleaseFunc _release_cb;

public:
    Timer(uint64_t id, uint32_t timeout, const TaskFunc &cb) : _id(id), _timeout(timeout), _task_cb(cb), _cancel(false) {}
    void SetRelease(const ReleaseFunc &cb) { _release_cb = cb; }
    void Cancel() { _cancel = true; }
    ~Timer()
    {
        if (!_cancel) //任务未取消才执行
            _task_cb();
        _release_cb();
    }
    uint32_t GetTimeout() { return _timeout; }
};

class TimeWheel
{
    using PtrTask = std::shared_ptr<Timer>;
    using WeakTask = std::weak_ptr<Timer>;

private:
    int _tick;                                      // 当前的秒针，走到哪个位置就释放哪个位置
    int _capacity;                                  // 表盘的大小
    std::vector<std::vector<PtrTask>> _wheel;       // 存储表盘中的内容
    std::unordered_map<uint64_t, WeakTask> _timers; // 将Timer存入到哈希表中方便我们寻找到对应的事件进行更新操作 此处使用weak_ptr是防止_wheel中的内容引用计数无法减到零从而无法析构的问题
    void RemoveTimer(uint64_t id)                   // 从unordered_map中移除Timer信息
    {
        auto it = _timers.find(id);
        if (it == _timers.end())
        {
            return;
        }
        _timers.erase(it);
    }

public:
    TimeWheel() : _tick(0), _capacity(60), _wheel(_capacity) {};
    void AddTimer(uint64_t id, uint32_t delay, const TaskFunc &cb)
    {
        PtrTask pt(new Timer(id, delay, cb)); // 创建一个Timer对象
        // 将Timer对象添加到表盘中
        int pos = (_tick + delay) % _capacity;
        _wheel[pos].push_back(pt);
        // 将Timer对象添加到哈希表中方便管理
        _timers[id] = WeakTask(pt); // 构造一个匿名的WeakTask对象然后再赋值，简化为直接构造
        // 当Timer对象释放的时候需要将其对应的信息从unordered_map中移除，绑定回调函数
        pt->SetRelease(std::bind(&TimeWheel::RemoveTimer, this, id));
    }
    void RefreshTimer(uint64_t id)
    {
        // 通过id寻找到对应的weak_ptr从而形成一个新的shared_ptr对象存储到表盘中，此时之前的shared_ptr对象释放时候Timer对象就不会被析构了，这样就达到了更新生命周期的目的
        auto it = _timers.find(id);
        if (it == _timers.end())
        {
            return;
        }
        // 说明寻找到了相应的weak_ptr
        PtrTask pt = it->second.lock();
        int pos = (_tick + pt->GetTimeout()) % _capacity;
        _wheel[pos].push_back(pt);
    }
    void TimerCancel(uint64_t id)
    {
        auto it = _timers.find(id);
        if (it == _timers.end())
        {
            return;
        }
        PtrTask pt = it->second.lock();
        if(pt) pt->Cancel();//取消该任务
    }
    void RunTimerTask()
    {
        _tick = (_tick + 1) % _capacity;
        _wheel[_tick].clear();
    }
};
