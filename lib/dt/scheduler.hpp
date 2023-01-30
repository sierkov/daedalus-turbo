/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_SCHEDULER_HPP
#define DAEDALUS_TURBO_SCHEDULER_HPP 1

#include <any>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <iomanip>
#include <new>
#include <map>
#include <mutex>
#include <queue>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>
#include <dt/util.hpp>

namespace daedalus_turbo {

#   ifdef __cpp_lib_hardware_interference_size
        using std::hardware_destructive_interference_size;
#   else
        constexpr std::size_t hardware_destructive_interference_size = 64;
#   endif

    using namespace std;

    class scheduled_task_error: public error {
    public:
        using error::error;
    };

    struct scheduled_task {
        int priority;
        string task_group;
        function<void()> task;

        scheduled_task(int prio, const string &tg, function<void()> &&t)
            : priority(prio), task_group(tg), task(t)
        {
        }

        bool operator<(const scheduled_task &t) const noexcept
        {
            return priority < t.priority;
        }
    };

    struct scheduled_result {
        int priority;
        string task_group;
        std::any result;

        scheduled_result(int prio, const string &tg, const std::any &res)
            : priority(prio), task_group(tg), result(res)
        {
        }

        bool operator<(const scheduled_result &r) const noexcept
        {
            return priority < r.priority;
        }
    };

    /*
     * Design objectives:
     * - allow for parallel execution of multiple heteregeneous task gorups when resources allow.
     * - always provide resources to the highest-priority task group first
     * - allow external observers to schedule further tasks
     * - allow external observers to be notified of task completions within a task group
     * - allow external observers to be notified about the general task execution progress
     * Implementation objectives:
     * - ensure that locking is minimal
     * - ensure that locks and atomics are allocated in different cache lines for optimal performance
     * - all notification are processed by a single thread to make the processing tasks simpler
     */

    class scheduler {
        alignas(hardware_destructive_interference_size) mutex _tasks_mutex;
        alignas(hardware_destructive_interference_size) condition_variable _tasks_cv;
        priority_queue<scheduled_task> _tasks;
        unordered_map<string, size_t> _tasks_cnt;

        using observer_list = vector<function<void(any &)>>;
        using observer_map = unordered_map<string, observer_list>;
        alignas(hardware_destructive_interference_size) mutex _observers_mutex;
        observer_map _observers;

        alignas(hardware_destructive_interference_size) mutex _results_mutex;
        alignas(hardware_destructive_interference_size) condition_variable _results_cv;
        priority_queue<scheduled_result> _results;

        thread _manager;
        vector<thread> _workers;
        vector<string> _worker_tasks;
        const size_t _num_workers;
        atomic<bool> _destroy = false;

        template<typename T>
        void _process_results(unique_lock<T> &results_lock)
        {
            if (!results_lock) throw error("the lock must have already been taken!");
            while (!_results.empty()) {
                auto res = _results.top();
                _results.pop();
                results_lock.unlock();
                {
                    unique_lock observers_lock(_observers_mutex);
                    auto it = _observers.find(res.task_group);
                    if (it != _observers.end()) {
                        observer_list to_notify = it->second;
                        observers_lock.unlock();
                        try {
                            for (const auto &observer: to_notify) observer(res.result);
                        } catch (...) {
                            if (res.result.type() == typeid(scheduled_task_error)) throw std::any_cast<scheduled_task_error>(res.result);
                            else throw;
                        }
                    }
                }
                {
                    scoped_lock tasks_lock(_tasks_mutex);
                    auto it = _tasks_cnt.find(res.task_group);
                    if (it != _tasks_cnt.end()) it->second--;
                }
                results_lock.lock();
            }
        }

        void _add_result(int priority, const string &task_group, const std::any &res)
        {
            unique_lock results_lock(_results_mutex);
            _results.emplace(priority, task_group, res);
            results_lock.unlock();
            _results_cv.notify_one();
        }

        void _worker_thread(size_t worker_idx)
        {
            for (;;) {
                unique_lock lock(_tasks_mutex);
                _tasks_cv.wait(lock, [&] { return _destroy || (!_tasks.empty()); });
                if (_destroy) break;
                if (_tasks.empty()) continue;
                auto task = _tasks.top();
                _tasks.pop();
                _worker_tasks[worker_idx] = task.task_group;
                lock.unlock();
                task.task();
                lock.lock();
                _worker_tasks[worker_idx] = "";
                lock.unlock();
            }
        }

    public:

        scheduler(size_t num_workers=scheduler::default_worker_count())
            : _tasks_mutex(), _tasks_cv(), _tasks(), _tasks_cnt(),
                _observers_mutex(), _observers(),
                _results_mutex(), _results_cv(), _results(),
                _workers(), _worker_tasks(), _num_workers(num_workers)
        {
            for (size_t i = 0; i < num_workers; ++i) {
                _workers.emplace_back([this, i]() { _worker_thread(i); });
                _worker_tasks.push_back("");
            }
        }

        ~scheduler()
        {
            _destroy = true;
            _tasks_cv.notify_all();
            _results_cv.notify_all();
            for (auto &t: _workers)
                t.join();
        }

        static inline size_t default_worker_count()
        {
            return thread::hardware_concurrency();
        }

        size_t num_workers() const
        {
            return _num_workers;
        }

        template<typename T, typename ...A>
        void submit(const string &task_group, int priority, T &&action, A &&...args)
        {
            unique_lock tasks_lock(_tasks_mutex);
            auto action_call = bind(forward<T>(action), forward<A>(args)...);
            function<void()> task = [this, action_call, task_group, priority]() {
                try {
                    _add_result(priority, task_group, action_call());
                } catch (std::exception &ex) {
                    _add_result(priority, task_group, std::make_any<scheduled_task_error>("task from group '%s' has failed with '%s' error!", task_group.c_str(), ex.what()));
                }
            };
            _tasks.emplace(priority, task_group, move(task));
            auto it = _tasks_cnt.find(task_group);
            if (it == _tasks_cnt.end()) {
                auto [ new_it, ok ] = _tasks_cnt.emplace(task_group, 1);
                if (!ok) throw error("Internal error: task count operation failed!");
            } else {
                it->second++;
            }
            tasks_lock.unlock();
            _tasks_cv.notify_one();
        }

        template<typename T>
        void on_result(const string &task_group, T &&observer)
        {
            function<void(any &)> notify_call = [task_group, observer](any &res) { observer(res); };
            const scoped_lock lock(_observers_mutex);
            auto it = _observers.find(task_group);
            if (it == _observers.end()) {
                auto [new_it, ok] = _observers.emplace(task_group, 0);
                if (!ok) throw error("Internal error: cannot add new observer!");
                it = new_it;
            }
            it->second.push_back(move(notify_call));
        }

        // task_count is decremented only after all observers are notified of completion.
        // The code of observers should be aware of that!
        size_t task_count(const string &task_group)
        {
            size_t cnt = 0;
            {
                scoped_lock lock(_tasks_mutex);
                auto it = _tasks_cnt.find(task_group);
                if (it != _tasks_cnt.end()) cnt = it->second;
            }
            return cnt;
        }

        void process(bool report_progress=true, chrono::milliseconds update_interval_ms=1000ms, ostream &report_stream=cerr)
        {
            struct task_status {
                size_t active;
                size_t pending;
            };
            size_t max_str = 0;
            map<string, task_status> status;
            auto next_report = chrono::system_clock::now() + update_interval_ms;
            for (;;) {
                {
                    unique_lock results_lock(_results_mutex);
                    bool have_work = _results_cv.wait_for(results_lock, update_interval_ms, [&]{ return !_results.empty(); });
                    if (have_work) _process_results(results_lock);
                }
                {
                    scoped_lock lock(_tasks_mutex);
                    if (_tasks.size() == 0 || (report_progress && chrono::system_clock::now() >= next_report)) {
                        status.clear();
                        for (const auto &tc: _tasks_cnt) {
                            if (tc.second > 0) {
                                status[tc.first].pending += tc.second;
                            }
                        }
                        for (const auto &wt: _worker_tasks) {
                            if (wt.size() > 0) {
                                status[wt].active += 1;
                            }
                        }
                        if (status.size() == 0) break;
                    }
                }
                if (report_progress && chrono::system_clock::now() >= next_report) {
                    ostringstream os;
                    os << "\r";
                    for (const auto &t: status) {
                        os << t.first << ": [" << t.second.active << "/" << t.second.pending << "] ";
                    }
                    const string str = os.str();
                    if (str.size() - 1 > max_str) max_str = str.size() - 1;
                    report_stream << std::left << std::setw(max_str) << str;
                    next_report = chrono::system_clock::now() + update_interval_ms;
                }
            }
            if (report_progress) {
                report_stream << '\r' << std::left << std::setw(max_str) << ' ' << '\r';
            }
        }

    };

}

#endif // !DAEDALUS_TURBO_SCHEDULER_HPP
