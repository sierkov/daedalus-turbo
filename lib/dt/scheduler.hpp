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

    using scheduler_error = error_fmt;

    class scheduled_task_error: public error_fmt {
    public:
        using error_fmt::error_fmt;
    };

    struct scheduled_task {
        int priority;
        std::string task_group;
        std::function<void()> task;

        scheduled_task(int prio, const std::string &tg, std::function<void()> &&t)
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
        std::string task_group;
        std::any result;

        scheduled_result(int prio, const std::string &tg, const std::any &res)
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
     * - allow for parallel execution of multiple heterogeneous task groups when resources allow.
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
    protected:
        alignas(hardware_destructive_interference_size) std::mutex _tasks_mutex;
        alignas(hardware_destructive_interference_size) std::condition_variable _tasks_cv;
        std::priority_queue<scheduled_task> _tasks;
        std::unordered_map<std::string, size_t> _tasks_cnt;

        using observer_list = std::vector<std::function<void(std::any &)>>;
        using observer_map = std::unordered_map<std::string, observer_list>;
        alignas(hardware_destructive_interference_size) std::mutex _observers_mutex;
        observer_map _observers;

        alignas(hardware_destructive_interference_size) std::mutex _results_mutex;
        alignas(hardware_destructive_interference_size) std::condition_variable _results_cv;
        std::priority_queue<scheduled_result> _results;

        std::thread _manager;
        std::vector<std::thread> _workers;
        std::vector<std::string> _worker_tasks;
        const size_t _num_workers;
        std::atomic<bool> _destroy = false;

        template<typename T>
        void _process_results(std::unique_lock<T> &results_lock)
        {
            if (!results_lock) throw scheduler_error("the lock must have already been taken!");
            while (!_results.empty()) {
                auto res = _results.top();
                _results.pop();
                results_lock.unlock();
                {
                    std::unique_lock observers_lock(_observers_mutex);
                    auto it = _observers.find(res.task_group);
                    if (it != _observers.end()) {
                        observer_list to_notify = it->second;
                        observers_lock.unlock();
                        for (const auto &observer: to_notify) observer(res.result);
                    } else {
                        if (res.result.type() == typeid(scheduled_task_error)) throw std::any_cast<scheduled_task_error>(res.result);
                    }
                }
                {
                    std::scoped_lock tasks_lock(_tasks_mutex);
                    auto it = _tasks_cnt.find(res.task_group);
                    if (it != _tasks_cnt.end()) it->second--;
                }
                results_lock.lock();
            }
        }

        void _add_result(int priority, const std::string &task_group, const std::any &res)
        {
            std::unique_lock results_lock(_results_mutex);
            _results.emplace(priority, task_group, res);
            results_lock.unlock();
            _results_cv.notify_one();
        }

        bool _worker_try_execute(size_t worker_idx)
        {
            std::unique_lock lock(_tasks_mutex);
            _tasks_cv.wait(lock, [&] { return _destroy || (!_tasks.empty()); });
            if (_destroy) return false;
            if (!_tasks.empty()) {
                auto task = _tasks.top();
                _tasks.pop();
                _worker_tasks[worker_idx] = task.task_group;
                lock.unlock();
                task.task();
                lock.lock();
                _worker_tasks[worker_idx] = "";
                lock.unlock();
            }
            return true;
        }

        void _worker_thread(size_t worker_idx)
        {
            while (_worker_try_execute(worker_idx)) {
            }
        }

    public:

        scheduler(size_t num_workers=scheduler::default_worker_count())
            : _tasks_mutex(), _tasks_cv(), _tasks(), _tasks_cnt(),
                _observers_mutex(), _observers(),
                _results_mutex(), _results_cv(), _results(),
                _workers(), _worker_tasks(), _num_workers(num_workers)
        {
            if (num_workers == 0) throw error_fmt("the number of worker threads must be greater than zero!");
            // One worker is a special case handled by the process method itself
            if (num_workers >= 2) {
                for (size_t i = 0; i < num_workers; ++i) {
                    _workers.emplace_back([this, i]() { _worker_thread(i); });
                    _worker_tasks.push_back("");
                }
            } else {
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
            return std::thread::hardware_concurrency();
        }

        size_t num_workers() const
        {
            return _num_workers;
        }

        template<typename T, typename ...A>
        void submit(const std::string &task_group, int priority, T &&action, A &&...args)
        {
            std::unique_lock tasks_lock(_tasks_mutex);
            auto action_call = std::bind(std::forward<T>(action), std::forward<A>(args)...);
            std::function<void()> task = [this, action_call, task_group, priority]() {
                try {
                    _add_result(priority, task_group, action_call());
                } catch (std::exception &ex) {
                    _add_result(priority, task_group, std::make_any<scheduled_task_error>("task from group '{}' has failed with '{}' error!", task_group, ex.what()));
                }
            };
            _tasks.emplace(priority, task_group, std::move(task));
            auto it = _tasks_cnt.find(task_group);
            if (it == _tasks_cnt.end()) {
                auto [ new_it, ok ] = _tasks_cnt.emplace(task_group, 1);
                if (!ok) throw scheduler_error("Internal error: task count operation failed!");
            } else {
                it->second++;
            }
            tasks_lock.unlock();
            _tasks_cv.notify_one();
        }

        template<typename T>
        void on_result(const std::string &task_group, T &&observer)
        {
            std::function<void(std::any &)> notify_call = [task_group, observer](std::any &res) { observer(res); };
            const std::scoped_lock lock(_observers_mutex);
            auto it = _observers.find(task_group);
            if (it == _observers.end()) {
                auto [new_it, ok] = _observers.emplace(task_group, 0);
                if (!ok) throw scheduler_error("Internal error: cannot add new observer!");
                it = new_it;
            }
            it->second.push_back(std::move(notify_call));
        }

        // task_count is decremented only after all observers are notified of completion.
        // The code of observers should be aware of that!
        size_t task_count(const std::string &task_group)
        {
            size_t cnt = 0;
            {
                std::scoped_lock lock(_tasks_mutex);
                auto it = _tasks_cnt.find(task_group);
                if (it != _tasks_cnt.end()) cnt = it->second;
            }
            return cnt;
        }

        void process(bool report_progress=true, std::chrono::milliseconds update_interval_ms=std::chrono::milliseconds {1000 },
            std::ostream &report_stream=std::cerr)
        {
            struct task_status {
                size_t active;
                size_t pending;
            };
            size_t max_str = 0;
            std::map<std::string, task_status> status;
            auto next_report = std::chrono::system_clock::now() + update_interval_ms;
            for (;;) {
                // Special case, in one-worker mode execute tasks in the loop
                if (_num_workers == 1) _worker_try_execute(0);
                {
                    std::unique_lock results_lock(_results_mutex);
                    bool have_work = _results_cv.wait_for(results_lock, update_interval_ms, [&]{ return !_results.empty(); });
                    if (have_work) _process_results(results_lock);
                }
                {
                    std::scoped_lock lock(_tasks_mutex);
                    if (_tasks.size() == 0 || (report_progress && std::chrono::system_clock::now() >= next_report)) {
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
                if (report_progress && std::chrono::system_clock::now() >= next_report) {
                    std::ostringstream os;
                    os << "\r";
                    for (const auto &t: status) {
                        os << t.first << ": [" << t.second.active << "/" << t.second.pending << "] ";
                    }
                    const std::string str = os.str();
                    if (str.size() - 1 > max_str) max_str = str.size() - 1;
                    report_stream << std::left << std::setw(max_str) << str;
                    next_report = std::chrono::system_clock::now() + update_interval_ms;
                }
            }
            if (report_progress) {
                report_stream << '\r' << std::left << std::setw(max_str) << ' ' << '\r';
            }
        }

    };

}

#endif // !DAEDALUS_TURBO_SCHEDULER_HPP
