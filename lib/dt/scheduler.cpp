/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <list>
#include <queue>
#include <source_location>
//#include <thread>
#include <unordered_map>
#include <vector>
#include <boost/thread.hpp>
#include <dt/file.hpp>
#include <dt/logger.hpp>
#include <dt/memory.hpp>
#include <dt/progress.hpp>
#include <dt/scheduler.hpp>
#include <dt/timer.hpp>
#include <dt/mutex.hpp>
#include <dt/static-map.hpp>

namespace fmt {
    template<>
    struct formatter<boost::thread::id>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out())
        {
            std::ostringstream ss {};
            ss << v;
            return fmt::format_to(ctx.out(), "{}", ss.str());
        }
    };
}

namespace daedalus_turbo {
    struct scheduler::impl {
        explicit impl(const size_t user_num_workers)
            : _num_workers { _find_num_workers(user_num_workers) }
        {
            if (_num_workers == 0)
                throw error("the number of worker threads must be greater than zero!");
            logger::info("scheduler started, worker count: {}", _num_workers);
            _worker_tasks.resize(_num_workers);
            map<boost::thread::id, size_t> ids {};
            // One worker is a special case handled by the process method itself
            if (_num_workers == 1) {
                ids.emplace(boost::this_thread::get_id(), 0);
            } else {
                boost::thread::attributes attrs {};
                attrs.set_stack_size(16 << 20);
                for (size_t i = 0; i < _num_workers; ++i) {
                    _workers.emplace_back(attrs, [this, i]() { _worker_thread(i); });
                    ids.emplace(_workers.back().get_id(), i);
                }
            }
            _worker_ids = ids;
        }

        ~impl()
        {
            _destroy = true;
            _tasks_cv.notify_all();
            _results_cv.notify_all();
            for (auto &w: _workers)
                w.join();
            _workers.clear();

            logger::debug("scheduler's peak RAM use: {} MB", memory::max_usage_mb());
            logger::debug("scheduler's cumulative cpu utilization statistics by task group:");
            task_stats_map grouped_stats {};
            double total_cpu_time = 0;
            for (const auto &[task_name, stats]: _task_stats) {
                const auto pos = task_name.find(':');
                auto [it, created] = grouped_stats.try_emplace(std::string { pos == task_name.npos ? task_name : task_name.substr(0, pos) }, stats);
                if (!created) {
                    it->second.submitted += stats.submitted;
                    it->second.completed += stats.completed;
                    it->second.cpu_time += stats.cpu_time;
                }
                total_cpu_time += stats.cpu_time;
            }
            std::vector<std::pair<std::string, task_stat>> sorted_stats {};
            std::copy(grouped_stats.begin(), grouped_stats.end(), std::back_inserter(sorted_stats));
            std::sort(sorted_stats.begin(), sorted_stats.end(), [](const auto &a, const auto &b) { return a.second.cpu_time > b.second.cpu_time; });
            for (const auto &[task_name, stats]: sorted_stats) {
                logger::debug("task: {} submitted: {} completed: {} cpu_time: {:0.3f} sec ({:0.1f}%)",
                    task_name, stats.submitted, stats.completed, stats.cpu_time, 100 * stats.cpu_time / total_cpu_time);
            }
            logger::debug("total cpu time spent by all tasks: {:0.3f} sec", total_cpu_time);
        }

        size_t num_workers() const
        {
            return _num_workers;
        }

        size_t num_observers(const std::string &task_group) const
        {
            mutex::scoped_lock ob_lk { _observers_mutex };
            const auto it = _observers.find(task_group);
            return it != _observers.end() ? it->second.size() : 0;
        }

        size_t active_workers() const
        {
            return _num_active.load();
        }

        size_t cancel(const cancel_predicate &pred)
        {
            size_t num_cancelled = 0;
            mutex::unique_lock tasks_lock { _tasks_mutex };
            task_queue new_tasks {};
            while (!_tasks.empty()) {
                auto task = _tasks.top();
                _tasks.pop();
                if (pred(task.task_group, task.param)) {
                    --_task_stats[task.task_group].queued;
                    ++num_cancelled;
                } else {
                    new_tasks.emplace(std::move(task));
                }
            }
            _tasks = std::move(new_tasks);
            return num_cancelled;
        }

        void submit(const std::string &task_group, int64_t priority, const std::function<std::any ()> &action, std::optional<std::any> param={})
        {
            mutex::unique_lock tasks_lock { _tasks_mutex };
            _tasks.emplace(priority, task_group, action, std::move(param));
            auto [ it, created ] = _task_stats.emplace(task_group, task_stat { 1, 1 });
            if (!created) {
                ++it->second.submitted;
                ++it->second.queued;
            }
            tasks_lock.unlock();
            _tasks_cv.notify_one();
        }

        void on_result(const std::string &task_group, const std::function<void (std::any &&)> &observer, bool replace_if_exists=false)
        {
            if (task_count(task_group) != 0)
                throw error(fmt::format("observers for task '{}' must be configured before task submission!", task_group));
            const mutex::scoped_lock lock { _observers_mutex };
            auto [ it, created ] = _observers.emplace(task_group, 0);
            if (!created && replace_if_exists)
                it->second.clear();
            it->second.emplace_front(observer);
        }

        void on_completion(const std::string &task_group, size_t task_count, const std::function<void()> &action)
        {
            mutex::scoped_lock lk { _completion_mutex };
            const auto [it, created] = _completion_actions.try_emplace(task_group, action, task_count);
            if (!created)
                throw error(fmt::format("duplicate completion handler for {}", task_group));
        }

        void clear_observers(const std::string &task_group)
        {
            mutex::scoped_lock ob_lk { _observers_mutex };
            _observers.erase(task_group);
        }

        size_t task_count(const std::string &task_group)
        {
            size_t cnt = 0;
            {
                mutex::scoped_lock lock { _tasks_mutex };
                auto it = _task_stats.find(task_group);
                if (it != _task_stats.end())
                    cnt = it->second.queued;
            }
            return cnt;
        }

        size_t task_count()
        {
            size_t cnt = 0;
            {
                mutex::scoped_lock lock{ _tasks_mutex };
                for (const auto &[task_name, stats]: _task_stats)
                    cnt += stats.queued;
            }
            return cnt;
        }

        bool process_ok(bool report_status=true, const std::source_location &loc=std::source_location::current())
        {
            timer t { fmt::format("scheduler::process_ok call from {}:{}", loc.file_name(), loc.line()), logger::level::debug, true };
            bool must_be_false = false;
            if (!_process_running.compare_exchange_strong(must_be_false, true))
                throw error("nested calls to scheduler::process are prohibited!");
            const auto finalize = [&] {
                {
                    mutex::scoped_lock observers_lock { _observers_mutex };
                    _observers.clear();
                }
                {
                    mutex::scoped_lock completion_lock { _completion_mutex };
                    _completion_actions.clear();
                }
                _process_running = false;
                _success = true;
            };
            try {
                _process(report_status);
                const bool res = _success.load();
                finalize();
                return res;
            } catch (const std::exception &ex) {
                logger::warn("scheduler::process failed: {}", ex.what());
                finalize();
                throw;
            }
        }

        void process(bool report_status=true, const std::source_location &loc=std::source_location::current())
        {
            if (!process_ok(report_status, loc))
                throw error("some scheduled tasks have failed, please consult logs for more details");
        }

        void process_once(bool report_status=true)
        {
            // to ensure that result observers are always called from one thread
            // process once will process results only if there is no _process running
            _process_once(report_status, false, !_process_running);
        }

        void wait_all_done(const std::string &task_group, const size_t task_count,
                            const std::function<void ()> &submit_tasks, const std::function<void (std::any &&, size_t, size_t)> &process_res)
        {
            bool exp_false = false;
            if (!_wait_all_done_running.compare_exchange_strong(exp_false, true))
                throw error("concurrent wait_all_done calls are not allowed!");
            if (_num_workers < 4)
                throw error(fmt::format("wait_all_done relies on a high worker count but got {} worker threads!", _num_workers));
            std::atomic_size_t errors = 0;
            try {
                static constexpr std::chrono::milliseconds report_period{10000};
                const auto wait_start = std::chrono::system_clock::now();
                auto next_warn = wait_start + report_period;
                std::atomic_size_t done_parts = 0;
                on_result(task_group, [&done_parts, &errors, process_res](auto &&res) {
                    ++done_parts;
                    if (res.type() != typeid(scheduled_task_error)) [[likely]] {
                        process_res(std::move(res), done_parts.load(), errors.load());
                    } else {
                        ++errors;
                    }
                }, true);
                submit_tasks();
                const auto process_results = !_process_running.load();
                while (done_parts < task_count) {
                    const auto now = std::chrono::system_clock::now();
                    if (now >= next_warn) {
                        next_warn = now + report_period;
                        logger::warn(
                                "wait_all_done takes longer than expected task: {} count: {} done: {} errors: {} process_results: {} waiting for: {} secs",
                                task_group, task_count, done_parts.load(), errors.load(), process_results,
                                std::chrono::duration_cast<std::chrono::seconds>(now - wait_start).count());
                    }
                    _process_once(true, false, process_results);
                }
                _wait_all_done_running = false;
            } catch (const std::exception &ex) {
                logger::warn("wait_all_done failed with std::exception: {}", ex.what());
                _wait_all_done_running = false;
                throw;
            } catch (...) {
                logger::warn("wait_all_done failed with an unknown exception");
                _wait_all_done_running = false;
                throw;
            }
            if (errors > 0)
                throw scheduler_error(fmt::format("wait_all_done {} - there were failed tasks; cannot continue", task_group));
        }
    private:
        struct completion_action {
            std::function<void()> action {};
            size_t todo = 0;
            size_t done = 0;
        };
        using task_queue = std::priority_queue<scheduled_task>;

        struct task_stat {
            size_t submitted = 0;
            size_t queued = 0;
            size_t completed = 0;
            double cpu_time = 0.0;
        };
        using task_stats_map = std::unordered_map<std::string, task_stat>;

        mutable mutex::unique_lock::mutex_type _tasks_mutex alignas(mutex::alignment) {};
        std::condition_variable_any _tasks_cv alignas(mutex::alignment) {};
        task_queue _tasks {};
        task_stats_map _task_stats {};

        using observer_list = std::list<std::function<void (std::any &&)>>;
        using observer_map = std::unordered_map<std::string, observer_list>;
        mutable mutex::unique_lock::mutex_type _observers_mutex alignas(mutex::alignment) {};
        observer_map _observers {};

        mutex::unique_lock::mutex_type _results_mutex alignas(mutex::alignment) {};
        std::condition_variable_any _results_cv alignas(mutex::alignment) {};
        std::priority_queue<scheduled_result> _results {};
        std::atomic_bool _results_processed = false;

        mutex::unique_lock::mutex_type _completion_mutex alignas(mutex::alignment) {};
        std::map<std::string, completion_action> _completion_actions {};

        std::vector<boost::thread> _workers {};
        static_map<boost::thread::id, size_t> _worker_ids {};
        std::vector<std::optional<std::string>> _worker_tasks {};
        const size_t _num_workers;
        std::atomic_size_t _num_active = 0;
        std::atomic_bool _destroy { false };
        std::atomic_bool _success { true };
        std::atomic_bool _process_running { false };
        std::atomic_bool _wait_all_done_running { false };
        std::atomic<std::chrono::time_point<std::chrono::system_clock>> _report_next_time { std::chrono::system_clock::now() + default_update_interval };

        static size_t _find_num_workers(size_t user_num_workers)
        {
            const char *env_workers_str = std::getenv("DT_WORKERS");
            if (env_workers_str != nullptr) {
                size_t env_workers = std::stoul(env_workers_str);
                if (env_workers != 0)
                    return env_workers;
            }
            return user_num_workers;
        }

        std::optional<size_t> _get_worker_id() const
        {
            const auto w_it = _worker_ids.find(boost::this_thread::get_id());
            if (w_it != _worker_ids.end())
                return w_it->second;
            return {};
        }

        void _report_status()
        {
            const auto now = std::chrono::system_clock::now();
            auto prev_next_time = _report_next_time.load();
            if (now >= prev_next_time) {
                const auto next_next_time = now + default_update_interval;
                if (_report_next_time.compare_exchange_strong(prev_next_time, next_next_time)) {
                    size_t num_tasks = 0;
                    std::map<std::string, size_t> active_tasks {};
                    {
                        mutex::scoped_lock tasks_lk { _tasks_mutex };
                        for (const auto &[task_name, stats]: _task_stats)
                            num_tasks += stats.queued;
                        for (const auto &task_name: _worker_tasks) {
                            if (task_name)
                                ++active_tasks[*task_name];
                        }
                    }
                    logger::debug("scheduler tasks total: {} active: {}", num_tasks, active_tasks);
                    progress::get().inform();
                }
            }
        }

        void _process_results(mutex::unique_lock &results_lock)
        {
            if (!results_lock)
                throw scheduler_error("the lock must have already been taken!");
            bool must_be_false = false;
            if (_results_processed.compare_exchange_strong(must_be_false, true)) {
                try {
                    while (!_results.empty()) {
                        std::optional<std::string> completion_task_group {};
                        // ensure that the result object is destroyed before completion actions are called
                        {
                            auto res = _results.top();
                            _results.pop();
                            results_lock.unlock();
                            completion_task_group = res.task_group;
                            {
                                mutex::scoped_lock tasks_lock { _tasks_mutex };
                                auto it = _task_stats.find(res.task_group);
                                if (it == _task_stats.end())
                                    throw error(fmt::format("internal error: unknown task: {}", res.task_group));
                                --it->second.queued;
                                ++it->second.completed;
                                it->second.cpu_time += res.cpu_time;
                            }
                            {
                                mutex::unique_lock observers_lock { _observers_mutex };
                                auto it = _observers.find(res.task_group);
                                if (it != _observers.end()) {
                                    observers_lock.unlock();
                                    // assumes that the observer list for a task group is configured before task submission
                                    for (const auto &observer: it->second) {
                                        logger::run_log_errors([&] {
                                            observer(std::move(res.result));
                                        });
                                    }
                                }
                            }
                        }
                        {
                            if (!completion_task_group)
                                throw scheduler_error("internal error: completion task group is undefined!");
                            mutex::unique_lock completion_lk { _completion_mutex };
                            auto it = _completion_actions.find(*completion_task_group);
                            if (it != _completion_actions.end() && ++it->second.done == it->second.todo) {
                                auto node = _completion_actions.extract(it);
                                completion_lk.unlock();
                                clear_observers(*completion_task_group);
                                logger::run_log_errors([&] {
                                    node.mapped().action();
                                });
                            }
                        }
                        results_lock.lock();
                    }
                    _results_processed = false;
                } catch (const std::exception &ex) {
                    _results_processed = false;
                    logger::error("scheduler::_process_results failed with std::exception: {}", ex.what());
                    throw;
                } catch (...) {
                    _results_processed = false;
                    logger::error("scheduler::_process_results failed with an unknown exception");
                    throw;
                }
            }
        }

        void _add_result(int64_t priority, const std::string &task_group, std::any &&res, double cpu_time)
        {
            mutex::unique_lock results_lock { _results_mutex };
            _results.emplace(priority, task_group, res, cpu_time);
            results_lock.unlock();
            _results_cv.notify_one();
        }

        bool _worker_try_execute(size_t worker_idx, const std::optional<std::chrono::milliseconds> wait_interval_ms)
        {
            static std::string wait_task_name { "__WAIT_FOR_TASKS__" };
            const auto sleep_start_time = std::chrono::system_clock::now();
            mutex::unique_lock lock { _tasks_mutex };
            _tasks_cv.wait_for(lock, *wait_interval_ms, [&] {
                return !_tasks.empty() || _destroy;
            });
            _task_stats[wait_task_name].cpu_time += std::chrono::duration<double> { std::chrono::system_clock::now() - sleep_start_time }.count();
            if (_destroy)
                return false;
            if (!_tasks.empty()) {
                auto &worker_task = _worker_tasks[worker_idx];
                const auto prev_task = worker_task;
                if (!prev_task)
                    ++_num_active;
                std::any task_res {};
                // need to create copies since the task will be destroyed before reporting its result.
                std::optional<int64_t> res_prio {};
                std::optional<std::string> res_task_group {};
                const auto start_time = std::chrono::system_clock::now();
                // ensure that the task instance is destroyed before its results are reported
                {
                    auto task = _tasks.top();
                    _tasks.pop();
                    if (prev_task)
                        worker_task = fmt::format("{}/{}", *prev_task, task.task_group);
                    else
                        worker_task = task.task_group;
                    lock.unlock();
                    res_prio = task.priority;
                    res_task_group = task.task_group;
                    try {
                        task_res = task.task();
                    } catch (const std::exception &ex) {
                        _success = false;
                        logger::warn("worker-{} task {} std::exception: {}", worker_idx, task.task_group, ex.what());
                        task_res = std::make_any<scheduled_task_error>(std::source_location::current(), std::move(task), "task: '{}' error: '{}' of type: '{}'!", task.task_group, ex.what(), typeid(ex).name());
                    } catch (...) {
                        _success = false;
                        logger::warn("worker-{} task {} unknown exception", worker_idx, task.task_group);
                        task_res = std::make_any<scheduled_task_error>(std::source_location::current(), std::move(task), "task: '{}' unknown exception", task.task_group);
                    }
                }
                const auto cpu_time = std::chrono::duration<double> { std::chrono::system_clock::now() - start_time }.count();
                lock.lock();
                worker_task = prev_task;
                lock.unlock();
                if (!(res_prio && res_task_group))
                    throw scheduler_error("internal error: result priority or task group are not defined!");
                _add_result(*res_prio, *res_task_group, std::move(task_res), cpu_time);
                if (!prev_task)
                    --_num_active;
            }
            return true;
        }

        void _worker_thread(size_t worker_idx)
        {
            static auto wait_ms = default_wait_interval;
            while (_worker_try_execute(worker_idx, wait_ms)) {
            }
        }

        void _process_once(const bool report_status, const bool process_tasks=false, const bool process_results=false)
        {
            // In the single-worker mode, the tasks are executed in the loop
            if (process_tasks) {
                const auto w_id = _get_worker_id();
                if (w_id)
                    _worker_try_execute(*w_id, default_wait_interval);
                else
                    logger::warn("Thread {} outside of the worker pool attempted to execute tasks", boost::this_thread::get_id());
            }
            if (process_results) {
                mutex::unique_lock results_lock { _results_mutex };
                if (_results_cv.wait_for(results_lock, default_wait_interval, [&]{ return !_results.empty(); }))
                    _process_results(results_lock);
            } else if (!process_tasks) {
                std::this_thread::sleep_for(default_wait_interval);
            }
            if (report_status)
                _report_status();
        }

        void _process(const bool report_status)
        {
            for (;;) {
                {
                    mutex::scoped_lock results_lk { _results_mutex };
                    mutex::scoped_lock tasks_lk { _tasks_mutex };
                    size_t num_tasks = 0;
                    for (const auto &[task_name, stats]: _task_stats)
                        num_tasks += stats.queued;
                    if (num_tasks == 0 && _results.empty() && !_results_processed.load())
                        break;
                }
                _process_once(report_status, _num_workers == 1, true);
            }
            if (report_status)
                progress::get().inform();
        }
    };

    scheduler::scheduler(size_t user_num_workers)
        : _impl { std::make_unique<impl>(user_num_workers) }
    {
    }

    scheduler::~scheduler() =default;

    size_t scheduler::num_workers() const
    {
        return _impl->num_workers();
    }

    size_t scheduler::num_observers(const std::string &task_group) const
    {
        return _impl->num_observers(task_group);
    }

    size_t scheduler::active_workers() const
    {
        return _impl->active_workers();
    }

    size_t scheduler::cancel(const cancel_predicate &pred)
    {
        return _impl->cancel(pred);
    }

    void scheduler::submit(const std::string &task_group, int64_t priority, const std::function<std::any ()> &action, std::optional<std::any> param)
    {
        _impl->submit(task_group, priority, action, param);
    }

    void scheduler::submit_void(const std::string &task_group, int64_t priority, const std::function<void ()> &action, std::optional<std::any> param)
    {
        submit(
                task_group, priority,
                [action] {
                    action();
                    return true;
                },
                std::move(param)
        );
    }

    void scheduler::on_result(const std::string &task_group, const std::function<void (std::any &&)> &observer, bool replace_if_exists)
    {
        _impl->on_result(task_group, observer, replace_if_exists);
    }

    void scheduler::on_completion(const std::string &task_group, size_t task_count, const std::function<void()> &action)
    {
        _impl->on_completion(task_group, task_count, action);
    }

    void scheduler::clear_observers(const std::string &task_group)
    {
        _impl->clear_observers(task_group);
    }

    size_t scheduler::task_count(const std::string &task_group)
    {
        return _impl->task_count(task_group);
    }

    size_t scheduler::task_count()
    {
        return _impl->task_count();
    }

    bool scheduler::process_ok(bool report_status, const std::source_location &loc)
    {
        return _impl->process_ok(report_status, loc);
    }

    void scheduler::process(bool report_status, const std::source_location &loc)
    {
        _impl->process(report_status, loc);
    }

    void scheduler::process_once(const bool report_status)
    {
        _impl->process_once(report_status);
    }

    void scheduler::wait_all_done(const std::string &task_group, const size_t task_count,
        const std::function<void()> &submit_tasks, const std::function<void(std::any &&, size_t, size_t)> &process_res)
    {
        return _impl->wait_all_done(task_group, task_count, submit_tasks, process_res);
    }
}