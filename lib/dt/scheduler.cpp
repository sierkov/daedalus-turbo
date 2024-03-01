/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <cstdlib>
#include <dt/file.hpp>
#include <dt/logger.hpp>
#include <dt/memory.hpp>
#include <dt/progress.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo {
    size_t scheduler::_find_num_workers(size_t user_num_workers)
    {
        const char *env_workers_str = std::getenv("DT_WORKERS");
        if (env_workers_str != nullptr) {
            size_t env_workers = std::stoul(env_workers_str);
            if (env_workers != 0)
                return env_workers;
        }
        return user_num_workers;
    }

    scheduler::scheduler(size_t user_num_workers)
        : _num_workers { _find_num_workers(user_num_workers) }
    {
        if (_num_workers == 0)
            throw error("the number of worker threads must be greater than zero!");
        logger::info("scheduler started, worker count: {}", _num_workers);
        // One worker is a special case handled by the process method itself
        if (_num_workers >= 2) {
            for (size_t i = 0; i < _num_workers; ++i) {
                _workers.emplace_back([this, i]() { _worker_thread(i); });
                _worker_tasks.push_back("");
            }
        } else {
            _worker_tasks.push_back("");
        }
    }

    scheduler::~scheduler()
    {
        _destroy = true;
        _tasks_cv.notify_all();
        _results_cv.notify_all();
        for (auto &t: _workers)
            t.join();
    }

    size_t scheduler::num_workers() const
    {
        return _num_workers;
    }

    void scheduler::submit(const std::string &task_group, int priority, const std::function<std::any ()> &action)
    {
        std::unique_lock tasks_lock { _tasks_mutex };
        _tasks.emplace(priority, task_group, action);
        auto [ it, created ] = _tasks_cnt.emplace(task_group, 1);
        if (!created)
            it->second++;
        tasks_lock.unlock();
        _tasks_cv.notify_one();
    }

    void scheduler::submit_void(const std::string &task_group, int priority, const std::function<void ()> &action)
    {
        submit(task_group, priority, [action] {
            action();
            return true;
        });
    }

    void scheduler::on_result(const std::string &task_group, const std::function<void (std::any &&)> &observer, bool replace_if_exists)
    {
        if (task_count(task_group) != 0)
            throw error("observers for task '{}' must be configured before task submission!", task_group);
        const std::scoped_lock lock { _observers_mutex };
        auto [ it, created ] = _observers.emplace(task_group, 0);
        if (!created && replace_if_exists)
            it->second.clear();
        it->second.emplace_front(observer);
    }

    void scheduler::clear_observers(const std::string &task_group)
    {
        std::scoped_lock lk { _retiring_mutex };
        _retiring_observers.emplace_back(task_group);
    }

    size_t scheduler::task_count(const std::string &task_group)
    {
        size_t cnt = 0;
        {
            std::scoped_lock lock(_tasks_mutex);
            auto it = _tasks_cnt.find(task_group);
            if (it != _tasks_cnt.end())
                cnt = it->second;
        }
        return cnt;
    }

    size_t scheduler::task_count()
    {
        size_t cnt = 0;
        {
            std::scoped_lock lock(_tasks_mutex);
            for (const auto &[task_name, task_cnt]: _tasks_cnt)
                cnt += task_cnt;
        }
        return cnt;
    }

    bool scheduler::process_ok(bool report_progress, std::chrono::milliseconds update_interval_ms, std::ostream &report_stream)
    {
        bool must_be_false = false;
        bool must_be_true = true;
        if (!_process_running.compare_exchange_strong(must_be_false, true))
            throw error("nested calls to scheduler::process are prohibited!");
        logger::debug("scheduler process_ok started tasks: {}", task_count());
        try {
            _process(report_progress, report_stream, update_interval_ms);
            _observers.clear();
            if (!_process_running.compare_exchange_strong(must_be_true, false))
                throw error("internal error: failed to set _process running back to false!");
        } catch (std::exception &ex) {
            _observers.clear();
            logger::warn("scheduler::process failed: {}", ex.what());
            if (!_process_running.compare_exchange_strong(must_be_true, false))
                logger::warn("internal error: failed to set _process running back to false during exception handling!");
            throw;
        }
        bool res = _success.load();
        logger::debug("scheduler process_ok done remaining tasks: {} success: {}", task_count(), res);
        _success = true;
        return res;
    }

    void scheduler::process(bool report_progress, std::chrono::milliseconds update_interval_ms, std::ostream &report_stream)
    {
        if (!process_ok(report_progress, update_interval_ms, report_stream))
            throw error("some scheduled tasks have failed, please consult logs for more details");
    }

    bool scheduler::process_once(bool process_tasks, std::chrono::milliseconds wait_interval_ms)
    {
        // to ensure that result observers are always called from one thread
        // process once will process results only if there is no _process running
        return _process_once(wait_interval_ms, process_tasks, !_process_running);
    }

    void scheduler::wait_for_count(const std::string &task_group, size_t task_count,
        const std::function<void ()> &submit_tasks, const std::function<void (std::any &&res)> &process_res)
    {
        auto wait_start = std::chrono::system_clock::now();
        static constexpr std::chrono::milliseconds report_period { 10000 };
        auto next_warn = wait_start + report_period;
        std::atomic_size_t errors = 0;
        std::atomic_size_t done_parts = 0;
        auto process_tasks = _num_workers <= 16;
        auto process_results = !_process_running;
        on_result(task_group, [&done_parts, &errors, process_res](auto &&res) {
            ++done_parts;
            if (res.type() == typeid(scheduled_task_error)) {
                ++errors;
                return;
            }
            process_res(std::move(res));
        }, true);
        submit_tasks();
        while (done_parts < task_count) {
            auto now = std::chrono::system_clock::now();
            if (now >= next_warn) {
                next_warn = now + report_period;
                logger::warn("wait_for_count takes longer than expected task: {} count: {} done: {} errors: {} process_tasks: {} process_results: {} waiting for: {} secs",
                    task_group, task_count, done_parts.load(), errors.load(), process_tasks, process_results, std::chrono::duration_cast<std::chrono::seconds>(now - wait_start).count());
            }
            _process_once(default_wait_interval, process_tasks, process_results);
        }
        if (errors > 0)
            throw scheduler_error("wait_for_count {} - there were failed tasks; cannot continue", task_group);
    }

    void scheduler::_process_results(std::unique_lock<std::mutex> &results_lock)
    {
        if (!results_lock)
            throw scheduler_error("the lock must have already been taken!");
        _results_processed = true;
        while (!_results.empty()) {
            auto res = _results.top();
            _results.pop();
            results_lock.unlock();
            {
                std::scoped_lock tasks_lock(_tasks_mutex);
                auto it = _tasks_cnt.find(res.task_group);
                if (it != _tasks_cnt.end()) {
                    if (it->second == 1)
                        _tasks_cnt.erase(it);
                    else
                        it->second--;
                }
            }
            {
                std::unique_lock observers_lock { _observers_mutex };
                auto it = _observers.find(res.task_group);
                if (it != _observers.end()) {
                    observers_lock.unlock();
                    // assumes that the observer list for a task group is configured before task submission
                    for (const auto &observer: it->second)
                        observer(std::move(res.result));
                }
            }
            results_lock.lock();
        }
        _results_processed = false;
    }

    void scheduler::_add_result(int priority, const std::string &task_group, std::any &&res)
    {
        std::unique_lock results_lock(_results_mutex);
        _results.emplace(priority, task_group, res);
        results_lock.unlock();
        _results_cv.notify_one();
    }

    bool scheduler::_worker_try_execute(size_t worker_idx, const std::chrono::milliseconds &wait_interval)
    {
        std::unique_lock lock { _tasks_mutex };
        _tasks_cv.wait_for(lock, wait_interval, [&] {
            return _destroy || (!_tasks.empty());
        });
        if (_destroy)
            return false;
        if (!_tasks.empty()) {
            std::any task_res {};
            std::string task_name {};
            int task_prio = 0;
            {
                auto task = _tasks.top();
                _tasks.pop();
                _worker_tasks[worker_idx] = task.task_group;
                lock.unlock();
                task_name = task.task_group;
                task_prio = task.priority;
                try {
                    task_res = task.task();
                } catch (std::exception &ex) {
                    _success = false;
                    logger::warn("worker-{} task {} failed: {} success: {}", worker_idx, task_name, ex.what(), _success.load());
                    task_res = std::make_any<scheduled_task_error>("task: '{}' error: '{}' of type: '{}'!", task_name, ex.what(), typeid(ex).name());
                }
                lock.lock();
                _worker_tasks[worker_idx] = "";
                lock.unlock();
            }
            _add_result(task_prio, task_name, std::move(task_res));
        }
        return true;
    }

    void scheduler::_worker_thread(size_t worker_idx)
    {
        const std::chrono::milliseconds wait_interval { 500 };
        while (_worker_try_execute(worker_idx, wait_interval)) {
        }
    }

    bool scheduler::_process_once(const std::chrono::milliseconds &wait_interval_ms, bool process_tasks, bool process_results)
    {
        {
            std::scoped_lock lk { _retiring_mutex };
            if (!_retiring_observers.empty()) {
                {
                    std::scoped_lock ob_lk { _observers_mutex };
                    for (const auto &task_group: _retiring_observers)
                        _observers.erase(task_group);
                }
                _retiring_observers.clear();
            }
        }
        // Special case, in the single-worker mode, the tasks are executed in the loop
        if (process_tasks && !_tasks.empty())
            _worker_try_execute(0);
        bool have_work = false;
        if (process_results) {
            std::unique_lock results_lock(_results_mutex);
            have_work = _results_cv.wait_for(results_lock, wait_interval_ms, [&]{ return !_results.empty(); });
            if (have_work && process_results)
                _process_results(results_lock);
        } else if (!process_tasks) {
            std::this_thread::sleep_for(wait_interval_ms);
        }
        return have_work;
    }

    void scheduler::_process(bool report_progress, std::ostream &report_stream, std::chrono::milliseconds update_interval_ms)
    {
        auto &progress = progress::get();
        auto next_report = std::chrono::system_clock::now() + update_interval_ms;
        for (;;) {
            size_t num_tasks = 0;
            size_t num_results = 0;
            bool notifying = false;
            {
                std::scoped_lock lock { _tasks_mutex, _results_mutex };
                for (const auto &[task_name, task_cnt]: _tasks_cnt)
                    num_tasks += task_cnt;
                num_results = _results.size();
                notifying = _results_processed.load();
                if (num_tasks == 0 && num_results == 0 && !notifying)
                    break;
            }
            if (report_progress && std::chrono::system_clock::now() >= next_report) {
                logger::debug("scheduler tasks: {} results: {} notifying: {} open files: {} peak open files: {} peak RAM use: {} MB",
                    num_tasks, num_results, notifying, file::stream::open_files(), file::stream::max_open_files(), memory::max_usage_mb());
                progress.inform(report_stream);
                next_report = std::chrono::system_clock::now() + update_interval_ms;
            }
            _process_once(update_interval_ms, _num_workers == 1, true);
        }
        progress.inform(report_stream);
    }
}