/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <cstdlib>
#include <source_location>
#include <dt/file.hpp>
#include <dt/logger.hpp>
#include <dt/memory.hpp>
#include <dt/progress.hpp>
#include <dt/scheduler.hpp>
#include <dt/timer.hpp>

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
        _worker_tasks.resize(_num_workers);
        std::map<std::thread::id, size_t> ids {};
        // One worker is a special case handled by the process method itself
        if (_num_workers == 1) {
            ids.emplace(std::this_thread::get_id(), 0);
        } else {
            for (size_t i = 0; i < _num_workers; ++i) {
                _workers.emplace_back([this, i]() { _worker_thread(i); });
                ids.emplace(_workers.back().get_id(), i);
            }
        }
        _worker_ids = ids;
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

    size_t scheduler::num_observers(const std::string &task_group) const
    {
        mutex::scoped_lock ob_lk { _observers_mutex };
        const auto it = _observers.find(task_group);
        return it != _observers.end() ? it->second.size() : 0;
    }

    size_t scheduler::active_workers() const
    {
        return _num_active.load();
    }

    void scheduler::submit(const std::string &task_group, int priority, const std::function<std::any ()> &action)
    {
        mutex::unique_lock tasks_lock { _tasks_mutex };
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
        const mutex::scoped_lock lock { _observers_mutex };
        auto [ it, created ] = _observers.emplace(task_group, 0);
        if (!created && replace_if_exists)
            it->second.clear();
        it->second.emplace_front(observer);
    }

    void scheduler::on_completion(const std::string &task_group, size_t task_count, const std::function<void()> &action)
    {
        mutex::scoped_lock lk { _completion_mutex };
        const auto [it, created] = _completion_actions.try_emplace(task_group, action, task_count);
        if (!created)
            throw error("duplicate completion handler for {}", task_group);
    }

    void scheduler::clear_observers(const std::string &task_group)
    {
        mutex::scoped_lock ob_lk { _observers_mutex };
        _observers.erase(task_group);
    }

    size_t scheduler::task_count(const std::string &task_group)
    {
        size_t cnt = 0;
        {
            mutex::scoped_lock lock { _tasks_mutex };
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
            mutex::scoped_lock lock{ _tasks_mutex };
            for (const auto &[task_name, task_cnt]: _tasks_cnt)
                cnt += task_cnt;
        }
        return cnt;
    }

    bool scheduler::process_ok(bool report_status, const std::source_location &loc)
    {
        timer t { fmt::format("scheduler::process_ok call from {}:{}", loc.file_name(), loc.line()), logger::level::debug };
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

    void scheduler::process(bool report_status, const std::source_location &loc)
    {
        if (!process_ok(report_status, loc))
            throw error("some scheduled tasks have failed, please consult logs for more details");
    }

    void scheduler::process_once(const bool report_status)
    {
        // to ensure that result observers are always called from one thread
        // process once will process results only if there is no _process running
        _process_once(report_status, false, !_process_running);
    }

    void scheduler::wait_for_count(const std::string &task_group, const size_t task_count,
        const std::function<void()> &submit_tasks, const std::function<void(std::any &&res)> &process_res) {
        bool exp_false = false;
        if (!_wait_for_count_running.compare_exchange_strong(exp_false, true))
            throw error("concurrent wait_for_count calls are not allowed!");
        if (_num_workers < 4)
            throw error("wait_for_count relies on a high worker count but got {} worker threads!", _num_workers);
        std::atomic_size_t errors = 0;
        try {
            static constexpr std::chrono::milliseconds report_period{10000};
            const auto wait_start = std::chrono::system_clock::now();
            auto next_warn = wait_start + report_period;
            std::atomic_size_t done_parts = 0;
            on_result(task_group, [&done_parts, &errors, process_res](auto &&res) {
                ++done_parts;
                if (res.type() == typeid(scheduled_task_error)) {
                    ++errors;
                    return;
                }
                process_res(std::move(res));
            }, true);
            submit_tasks();
            const auto process_results = !_process_running.load();
            timer t{fmt::format("wait_for_count task: {} count: {} process_results: {}", task_group,
                                task_count, process_results)};
            while (done_parts < task_count) {
                const auto now = std::chrono::system_clock::now();
                if (now >= next_warn) {
                    next_warn = now + report_period;
                    logger::warn(
                            "wait_for_count takes longer than expected task: {} count: {} done: {} errors: {} process_results: {} waiting for: {} secs",
                            task_group, task_count, done_parts.load(), errors.load(), process_results,
                            std::chrono::duration_cast<std::chrono::seconds>(now - wait_start).count());
                }
                _process_once(true, false, process_results);
            }
            _wait_for_count_running = false;
        } catch (const std::exception &ex) {
            logger::warn("wait_for_count failed with std::exception: {}", ex.what());
            _wait_for_count_running = false;
            throw;
        } catch (...) {
            logger::warn("wait_for_count failed with an unknown exception");
            _wait_for_count_running = false;
            throw;
        }
        if (errors > 0)
            throw scheduler_error("wait_for_count {} - there were failed tasks; cannot continue", task_group);
    }

    void scheduler::_process_results(mutex::unique_lock &results_lock)
    {
        if (!results_lock)
            throw scheduler_error("the lock must have already been taken!");
        bool must_be_false = false;
        if (_results_processed.compare_exchange_strong(must_be_false, true)) {
            try {
                while (!_results.empty()) {
                    auto res = _results.top();
                    _results.pop();
                    results_lock.unlock();
                    {
                        mutex::scoped_lock tasks_lock { _tasks_mutex };
                        auto it = _tasks_cnt.find(res.task_group);
                        if (it != _tasks_cnt.end()) {
                            if (it->second == 1)
                                _tasks_cnt.erase(it);
                            else
                                it->second--;
                        }
                    }
                    {
                        mutex::unique_lock observers_lock { _observers_mutex };
                        auto it = _observers.find(res.task_group);
                        if (it != _observers.end()) {
                            observers_lock.unlock();
                            // assumes that the observer list for a task group is configured before task submission
                            for (const auto &observer: it->second)
                                observer(std::move(res.result));
                        }
                    }

                    {
                        mutex::scoped_lock completion_lk { _completion_mutex };
                        auto it = _completion_actions.find(res.task_group);
                        if (it != _completion_actions.end()) {
                            if (++it->second.done == it->second.todo) {
                                it->second.action();
                                _completion_actions.erase(it);
                            }
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

    void scheduler::_add_result(int priority, const std::string &task_group, std::any &&res)
    {
        mutex::unique_lock results_lock { _results_mutex };
        _results.emplace(priority, task_group, res);
        results_lock.unlock();
        _results_cv.notify_one();
    }

    bool scheduler::_worker_try_execute(size_t worker_idx, const std::optional<std::chrono::milliseconds> wait_interval_ms)
    {
        mutex::unique_lock lock { _tasks_mutex };
        _tasks_cv.wait_for(lock, *wait_interval_ms, [&] {
            return !_tasks.empty() || _destroy;
        });
        if (_destroy)
            return false;
        if (!_tasks.empty()) {
            auto &worker_task = _worker_tasks[worker_idx];
            const auto prev_task = worker_task;
            if (!prev_task)
                ++_num_active;
            std::any task_res {};
            const auto task = _tasks.top();
            _tasks.pop();
            if (prev_task)
                worker_task = fmt::format("{}/{}", *prev_task, task.task_group);
            else
                worker_task = task.task_group;
            lock.unlock();
            try {
                task_res = task.task();
            } catch (const error &err) {
                _success = false;
                logger::warn("worker-{} task {} {}", worker_idx, task.task_group, err);
                task_res = std::make_any<scheduled_task_error>("task: '{}' error: '{}' of type: '{}'!", task.task_group, err, typeid(err).name());
            } catch (const std::exception &ex) {
                _success = false;
                logger::warn("worker-{} task {} std::exception: {}", worker_idx, task.task_group, ex.what());
                task_res = std::make_any<scheduled_task_error>("task: '{}' error: '{}' of type: '{}'!", task.task_group, ex.what(), typeid(ex).name());
            } catch (...) {
                _success = false;
                logger::warn("worker-{} task {} unknown exception", worker_idx, task.task_group);
                task_res = std::make_any<scheduled_task_error>("task: '{}' unknown exception", task.task_group);
            }
            lock.lock();
            worker_task = prev_task;
            lock.unlock();
            _add_result(task.priority, task.task_group, std::move(task_res));
            if (!prev_task)
                --_num_active;
        }
        return true;
    }

    void scheduler::_worker_thread(size_t worker_idx)
    {
        static auto wait_ms = default_wait_interval;
        while (_worker_try_execute(worker_idx, wait_ms)) {
        }
    }

    std::optional<size_t> scheduler::_get_worker_id() const
    {
        const auto w_it = _worker_ids.find(std::this_thread::get_id());
        if (w_it != _worker_ids.end())
            return w_it->second;
        return {};
    }

    void scheduler::_report_status()
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
                    for (const auto &[task_name, task_cnt]: _tasks_cnt)
                        num_tasks += task_cnt;
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

    void scheduler::_process_once(const bool report_status, const bool process_tasks, const bool process_results)
    {
        // In the single-worker mode, the tasks are executed in the loop
        if (process_tasks) {
            const auto w_id = _get_worker_id();
            if (w_id)
                _worker_try_execute(*w_id, default_wait_interval);
            else
                logger::warn("Thread {} outside of the worker pool attempted to execute tasks", std::this_thread::get_id());
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

    void scheduler::_process(const bool report_status)
    {
        auto &progress = progress::get();
        for (;;) {
            {
                mutex::scoped_lock results_lk { _results_mutex };
                mutex::scoped_lock tasks_lk { _tasks_mutex };
                size_t num_tasks = 0;
                for (const auto &[task_name, task_cnt]: _tasks_cnt)
                    num_tasks += task_cnt;
                if (num_tasks == 0 && _results.empty() && !_results_processed.load())
                    break;
            }
            _process_once(report_status, _num_workers == 1, true);
        }
        if (report_status)
            progress.inform();
    }
}