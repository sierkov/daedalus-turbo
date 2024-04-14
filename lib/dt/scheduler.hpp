/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SCHEDULER_HPP
#define DAEDALUS_TURBO_SCHEDULER_HPP

#include <any>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <list>
#include <queue>
#include <thread>
#include <unordered_map>
#include <vector>
#include <dt/mutex.hpp>
#include <dt/error.hpp>

namespace daedalus_turbo {
    using scheduler_error = error;
    struct scheduled_task_error: public error {
        using error::error;
    };
    struct scheduled_task {
        int priority;
        std::string task_group;
        std::function<std::any ()> task;

        scheduled_task(int prio, const std::string &tg, const std::function<std::any ()> &t)
            : priority { prio }, task_group { tg }, task { t }
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

    struct scheduler {
        static constexpr std::chrono::milliseconds default_wait_interval { 10 };

        static size_t default_worker_count()
        {
            return std::thread::hardware_concurrency();
        }

        static scheduler &get()
        {
            static scheduler sched {};
            return sched;
        }

        scheduler(size_t user_num_workers=scheduler::default_worker_count());
        ~scheduler();
        size_t num_workers() const;
        size_t active_workers() const;
        void submit(const std::string &task_group, int priority, const std::function<std::any ()> &action);
        void submit_void(const std::string &task_group, int priority, const std::function<void ()> &action);
        void on_result(const std::string &task_group, const std::function<void (std::any &&)> &observer, bool replace_if_exists=false);
        void clear_observers(const std::string &task_group);
        size_t task_count(const std::string &task_group);
        size_t task_count();
        bool process_ok(bool report_progress=true, std::chrono::milliseconds update_interval_ms=std::chrono::milliseconds { 1000 },
            std::ostream &report_stream=std::cerr, const std::source_location &loc=std::source_location::current());
        void process(bool report_progress=true, std::chrono::milliseconds update_interval_ms=std::chrono::milliseconds { 1000 },
            std::ostream &report_stream=std::cerr, const std::source_location &loc=std::source_location::current());
        bool process_once(bool process_tasks=false, std::chrono::milliseconds wait_interval_ms=default_wait_interval);
        void wait_for_count(const std::string &task_group, size_t task_count,
            const std::function<void ()> &submit_tasks, const std::function<void (std::any &&)> &process_res=[](auto &&) {});
    private:
        alignas(mutex::padding) mutable mutex::unique_lock::mutex_type _tasks_mutex {};
        alignas(mutex::padding) std::condition_variable_any _tasks_cv {};
        std::priority_queue<scheduled_task> _tasks {};
        std::unordered_map<std::string, size_t> _tasks_cnt {};

        using observer_list = std::list<std::function<void (std::any &&)>>;
        using observer_map = std::unordered_map<std::string, observer_list>;
        alignas(mutex::padding) mutex::unique_lock::mutex_type _observers_mutex {};
        observer_map _observers {};

        alignas(mutex::padding) mutex::unique_lock::mutex_type _results_mutex {};
        alignas(mutex::padding) std::condition_variable_any _results_cv {};
        std::priority_queue<scheduled_result> _results {};
        std::atomic_bool _results_processed = false;

        alignas(mutex::padding) mutex::unique_lock::mutex_type _retiring_mutex {};
        std::vector<std::string> _retiring_observers {};

        std::vector<std::thread> _workers {};
        std::vector<std::string> _worker_tasks {};
        const size_t _num_workers;
        std::atomic_size_t _num_active = 0;
        std::atomic_bool _destroy { false };
        std::atomic_bool _success { true };
        std::atomic_bool _process_running { false };

        void _process_results(mutex::unique_lock &results_lock);
        void _add_result(int priority, const std::string &task_group, std::any &&res);
        bool _worker_try_execute(size_t worker_idx, const std::chrono::milliseconds &wait_interval_ms=default_wait_interval);
        void _worker_thread(size_t worker_idx);
        static size_t _find_num_workers(size_t user_num_workers);
        bool _process_once(const std::chrono::milliseconds &wait_interval_ms, bool process_tasks=false, bool process_results=false);
        void _process(bool report_progress, std::ostream &report_stream, std::chrono::milliseconds update_interval_ms);
    };
}

#endif // !DAEDALUS_TURBO_SCHEDULER_HPP