/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SCHEDULER_HPP
#define DAEDALUS_TURBO_SCHEDULER_HPP

#include <any>
#include <chrono>
#include <functional>
#include <dt/common/format.hpp>

namespace daedalus_turbo {
    typedef fmt_error scheduler_error;

    struct scheduled_task {
        int64_t priority;
        std::string task_group;
        std::function<std::any ()> task;
        std::optional<std::any> param {};

        scheduled_task(int64_t prio, const std::string &tg, const std::function<std::any ()> &t, std::optional<std::any> param_)
            : priority { prio }, task_group { tg }, task { t }, param { std::move(param_) }
        {
        }

        bool operator<(const scheduled_task &t) const noexcept
        {
            return priority < t.priority;
        }
    };

    struct scheduled_task_error: scheduler_error {
        template<typename... Args>
        scheduled_task_error(const std::source_location &loc, scheduled_task &&task, const char *fmt, Args&&... a)
            : scheduler_error { loc, fmt, std::forward<Args>(a)... }, _task { std::move(task) }
        {
        }

        const scheduled_task &task() const
        {
            return _task;
        }
    private:
        scheduled_task _task;
    };

    struct scheduled_result {
        int64_t priority = 0;
        std::string task_group {};
        std::any result {};
        double cpu_time = 0.0;

        bool operator<(const scheduled_result &r) const noexcept
        {
            return priority < r.priority;
        }
    };

    struct scheduler {
        using cancel_predicate = std::function<bool(const std::string &, const std::optional<std::any> &param)>;

        static constexpr std::chrono::milliseconds default_wait_interval { 10 };
        static constexpr std::chrono::milliseconds default_update_interval { 5000 };

        static size_t default_worker_count()
        {
            return std::thread::hardware_concurrency();
        }

        static scheduler &get()
        {
            static scheduler sched {};
            return sched;
        }

        explicit scheduler(size_t user_num_workers=scheduler::default_worker_count());
        ~scheduler();
        size_t num_workers() const;
        size_t num_observers(const std::string &task_group) const;
        size_t active_workers() const;
        size_t cancel(const cancel_predicate &pred);
        void submit(const std::string &task_group, int64_t priority, const std::function<std::any ()> &action, std::optional<std::any> param={});
        void submit_void(const std::string &task_group, int64_t priority, const std::function<void ()> &action, std::optional<std::any> param={});
        void on_result(const std::string &task_group, const std::function<void (std::any &&)> &observer, bool replace_if_exists=false);
        void on_completion(const std::string &task_group, size_t task_count, const std::function<void()> &action);
        void clear_observers(const std::string &task_group);
        size_t task_count(const std::string &task_group);
        size_t task_count();
        bool process_ok(bool report_status=true, const std::source_location &loc=std::source_location::current());
        void process(bool report_status=true, const std::source_location &loc=std::source_location::current());
        void process_once(bool report_statues=true);
        void wait_all_done(const std::string &task_group, size_t task_count,
            const std::function<void ()> &submit_tasks, const std::function<void (std::any &&, size_t, size_t)> &process_res=[](auto &&, auto, auto) {});
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif // !DAEDALUS_TURBO_SCHEDULER_HPP