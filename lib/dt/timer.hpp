/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_TIMER_HPP
#define DAEDALUS_TURBO_TIMER_HPP

#include <exception>
#include <dt/logger.hpp>

namespace daedalus_turbo {
    struct timer {
        explicit timer(const std::string_view &title, const logger::level lev=logger::level::trace, const bool report_start=false)
            : _title { title }, _level { lev }, _start_time { std::chrono::system_clock::now() }
        {
            if (report_start || logger::tracing_enabled())
                logger::log(_level, "timer '{}' created", _title);
        }

        ~timer() {
            stop_and_print();
        }

        void stop_and_print()
        {
            stop();
            print();
        }

        void print()
        {
            if (!_printed) {
                _printed = true;
                if (std::uncaught_exceptions() == 0)
                    logger::log(_level, "{} took {:0.3f} secs", _title, duration());
                else
                    logger::log(_level, "{} failed after {:0.3f} secs", _title, duration());
            }
        }

        double duration() const
        {
            std::chrono::duration<double> elapsed_seconds = _end_time - _start_time;
            return elapsed_seconds.count();
        }

        double stop(bool print_later=true)
        {
            if (!_stopped) {
                _stopped = true;
                _end_time = std::chrono::system_clock::now();
            }
            if (!print_later)
                _printed = true;
            return duration();
        }

    private:
        const std::string _title;
        const logger::level _level;
        const std::chrono::time_point<std::chrono::system_clock> _start_time;
        std::chrono::time_point<std::chrono::system_clock> _end_time {};
        bool _stopped = false;
        bool _printed = false;
    };
}

#endif // !DAEDALUS_TURBO_TIMER_HPP