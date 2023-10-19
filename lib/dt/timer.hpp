/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_TIMER_HPP
#define DAEDALUS_TURBO_TIMER_HPP

#include <dt/logger.hpp>

namespace daedalus_turbo {
    struct timer {
        timer(const std::string_view &title, logger::level lev=logger::level::info)
            : _title { title }, _level { lev }, _start_time { std::chrono::system_clock::now() }
        {
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
                logger::log(_level, "timer '{}' finished in {:0.3f} secs", _title, duration());
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