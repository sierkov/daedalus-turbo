/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_LOGGER_HPP
#define DAEDALUS_TURBO_LOGGER_HPP 1

#include <iostream>
#include <sstream>
#include <string_view>

#include <dt/util.hpp>

namespace daedalus_turbo {

    class logger_base {
    public:
        virtual ~logger_base() {};
        virtual void log_write(const std::string_view &) =0;

        template<typename... Args>
        void log(const char *fmt, Args&&... a)
        {
            auto now = std::chrono::system_clock::now();
            auto in_time_t = std::chrono::system_clock::to_time_t(now);
            std::ostringstream os;
            os << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X")
                << ": " << format(fmt::runtime(fmt), std::forward<Args>(a)...) << '\n';
            log_write(os.str());
        }

        void log(const std::string_view &s)
        {
            std::string log_s { s };
            log_s += '\n';
            log_write(log_s);
        }
    };

    class logger_null: public logger_base {
    public:

        logger_null()
        {
        }

        void log_write(const std::string_view &) override
        {
        }

    };

    class logger_file: public logger_base {
        std::ostream &_log_stream;

    public:

        logger_file(std::ostream &log_stream) : _log_stream(log_stream)
        {
        }

        virtual void log_write(const std::string_view &line) override
        {
            _log_stream << line;
            _log_stream.flush();
        }

    };

}

#endif // !DAEDALUS_TURBO_LOGGER_HPP
