/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ERROR_HPP
#define DAEDALUS_TURBO_ERROR_HPP

#include <cerrno>
#include <cstring>
#ifdef __APPLE__
#   define _GNU_SOURCE 1
#endif
#include <boost/stacktrace.hpp>
#include <dt/format.hpp>
#include <dt/logger.hpp>

namespace daedalus_turbo {
    struct error: std::runtime_error {
        static std::string my_stacktrace()
        {
            std::ostringstream ss {};
            ss << boost::stacktrace::stacktrace();
            return ss.str();
        }

        static const std::string &trace_error(const std::string &msg, const std::string &stack)
        {
            logger::debug("error created: {}, stacktrace: {}", msg, stack);
            return msg;
        }

        template<typename... Args>
        explicit error(const char *fmt, Args&&... a)
            : error { format(fmt::runtime(fmt), std::forward<Args>(a)...), my_stacktrace() }
        {
        }

        explicit error(const std::string &msg, const std::string &stack=my_stacktrace())
            : std::runtime_error { trace_error(msg, stack) }
        {
        }
    };

    struct error_sys: error {
        template<typename... Args>
        explicit error_sys(const char *fmt, Args&&... a)
            : error { fmt::format("{}, errno: {}, strerror: {}", format(fmt::runtime(fmt), std::forward<Args>(a)...), errno, std::strerror(errno)), my_stacktrace() }
        {
        }
    };
}

#endif // !DAEDALUS_TURBO_ERROR_HPP