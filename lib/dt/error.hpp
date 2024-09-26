/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ERROR_HPP
#define DAEDALUS_TURBO_ERROR_HPP

#include <cerrno>
#include <cstring>
#include <dt/format.hpp>
#include <dt/logger.hpp>

namespace daedalus_turbo {
    extern std::string error_stacktrace();
    extern const std::string &error_trace(const std::string &msg, const std::string &stack);

    struct error: std::runtime_error {
        template<typename... Args>
        explicit error(const char *fmt, Args&&... a)
            : error { format(fmt::runtime(fmt), std::forward<Args>(a)...), error_stacktrace() }
        {
        }

        explicit error(const std::string &msg, const std::string &stack=error_stacktrace())
            : std::runtime_error { error_trace(msg, stack) }
        {
        }
    };

    struct error_sys: error {
        template<typename... Args>
        explicit error_sys(const char *fmt, Args&&... a)
            : error { fmt::format("{}, errno: {}, strerror: {}", format(fmt::runtime(fmt), std::forward<Args>(a)...), errno, std::strerror(errno)), error_stacktrace() }
        {
        }
    };
}

#endif // !DAEDALUS_TURBO_ERROR_HPP