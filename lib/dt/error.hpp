/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ERROR_HPP
#define DAEDALUS_TURBO_ERROR_HPP

#include <cerrno>
#include <cstring>
#include <source_location>
#include <dt/format.hpp>

namespace daedalus_turbo {
    struct error: std::runtime_error {
        template<typename... Args>
        error(const char *fmt, Args&&... a): std::runtime_error { format(fmt::runtime(fmt), std::forward<Args>(a)...) }
        {
        }
    };

    struct error_sys: error {
        template<typename... Args>
        error_sys(const char *fmt, Args&&... a)
            : error { "{}, errno: {}, strerror: {}", format(fmt::runtime(fmt), std::forward<Args>(a)...), errno, std::strerror(errno) }
        {
        }
    };

    struct error_src_loc: error {
        template<typename... Args>
        error_src_loc(const std::source_location &loc, const char *fmt, Args&&... a)
            : error { "{} at {}:{}", format(fmt::runtime(fmt), std::forward<Args>(a)...), loc.file_name(), loc.line() }
        {
        }
    };
}

#endif // !DAEDALUS_TURBO_ERROR_HPP