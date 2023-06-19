/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_ERROR_HPP
#define DAEDALUS_TURBO_ERROR_HPP

#include <cerrno>
#include <cstring>
#include <cstdarg>
#include <exception>
#include <string>
#include <utility>
#include <source_location>

#include <dt/format.hpp>

namespace daedalus_turbo {

    class error_fmt: public std::runtime_error {
    public:

        template<typename... Args>
        error_fmt(const std::string &fmt, Args&&... a)
            : std::runtime_error(format(fmt::runtime(fmt), std::forward<Args>(a)...))
        {
        }
    };

    class error_sys_fmt: public error_fmt
    {
    public:

        template<typename... Args>
        error_sys_fmt(const char *fmt, Args&&... a)
            : error_fmt("{}, errno: {}, strerror: {}", format(fmt::runtime(fmt), std::forward<Args>(a)...), errno, std::strerror(errno))
        {
        }
    };

    class error_src_loc: public error_fmt
    {
    public:

        template<typename... Args>
        error_src_loc(const std::source_location &loc, const char *fmt, Args&&... a)
            : error_fmt("{} at {}:{}", format(fmt::runtime(fmt), std::forward<Args>(a)...), loc.file_name(), loc.line())
        {
        }
    };
}

#endif // !DAEDALUS_TURBO_ERROR_HPP
