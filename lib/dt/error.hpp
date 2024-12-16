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
    struct error: std::runtime_error {
        explicit error(const std::string &msg, const std::source_location &loc=std::source_location::current())
            : error { true, fmt::format("{} at {}:{}", msg, loc.file_name(), loc.line()) }
        {
        }

        explicit error(const std::string &msg, const std::exception &ex, const std::source_location &loc=std::source_location::current())
            : error { true, fmt::format("{} at {}:{} caused by {}: {}", msg, loc.file_name(), loc.line(), typeid(ex).name(), ex.what()) }
        {
        }

        template<typename ...Args>
        explicit error(const std::source_location &loc, const char *fmt, Args&&... a)
            : error { true, fmt::format("{} at {}:{}", fmt::format(fmt::runtime(fmt), std::forward<Args>(a)...), loc.file_name(), loc.line()) }
        {
        }
    protected:
        explicit error(const bool trace, const std::string &msg): std::runtime_error { msg }
        {
            if (trace)
                logger::debug("an exception created: {}", msg);
        }
    };

    struct error_sys: error {
        explicit error_sys(const std::string &msg, const std::source_location &loc=std::source_location::current())
            : error { fmt::format("{}, errno: {}, strerror: {}", msg, errno, std::strerror(errno)), loc }
        {
        }
    };
}

#endif // !DAEDALUS_TURBO_ERROR_HPP