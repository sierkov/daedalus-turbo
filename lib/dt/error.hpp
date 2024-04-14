/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ERROR_HPP
#define DAEDALUS_TURBO_ERROR_HPP

#define DT_ERROR_WITH_STACKTRACE 0

#include <cerrno>
#include <cstring>
#if DT_ERROR_WITH_STACKTRACE
#   include <stacktrace>
#endif
#include <dt/format.hpp>

namespace daedalus_turbo {
#if DT_ERROR_WITH_STACKTRACE
    inline std::string my_stacktrace()
    {
        std::ostringstream ss {};
        ss << std::stacktrace::current();
        return ss.str();
    }
#endif

    struct error: std::runtime_error {
        template<typename... Args>
        explicit error(const char *fmt, Args&&... a)
            : std::runtime_error { format(fmt::runtime(fmt), std::forward<Args>(a)...) }
#if DT_ERROR_WITH_STACKTRACE
                , _stacktrace { my_stacktrace() }
#endif
        {
        }

#if DT_ERROR_WITH_STACKTRACE
        const std::string &stacktrace() const
        {
            return _stacktrace;
        }
    private:
        std::string _stacktrace;
#endif
    };

    struct error_sys: error {
        template<typename... Args>
        explicit error_sys(const char *fmt, Args&&... a)
            : error { "{}, errno: {}, strerror: {}", format(fmt::runtime(fmt), std::forward<Args>(a)...), errno, std::strerror(errno) }
        {
        }
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::error>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
#if DT_ERROR_WITH_STACKTRACE
            return fmt::format_to(ctx.out(), "dt::error: {}, stacktrace: {}", v.what(), v.stacktrace());
#else
            return fmt::format_to(ctx.out(), "dt::error: {}", v.what());
#endif
        }
    };
}

#endif // !DAEDALUS_TURBO_ERROR_HPP