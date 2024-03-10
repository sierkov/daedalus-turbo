/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_FORMAT_HPP
#define DAEDALUS_TURBO_FORMAT_HPP

#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#ifndef __clang__
#   pragma GCC diagnostic ignored "-Wdangling-reference"
#endif
#endif
#include <fmt/core.h>
#include <fmt/format.h>
#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif

namespace daedalus_turbo {
    using fmt::format;
}

namespace fmt {
    template<>
    struct formatter<std::span<const uint8_t>>: formatter<int> {
        template<typename FormatContext>
        auto format(const std::span<const uint8_t> &data, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = ctx.out();
            for (uint8_t v: data) {
                out_it = fmt::format_to(out_it, "{:02X}", v);
            }
            return out_it;
        }
    };

    template<size_t SZ>
    struct formatter<std::span<const uint8_t, SZ>>: formatter<std::span<const uint8_t>> {
    };

    template<typename T, typename A>
    struct formatter<std::vector<T, A>>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = ctx.out();
            for (auto it = v.begin(); it != v.end(); it++) {
                const std::string sep { std::next(it) == v.end() ? "" : ", " };
                out_it = fmt::format_to(out_it, "{}{}", *it, sep);
            }
            return out_it;
        }
    };

    template<typename T, typename A>
    struct formatter<std::set<T, std::less<T>, A>>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = ctx.out();
            for (auto it = v.begin(); it != v.end(); it++) {
                const std::string sep { std::next(it) == v.end() ? "" : ", " };
                out_it = fmt::format_to(out_it, "{}{}", *it, sep);
            }
            return out_it;
        }
    };

    template<typename T>
    struct formatter<std::optional<T>>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            if (v)
                return fmt::format_to(ctx.out(), "{}", *v);
            else
                return fmt::format_to(ctx.out(), "std::nullopt");
        }
    };

    template<>
    struct formatter<std::thread::id>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            std::stringstream ss {};
            ss << v;
            return fmt::format_to(ctx.out(), "{}", ss.str());
        }
    };
}

#endif // !DAEDALUS_TURBO_FORMAT_HPP