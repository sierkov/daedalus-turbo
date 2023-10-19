/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_FORMAT_HPP
#define DAEDALUS_TURBO_FORMAT_HPP

#include <array>
#include <span>
#include <string>
#include <vector>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#ifndef __clang__
#   pragma GCC diagnostic ignored "-Wdangling-reference"
#endif
#include <fmt/core.h>
#include <fmt/format.h>
#pragma GCC diagnostic pop

namespace daedalus_turbo {
    using fmt::format;
}

namespace fmt {
    template<>
    struct formatter<std::span<const uint8_t>>: public formatter<int> {
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
    struct formatter<std::span<const uint8_t, SZ>>: public formatter<std::span<const uint8_t>> {
    };

    template<>
    struct formatter<std::vector<std::string>>: public formatter<int> {
        template<typename FormatContext>
        auto format(const auto &vec, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = ctx.out();
            for (auto it = vec.begin(); it != vec.end(); it++) {
                const std::string sep { std::next(it) == vec.end() ? "" : ", " };
                out_it = fmt::format_to(out_it, "{}{}", *it, sep);
            }
            return out_it;
        }
    };
}

#endif // !DAEDALUS_TURBO_FORMAT_HPP