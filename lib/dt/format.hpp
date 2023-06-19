/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_FORMAT_HPP
#define DAEDALUS_TURBO_FORMAT_HPP

#include <span>
#include <string>
#include <fmt/core.h>
#include <fmt/format.h>

namespace fmt {
    template<>
    struct formatter<std::span<const uint8_t>> {
        constexpr auto parse(format_parse_context &ctx) -> decltype(ctx.begin()) {
            return ctx.begin();
        }

        template<typename FormatContext>
        auto format(const std::span<const uint8_t> &data, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = ctx.out();
            for (uint8_t v: data) {
                out_it = fmt::format_to(out_it, "{:02X}", v);
            }
            return out_it;
        }
    };

    template<>
    struct formatter<std::span<uint8_t>>: public formatter<std::span<const uint8_t>> {
    };

    template<size_t SZ>
    struct formatter<std::span<const uint8_t, SZ>>: public formatter<std::span<const uint8_t>> {
    };

    template<size_t SZ>
    struct formatter<std::span<uint8_t, SZ>>: public formatter<std::span<const uint8_t>> {
    };
}

namespace daedalus_turbo {

    using fmt::format;

}

#endif // !DAEDALUS_TURBO_FORMAT_HPP
