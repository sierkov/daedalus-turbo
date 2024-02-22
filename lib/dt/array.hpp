/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ARRAY_HPP
#define DAEDALUS_TURBO_ARRAY_HPP

#include <array>
#include <cstring>
#include <span>
#include <string_view>
#include <dt/error.hpp>
#include <dt/format.hpp>

namespace daedalus_turbo {
    using array_error = error;

    inline uint8_t uint_from_hex(char k)
    {
        switch (std::tolower(k)) {
            case '0': return 0;
            case '1': return 1;
            case '2': return 2;
            case '3': return 3;
            case '4': return 4;
            case '5': return 5;
            case '6': return 6;
            case '7': return 7;
            case '8': return 8;
            case '9': return 9;
            case 'a': return 10;
            case 'b': return 11;
            case 'c': return 12;
            case 'd': return 13;
            case 'e': return 14;
            case 'f': return 15;
            default: throw error("unexpected character in a hex string: {}!", k);
        }
    }

    template<typename T, size_t SZ>
    struct
#   ifndef _MSC_VER
        __attribute__((packed))
#   endif
        array: std::array<T, SZ> {
        using std::array<T, SZ>::array;

        static array<T, SZ> from_hex(const std::string_view &hex)
        {
            array<T, SZ> data;
            if (hex.size() != SZ * 2)
                throw error("hex string must have {} characters but got {}!", SZ * 2, hex.size());
            for (size_t i = 0; i < SZ; ++i)
                data[i] = uint_from_hex(hex[i * 2]) << 4 | uint_from_hex(hex[i * 2 + 1]);
            return data;
        }

        array(std::initializer_list<T> s) {
            static_assert(sizeof(*this) == SZ * sizeof(T));
            if (s.size() != SZ)
                throw array_error("span must be of size {} but got {}", SZ, s.size());
#ifndef __clang__
#   pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wclass-memaccess"
#endif
            memcpy(this, std::data(s), SZ * sizeof(T));
#ifndef __clang__
#   pragma GCC diagnostic pop
#endif
        }

        array(const std::span<const T> &s)
        {
            if (s.size() != SZ)
                throw array_error("span must be of size {} but got {}", SZ, s.size());
            memcpy(this, std::data(s), SZ * sizeof(T));
        }

        array(const std::string_view s)
        {
            if (s.size() != SZ * sizeof(T))
                throw array_error("string_view must be of size {} but got {}", SZ * sizeof(T), s.size());
            memcpy(this, std::data(s), SZ * sizeof(T));
        }

        array &operator=(const std::span<const T> &s)
        {
            if (s.size() != SZ)
                throw array_error("span must of size {} but got {}", SZ, s.size());
            memcpy(this, std::data(s), SZ * sizeof(T));
            return *this;
        }

        array &operator=(const std::string_view s)
        {
            if (s.size() != SZ * sizeof(T))
                throw array_error("string_view must be of size {} but got {}", SZ * sizeof(T), s.size());
            memcpy(this, std::data(s), SZ * sizeof(T));
            return *this;
        }

        const std::span<const T> span() const
        {
            return std::span<const T> { *this };
        }
    };
}

namespace fmt {
    template<size_t SZ>
    struct formatter<daedalus_turbo::array<uint8_t, SZ>>: public formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out())
        {
            return fmt::format_to(ctx.out(), "{}", std::span(v));
        }
    };
}

#endif //DAEDALUS_TURBO_ARRAY_HPP