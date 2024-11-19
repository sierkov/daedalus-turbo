/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ARRAY_HPP
#define DAEDALUS_TURBO_ARRAY_HPP

#include <array>
#include <cstring>
#include <span>
#include <dt/error.hpp>
#include <dt/format.hpp>

namespace daedalus_turbo {
    inline uint8_t uint_from_oct(char k)
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
            default: throw error("unexpected character in an octal number: {}!", k);
        }
    }

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
            default: throw error("unexpected character in a hex number: {}!", k);
        }
    }

    inline void init_from_hex(std::span<uint8_t> out, const std::string_view hex)
    {
        if (hex.size() != out.size() * 2)
            throw error("hex string must have {} characters but got {}: {}!", out.size() * 2, hex.size(), hex);
        for (size_t i = 0; i < out.size(); ++i)
            out[i] = uint_from_hex(hex[i * 2]) << 4 | uint_from_hex(hex[i * 2 + 1]);
    }

    template<typename T, size_t SZ>
    struct
#   ifndef _MSC_VER
        __attribute__((packed))
#   endif
    array: std::array<T, SZ> {
        using std::array<T, SZ>::array;

        static array<T, SZ> from_hex(const std::string_view hex)
        {
            array<T, SZ> data;
            init_from_hex(data, hex);
            return data;
        }

        array(std::initializer_list<T> s) {
            static_assert(sizeof(*this) == SZ * sizeof(T));
            if (s.size() != SZ)
                throw error("span must be of size {} but got {}", SZ, s.size());
#if !defined(__clang__) && !defined(_MSC_VER)
#   pragma GCC diagnostic push
#   pragma GCC diagnostic ignored "-Wclass-memaccess"
#endif
            memcpy(this, std::data(s), SZ * sizeof(T));
#if !defined(__clang__) && !defined(_MSC_VER)
#   pragma GCC diagnostic pop
#endif
        }

        array(const std::span<const T> &s)
        {
            if (s.size() != SZ)
                throw error("span must be of size {} but got {}", SZ, s.size());
            memcpy(this, std::data(s), SZ * sizeof(T));
        }

        array(const std::string_view s)
        {
            if (s.size() != SZ * sizeof(T))
                throw error("string_view must be of size {} but got {}", SZ * sizeof(T), s.size());
            memcpy(this, std::data(s), SZ * sizeof(T));
        }

        array &operator=(const std::span<const T> &s)
        {
            if (s.size() != SZ)
                throw error("span must of size {} but got {}", SZ, s.size());
            memcpy(this, std::data(s), SZ * sizeof(T));
            return *this;
        }

        array &operator=(const std::string_view s)
        {
            if (s.size() != SZ * sizeof(T))
                throw error("string_view must be of size {} but got {}", SZ * sizeof(T), s.size());
            memcpy(this, std::data(s), SZ * sizeof(T));
            return *this;
        }

        const std::span<const T> span() const
        {
            return std::span<const T> { *this };
        }
    };

    extern void secure_clear(std::span<uint8_t> store);

    struct secure_store {
        secure_store(const std::span<uint8_t> store): _store { store }
        {
        }

        ~secure_store()
        {
            secure_clear(_store);
        }
    private:
        std::span<uint8_t> _store;
    };

    template<typename T, size_t SZ>
    struct secure_array: array<T, SZ>
    {
        using array<T, SZ>::array;

        static secure_array<T, SZ> from_hex(const std::string_view &hex)
        {
            secure_array<T, SZ> data;
            init_from_hex(data, hex);
            return data;
        }

        ~secure_array()
        {
            secure_clear(*this);
        }
    };
}

namespace fmt {
    template<size_t SZ>
    struct formatter<daedalus_turbo::array<uint8_t, SZ>>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out())
        {
            return fmt::format_to(ctx.out(), "{}", std::span(v));
        }
    };

    template<size_t SZ>
    struct formatter<daedalus_turbo::secure_array<uint8_t, SZ>>: formatter<daedalus_turbo::array<uint8_t, SZ>> {
    };
}

#endif //DAEDALUS_TURBO_ARRAY_HPP