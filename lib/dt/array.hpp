#pragma once
#ifndef DAEDALUS_TURBO_ARRAY_HPP
#define DAEDALUS_TURBO_ARRAY_HPP
/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <array>
#include <cstring>
#include <span>
#include <dt/common/error.hpp>
#include <dt/common/format.hpp>
#include <dt/common/bytes.hpp>

namespace daedalus_turbo {
    template<size_t SZ>
    struct
#   ifndef _MSC_VER
        __attribute__((packed))
#   endif
    byte_array: std::array<uint8_t, SZ> {
        using base_type = std::array<uint8_t, SZ>;
        using base_type::base_type;

        static byte_array<SZ> from_hex(const std::string_view hex)
        {
            byte_array<SZ> data;
            init_from_hex(data, hex);
            return data;
        }

        byte_array() =default;

        byte_array(const std::initializer_list<uint8_t> s) {
            if (s.size() != SZ) [[unlikely]]
                throw error(fmt::format("span must be of size {} but got {}", SZ, s.size()));
            size_t i = 0;
            for (const auto b: s)
                *(base_type::data() + i++) = b;
        }

        byte_array(const buffer s)
        {
            if (s.size() != SZ) [[unlikely]]
                throw error(fmt::format("string_view must be of size {} but got {}", SZ, s.size()));
            memcpy(this, std::data(s), SZ);
        }

        byte_array(const std::string_view s)
        {
            if (s.size() != SZ) [[unlikely]]
                throw error(fmt::format("string_view must be of size {} but got {}", SZ, s.size()));
            memcpy(this, std::data(s), SZ);
        }

        byte_array &operator=(const buffer s)
        {
            if (s.size() != SZ) [[unlikely]]
                throw error(fmt::format("string_view must be of size {} but got {}", SZ, s.size()));
            memcpy(this, std::data(s), SZ);
            return *this;
        }

        byte_array &operator=(const std::string_view s)
        {
            if (s.size() != SZ) [[unlikely]]
                throw error(fmt::format("string_view must be of size {} but got {}", SZ, s.size()));
            memcpy(this, std::data(s), SZ);
            return *this;
        }

        operator buffer() const noexcept
        {
            return { base_type::data(), SZ };
            static_assert(std::is_convertible_v<byte_array, buffer>);
        }

        explicit operator std::string_view() const noexcept
        {
            return { reinterpret_cast<const char *>(base_type::data()), base_type::size() };
        }

        /*bool operator==(const byte_array<SZ> &o) const
        {
            return memcmp(base_type::data(), o.data(), base_type::size()) == 0;
        }*/
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

    template<size_t SZ>
    struct secure_byte_array: byte_array<SZ>
    {
        using byte_array<SZ>::byte_array;

        static secure_byte_array<SZ> from_hex(const std::string_view &hex)
        {
            secure_byte_array<SZ> data;
            init_from_hex(data, hex);
            return data;
        }

        ~secure_byte_array()
        {
            secure_clear(*this);
        }
    };
}

namespace fmt {
    template<size_t SZ>
    struct formatter<daedalus_turbo::byte_array<SZ>>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out())
        {
            return fmt::format_to(ctx.out(), "{}", std::span(v));
        }
    };

    template<size_t SZ>
    struct formatter<daedalus_turbo::secure_byte_array<SZ>>: formatter<daedalus_turbo::byte_array<SZ>> {
    };
}

#endif //DAEDALUS_TURBO_ARRAY_HPP