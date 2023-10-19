/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ARRAY_HPP
#define DAEDALUS_TURBO_ARRAY_HPP

#include <array>
#include <cstring>
#include <span>
#include <string_view>
#include <dt/error.hpp>

namespace daedalus_turbo {
    using array_error = error;

    template<typename T, size_t SZ>
    struct __attribute__((packed)) array: public std::array<T, SZ> {
        using std::array<T, SZ>::array;

        array(std::initializer_list<T> s) {
            static_assert(sizeof(*this) == SZ * sizeof(T));
            if (s.size() != SZ) throw array_error("span must be of size {} but got {}", SZ, s.size());
            memcpy(this, std::data(s), SZ * sizeof(T));
        }

        array(const std::span<const T> &s)
        {
            if (s.size() != SZ) throw array_error("span must be of size {} but got {}", SZ, s.size());
            memcpy(this, std::data(s), SZ * sizeof(T));
        }

        array(const std::string_view s)
        {
            if (s.size() != SZ * sizeof(T)) throw array_error("string_view must be of size {} but got {}", SZ * sizeof(T), s.size());
            memcpy(this, std::data(s), SZ * sizeof(T));
        }

        array &operator=(const std::span<const T> &s)
        {
            if (s.size() != SZ) throw array_error("span must of size {} but got {}", SZ, s.size());
            memcpy(this, std::data(s), SZ * sizeof(T));
            return *this;
        }

        array &operator=(const std::string_view s)
        {
            if (s.size() != SZ * sizeof(T)) throw array_error("string_view must be of size {} but got {}", SZ * sizeof(T), s.size());
            memcpy(this, std::data(s), SZ * sizeof(T));
            return *this;
        }

        const std::span<const T> span() const
        {
            return std::span<const T> { *this };
        }
    };
}

#endif //DAEDALUS_TURBO_ARRAY_HPP