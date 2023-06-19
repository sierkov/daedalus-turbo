/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_ARRAY_HPP
#define DAEDALUS_TURBO_ARRAY_HPP

#include <array>
#include <cstring>
#include <span>

#include <dt/error.hpp>

namespace daedalus_turbo {

    using array_error = error_fmt;

    template<typename T, size_t SZ>
    class __attribute__((packed)) array: public std::array<T, SZ> {
    public:
        using std::array<T, SZ>::array;

        array(std::initializer_list<T> s) {
            if (s.size() != SZ) throw array_error("span must of size {} but got {}", SZ, s.size());
            memcpy(this, std::data(s), SZ);
        }

        array(const std::span<const uint8_t> &s)
        {
            if (s.size() != SZ) throw array_error("span must of size {} but got {}", SZ, s.size());
            memcpy(this, s.data(), SZ);
        }

        array &operator=(const std::span<const uint8_t> &s)
        {
            if (s.size() != SZ) throw array_error("span must of size {} but got {}", SZ, s.size());
            memcpy(this, s.data(), SZ);
            return *this;
        }

    };

}

#endif //DAEDALUS_TURBO_ARRAY_HPP
