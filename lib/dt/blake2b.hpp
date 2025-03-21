#pragma once
#ifndef DAEDALUS_TURBO_BLAKE2B_HPP
#define DAEDALUS_TURBO_BLAKE2B_HPP
/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/array.hpp>
#include <dt/common/bytes.hpp>

namespace daedalus_turbo
{
    using blake2b_224_hash = byte_array<28>;
    using blake2b_256_hash = byte_array<32>;
    using blake2b_64_hash = byte_array<8>;

    extern void blake2b_sodium(void *out, size_t out_len, const void *in, size_t in_len);
    const auto blake2b_best = blake2b_sodium;

    inline void blake2b(const std::span<uint8_t> &out, const buffer &in)
    {
        blake2b_best(out.data(), out.size(), in.data(), in.size());
    }

    template<typename T>
    T blake2b(const buffer &in)
    {
        T out;
        blake2b_best(out.data(), out.size(), in.data(), in.size());
        return out;
    }
}

namespace std {
    template<>
    struct hash<daedalus_turbo::blake2b_256_hash> {
        size_t operator()(const daedalus_turbo::blake2b_256_hash &o) const noexcept
        {
            return *reinterpret_cast<const size_t *>(o.data());
        }
    };

    template<>
    struct hash<daedalus_turbo::blake2b_224_hash> {
        size_t operator()(const daedalus_turbo::blake2b_224_hash &o) const noexcept
        {
            return *reinterpret_cast<const size_t *>(o.data());
        }
    };
}

#endif // !DAEDALUS_TURBO_BLAKE2B_HPP