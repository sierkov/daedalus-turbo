/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_BLAKE2B_HPP
#define DAEDALUS_TURBO_BLAKE2B_HPP 1

extern "C" {
#   include <blake2/blake2.h>
};

#include <dt/array.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo
{
    using blake2b_224_hash = array<uint8_t, 28>;
    using blake2b_256_hash = array<uint8_t, 32>;

    inline void blake2b_best(void *out, size_t out_len, const void *in, size_t in_len)
    {
        if (blake2b(out, out_len, in, in_len, nullptr, 0) != 0) throw error_fmt("blake2b hashing failed with out_len: {} and in_len: {}!", out_len, in_len);
    }

    inline void blake2b(const std::span<uint8_t> &out, const std::span<const uint8_t> &in)
    {
        blake2b_best(out.data(), out.size(), in.data(), in.size());
    }

    template<typename T>
    inline T blake2b_best(const uint8_t *in, size_t in_len)
    {
        T hash;
        blake2b_best(hash.data(), hash.size(), in, in_len);
        return hash;
    }

    template<typename T>
    inline T blake2b(const std::span<const uint8_t> &in)
    {
        return blake2b_best<T>(in.data(), in.size());
    }

    template<typename T, size_t SZ>
    inline T blake2b(const std::span<const uint8_t, SZ> &in)
    {
        return blake2b_best<T>(in.data(), in.size());
    }
}

#endif // !DAEDALUS_TURBO_BLAKE2B_HPP
