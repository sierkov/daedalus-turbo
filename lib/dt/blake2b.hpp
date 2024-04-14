/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_BLAKE2B_HPP
#define DAEDALUS_TURBO_BLAKE2B_HPP

extern "C" {
#   include <sodium.h>
};
#include <dt/array.hpp>
#include <dt/ed25519.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo
{
    using blake2b_224_hash = array<uint8_t, 28>;
    using blake2b_256_hash = array<uint8_t, 32>;
    using blake2b_64_hash = array<uint8_t, 8>;

    inline void blake2b_sodium(void *out, size_t out_len, const void *in, size_t in_len)
    {
        ed25519::ensure_initialized();
        if (crypto_generichash(reinterpret_cast<unsigned char*>(out), out_len, reinterpret_cast<const unsigned char *>(in), in_len, nullptr, 0) != 0)
            throw error("libsodium error: can't compute hash!");
    }

    const auto blake2b_best = blake2b_sodium;

    inline void blake2b(const std::span<uint8_t> &out, const buffer &in)
    {
        blake2b_best(out.data(), out.size(), in.data(), in.size());
    }

    template<typename T>
    inline T blake2b(const buffer &in)
    {
        T out;
        blake2b_best(out.data(), out.size(), in.data(), in.size());
        return out;
    }
}

#endif // !DAEDALUS_TURBO_BLAKE2B_HPP