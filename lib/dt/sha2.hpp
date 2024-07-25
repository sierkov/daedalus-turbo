/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SHA2_HPP
#define DAEDALUS_TURBO_SHA2_HPP

extern "C" {
#   include <sodium.h>
};
#include <dt/array.hpp>
#include <dt/ed25519.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::sha2
{
    using hash_256 = array<uint8_t, crypto_hash_sha256_BYTES>;

    inline void digest(const std::span<uint8_t> &out, const buffer &in)
    {
        if (out.size() != sizeof(hash_256))
            throw error("output size must be {} but got {}", sizeof(hash_256), out.size());
        ed25519::ensure_initialized();
        if (crypto_hash_sha256(out.data(), in.data(), in.size()) != 0)
            throw error("sha2 computation hash failed!");
    }

    inline hash_256 digest(const buffer &in)
    {
        hash_256 out;
        digest(out, in);
        return out;
    }
}

#endif // !DAEDALUS_TURBO_SHA2_HPP