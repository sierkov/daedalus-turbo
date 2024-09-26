/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CRYPTO_KECCAK_HPP
#define DAEDALUS_TURBO_CRYPTO_KECCAK_HPP

#include <hash-library/keccak.h>
#include <dt/array.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::crypto::keccak
{
    using hash_256 = array<uint8_t, 32>;

    inline void digest(const std::span<uint8_t> &out, const buffer &in)
    {
        Keccak hasher {};
        hasher.add(in.data(), in.size());
        hasher.getHashBin(out);
    }

    inline hash_256 digest(const buffer &in)
    {
        hash_256 out;
        digest(out, in);
        return out;
    }
}

#endif // !DAEDALUS_TURBO_CRYPTO_KECCAK_HPP