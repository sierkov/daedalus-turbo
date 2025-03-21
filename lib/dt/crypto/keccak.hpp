/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CRYPTO_KECCAK_HPP
#define DAEDALUS_TURBO_CRYPTO_KECCAK_HPP

#include <dt/array.hpp>
#include <dt/common/bytes.hpp>

namespace daedalus_turbo::crypto::keccak
{
    using hash_256 = byte_array<32>;

    extern void digest(const std::span<uint8_t> &out, const buffer &in);

    inline hash_256 digest(const buffer &in)
    {
        hash_256 out;
        digest(out, in);
        return out;
    }
}

#endif // !DAEDALUS_TURBO_CRYPTO_KECCAK_HPP