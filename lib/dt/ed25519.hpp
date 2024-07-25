/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ED25519_HPP
#define DAEDALUS_TURBO_ED25519_HPP

#include <dt/array.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::ed25519 {
    using vkey = array<uint8_t, 32>;
    using skey = secure_array<uint8_t, 64>;
    using signature = array<uint8_t, 64>;
    using seed = secure_array<uint8_t, 32>;

    extern void ensure_initialized();
    extern void create(const std::span<uint8_t> &sk, const std::span<uint8_t> &vk);
    extern void create_from_seed(const std::span<uint8_t> &sk, const std::span<uint8_t> &vk, const buffer &sd);
    extern std::pair<skey, vkey> create_from_seed(const buffer &seed);
    extern skey create_sk_from_seed(const buffer &sd);
    extern void extract_vk(const std::span<uint8_t> &vk, const buffer &sk);
    extern vkey extract_vk(const buffer &sk);
    extern void sign(const std::span<uint8_t> &sig, const buffer &msg, const buffer &sk);
    extern signature sign(const buffer &msg, const buffer &sk);
    extern bool verify(const buffer &sig, const buffer &vk, const buffer &msg);
}

#endif // !DAEDALUS_TURBO_ED25519_HPP