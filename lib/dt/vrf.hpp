/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_VRF_HPP
#define DAEDALUS_TURBO_VRF_HPP 1

#include <array>
#include <span>

extern "C" {
#   include <vrf03/vrf.h>
}

#include <dt/blake2b.hpp>
#include <dt/ed25519.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo {

    using vrf_result = std::array<uint8_t, 64>;
    using vrf_vkey = std::array<uint8_t, 32>;
    using vrf_proof = std::array<uint8_t, 80>;

    inline bool vrf03_verify(const std::span<const uint8_t> &exp_res, const std::span<const uint8_t> &vkey,
        const std::span<const uint8_t> &proof, const std::span<const uint8_t> &msg)
    {
        if (exp_res.size() != sizeof(vrf_result)) throw error_fmt("result must be {} bytes but got {}!", sizeof(vrf_result), exp_res.size());
        if (vkey.size() != sizeof(vrf_vkey)) throw error_fmt("vkey must be {} bytes but got {}!", sizeof(vrf_vkey), vkey.size());
        if (proof.size() != sizeof(vrf_proof)) throw error_fmt("proof must be {} bytes but got {}!", sizeof(vrf_proof), proof.size());
        vrf_result res {};
        bool ok = crypto_vrf_ietfdraft03_verify(res.data(), vkey.data(), proof.data(), msg.data(), msg.size()) == 0;
        if (ok) ok = memcmp(res.data(), exp_res.data(), res.size()) == 0;
        return ok;
    }

}

#endif //!DAEDALUS_TURBO_VRF_HPP
