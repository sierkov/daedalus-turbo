/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_VRF_HPP
#define DAEDALUS_TURBO_VRF_HPP 1

#include <array>
#include <cstring>
#include <span>
extern "C" {
#   include <vrf03/vrf.h>
}
#include <dt/array.hpp>
#include <dt/blake2b.hpp>
#include <dt/logger.hpp>
#include <dt/rational.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo {
    using vrf_result = array<uint8_t, 64>;
    using vrf_vkey = array<uint8_t, 32>;
    using vrf_proof = array<uint8_t, 80>;
    using vrf_nonce = array<uint8_t, 32>;

    inline blake2b_256_hash vrf_make_input(uint64_t slot, const buffer &nonce)
    {
        array<uint8_t, 8 + 32> data {};
        uint64_t be_slot = host_to_net<uint64_t>(slot);
        static_assert(8 == sizeof(be_slot), "uint64_t must be 8 bytes");
        memcpy(data.data(), &be_slot, sizeof(be_slot));
        if (nonce.size() != 32) throw error("nonce must be of 32 bytes but got {}!", nonce.size());
        memcpy(data.data() + 8, nonce.data(), nonce.size());
        return blake2b<blake2b_256_hash>(data);
    }

    inline blake2b_256_hash vrf_make_seed(const buffer &uc_nonce, uint64_t slot, const buffer &nonce)
    {
        array<uint8_t, 8 + 32> data {};
        uint64_t be_slot = host_to_net<uint64_t>(slot);
        static_assert(8 == sizeof(be_slot), "uint64_t must be 8 bytes");
        memcpy(data.data(), &be_slot, sizeof(be_slot));
        if (nonce.size() != 32) throw error("nonce must be of 32 bytes but got {}!", nonce.size());
        memcpy(data.data() + 8, nonce.data(), nonce.size());
        auto seed_tmp = blake2b<blake2b_256_hash>(data);
        if (uc_nonce.size() != seed_tmp.size()) throw error("uc_nonce must be of {} bytes but got {}!", seed_tmp.size(), uc_nonce.size());
        for (size_t i = 0; i < seed_tmp.size(); ++i)
            seed_tmp[i] ^= uc_nonce[i];
        return seed_tmp;
    }

    inline blake2b_256_hash vrf_extended_hash(const buffer &result, uint8_t extension)
    {   
        array<uint8_t, 65> data;
        if (result.size() != 64) throw error("result must be 64 bytes but got {}!", result.size());
        data[0] = extension;
        memcpy(data.data() + 1, result.data(), result.size());
        return blake2b<blake2b_256_hash>(data);
    }

    inline vrf_nonce vrf_nonce_value(const buffer &result)
    {
        return blake2b<vrf_nonce>(vrf_extended_hash(result, 'N'));
    }

    inline vrf_nonce vrf_leader_value(const buffer &result)
    {
        return vrf_extended_hash(result, 'L');
    }

    inline cpp_int vrf_leader_value_nat(const buffer &data)
    {
        cpp_int leader_val {};
        for (size_t i = 0; i < data.size(); ++i) {
            leader_val <<= 8;
            leader_val += *static_cast<const uint8_t*>(data.data() + i);
        }
        return leader_val;
    }

    inline void vrf_nonce_accumulate(const std::span<uint8_t> &output, const buffer &nonce_prev, const buffer &nonce_new)
    {
        if (nonce_prev.size() != 32) throw error("prev_nonce must be of 32 bytes but got {}!", nonce_prev.size());
        if (nonce_new.size() != 32) throw error("prev_nonce must be of 32 bytes but got {}!", nonce_new.size());
        std::array<uint8_t, 64> data;
        static_assert(sizeof(data) == 32 + 32);
        memcpy(data.data(), nonce_prev.data(), nonce_prev.size());
        memcpy(data.data() + nonce_prev.size(), nonce_new.data(), nonce_new.size());
        blake2b(output, data);
    }

    inline blake2b_256_hash vrf_nonce_accumulate(const buffer &nonce_prev, const buffer &nonce_new)
    {
        blake2b_256_hash output;
        vrf_nonce_accumulate(output, nonce_prev, nonce_new);
        return output;
    }

    inline bool vrf03_verify(const buffer &exp_res, const buffer &vkey, const buffer &proof, const buffer &msg)
    {
        if (exp_res.size() != sizeof(vrf_result)) throw error("result must be {} bytes but got {}!", sizeof(vrf_result), exp_res.size());
        if (vkey.size() != sizeof(vrf_vkey)) throw error("vkey must be {} bytes but got {}!", sizeof(vrf_vkey), vkey.size());
        if (proof.size() != sizeof(vrf_proof)) throw error("proof must be {} bytes but got {}!", sizeof(vrf_proof), proof.size());
        vrf_result res {};
        bool ok = crypto_vrf_ietfdraft03_verify(res.data(), vkey.data(), proof.data(), msg.data(), msg.size()) == 0;
        if (ok) ok = memcmp(res.data(), exp_res.data(), res.size()) == 0;
        return ok;
    }

    inline bool vrf_leader_is_eligible(const buffer &result, const double f, const rational &leader_stake_rel)
    {
        if (result.size() != sizeof(vrf_result) && result.size() != sizeof(vrf_nonce))
            throw error("vrf result must have {} or {} bytes but got {}!", sizeof(vrf_result), sizeof(vrf_nonce), result.size());
        using boost::multiprecision::cpp_int;
        cpp_int max_val { 1 };
        max_val <<= 8 * result.size();
        auto leader_val = vrf_leader_value_nat(result);
        rational p { leader_val, max_val };
        auto p_d = static_cast<double>(p);
        auto ls_d = static_cast<double>(leader_stake_rel);
        auto threshold = 1.0 - std::pow(static_cast<double>(1.0 - f), ls_d);
        auto ok = p_d < threshold;
        if (!ok)
            logger::debug("failed leadership eligibility check: leader value: {} threshold: {}", p_d, threshold);
        return ok;
    }
}

#endif //!DAEDALUS_TURBO_VRF_HPP