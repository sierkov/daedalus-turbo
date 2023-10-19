/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_TYPE_HPP
#define DAEDALUS_TURBO_CARDANO_TYPE_HPP

#include <dt/blake2b.hpp>
#include <dt/bech32.hpp>
#include <dt/ed25519.hpp>
#include <dt/kes.hpp>
#include <dt/util.hpp>
#include <dt/vrf.hpp>

namespace daedalus_turbo {
    using cardano_error = error;
    using cardano_hash_32 = blake2b_256_hash;
    using cardano_hash_28 = blake2b_224_hash;
    using cardano_vkey = ed25519_vkey;
    using cardano_vkey_span = std::span<const uint8_t, sizeof(cardano_vkey)>;
    using cardano_signature = ed25519_signature;
    using cardano_kes_signature = kes_signature<6>;
    using cardano_kes_signature_data = std::array<uint8_t, cardano_kes_signature::size()>;
    using cardano_vrf_vkey = vrf_vkey;
    using cardano_vrf_result = vrf_result;
    using cardano_vrf_result_span = std::span<const uint8_t, sizeof(cardano_vrf_result)>;
    using cardano_vrf_proof = vrf_proof;
    using cardano_vrf_proof_span = std::span<const uint8_t, sizeof(cardano_vrf_proof)>;

    namespace cardano {
        struct address_buf: public uint8_vector {
            address_buf(const std::string_view &addr_sv): uint8_vector {}
            {
                static const std::string_view prefix { "0x" };
                if (addr_sv.substr(0, 2) == prefix) {
                    bytes_from_hex(*this, addr_sv.substr(2));
                } else {
                    const bech32 addr_bech32(addr_sv);
                    resize(addr_bech32.size());
                    memcpy(data(), addr_bech32.data(), addr_bech32.size());
                }
            }

            operator buffer() const
            {
                return buffer { *this };
            }
        };
    }
}

#endif // !DAEDALUS_TURBO_CARDANO_TYPE_HPP