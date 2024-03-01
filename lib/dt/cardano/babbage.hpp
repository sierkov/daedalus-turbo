/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_BABBAGE_HPP
#define DAEDALUS_TURBO_CARDANO_BABBAGE_HPP

#include <dt/cardano/common.hpp>
#include <dt/cardano/alonzo.hpp>
#include <dt/cbor.hpp>

namespace daedalus_turbo::cardano::babbage {
    struct block: alonzo::block {
        using alonzo::block::block;

        const protocol_version protocol_ver() const override
        {
            const auto &pv = header_body().at(9).array();
            return protocol_version { pv.at(0).uint(), pv.at(1).uint() };
        }

        const kes_signature kes() const override
        {
            const auto &op_cert = header_body().at(8).array();
            size_t op_start_idx = 0;
            return kes_signature {
                op_cert.at(op_start_idx + 0).buf(),
                op_cert.at(op_start_idx + 3).buf(),
                issuer_vkey(),
                header().at(1).buf(),
                header_body_raw(),
                op_cert.at(op_start_idx + 1).uint(),
                op_cert.at(op_start_idx + 2).uint(),
                slot()
            };
        }

        const block_vrf vrf() const override
        {
            const auto &vkey = header_body().at(4).span();
            const auto &leader_vrf = header_body().at(5).array();
            const auto &nonce_vrf = header_body().at(5).array(); // Yes, the same as leader_vrf
            return block_vrf {
                vkey,
                leader_vrf.at(0).span(),
                leader_vrf.at(1).span(),
                nonce_vrf.at(0).span(),
                nonce_vrf.at(1).span()
            };
        }

        bool body_hash_ok() const override
        {
            const auto &exp_hash = header_body().at(7).buf();
            auto act_hash = _calc_body_hash(_block.array(), 1, _block.array().size());
            return exp_hash == act_hash;
        }
    };

    using tx = alonzo::tx;
}

#endif // !DAEDALUS_TURBO_CARDANO_BABBAGE_HPP