/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_BABBAGE_HPP
#define DAEDALUS_TURBO_CARDANO_BABBAGE_HPP

#include <dt/cardano/common.hpp>
#include <dt/cardano/mary.hpp>
#include <dt/cbor.hpp>
#include <dt/ed25519.hpp>

namespace daedalus_turbo::cardano::babbage {
    struct tx;

    struct block: public mary::block {
        using mary::block::block;

        void foreach_tx(const std::function<void(const cardano::tx &)> &observer) const override;

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
    };

    struct tx: public mary::tx {
        using mary::tx::tx;

        virtual void foreach_output(const std::function<void(const tx_output &)> &observer) const
        {
            const cbor_array *outputs = nullptr;
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 1) outputs = &entry.array();
            }
            if (outputs == nullptr) return;
            for (size_t i = 0; i < outputs->size(); i++) {
                const cbor_value *address = nullptr;
                const cbor_value *amount = nullptr;
                switch (outputs->at(i).type) {
                case CBOR_ARRAY: {
                    const auto &out = outputs->at(i).array();
                    address = &out.at(0);
                    amount = &out.at(1);
                    break;
                }

                case CBOR_MAP:
                    for (const auto &[o_type, o_entry]: outputs->at(i).map()) {
                        switch (o_type.uint()) {
                        case 0: address = &o_entry; break;
                        case 1: amount = &o_entry; break;
                        default: break;
                        }
                    }
                    break;

                default:
                    throw cardano_error("unsupported transaction output format era: {}, slot: {}!", _blk.era(), (uint64_t)_blk.slot());
                }
                
                if (address == nullptr) throw cardano_error("transaction output misses address field!");
                if (amount == nullptr) throw cardano_error("transaction output misses amount field!");
                _extract_assets(*address, *amount, i, observer);
            }
        }
    };

    inline void block::foreach_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        if (txs.size() != wits.size())
            throw error("slot: {}, the number of transactions {} does not match the number of witnesses {}", (uint64_t)slot(), txs.size(), wits.size());
        for (size_t i = 0; i < txs.size(); ++i) {
            observer(tx { txs.at(i), *this, &wits.at(i) });
        }
    }
}

#endif // !DAEDALUS_TURBO_CARDANO_BABBAGE_HPP