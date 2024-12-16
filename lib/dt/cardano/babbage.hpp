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

        void foreach_tx(const std::function<void(const cardano::tx &)> &observer) const override;
        void foreach_invalid_tx(const std::function<void(const cardano::tx &)> &observer) const override;

        const protocol_version protocol_ver() const override
        {
            return protocol_version { header_body().at(9) };
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

    struct tx: alonzo::tx {
        using alonzo::tx::tx;

        void foreach_output(const std::function<void(const tx_output &)> &observer) const override
        {
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 1) {
                    const auto &outputs = entry.array();
                    for (size_t i = 0; i < outputs.size(); i++)
                        observer(tx_output::from_cbor(_blk.era(), i, outputs.at(i)));
                }
            }
        }

        virtual std::optional<tx_output> collateral_return() const
        {
            size_t num_outputs = 0;
            foreach_output([&](const auto &){ ++num_outputs; });
            std::optional<tx_output> c_out {};
            _if_item_present(16, [&](const auto &c_out_raw) {
                c_out.emplace(tx_output::from_cbor(_blk.era(), num_outputs, c_out_raw));
            });
            return c_out;
        }

        virtual std::optional<uint64_t> collateral_value() const
        {
            std::optional<uint64_t> coin {};
            _if_item_present(17, [&](const auto &tot_collateral_raw) {
                coin = tot_collateral_raw.uint();
            });
            return coin;
        }

        void foreach_referenced_input(const std::function<void(const tx_input &)> &observer) const override
        {
            _if_item_present(18, [&](const auto &rinputs_raw) {
                set<tx_out_ref> unique_inputs {};
                foreach_set(rinputs_raw, [&](const auto &txin, size_t) {
                    const auto in_idx = txin.at(1).uint();
                    unique_inputs.emplace(tx_out_ref { txin.at(0).buf(), in_idx });
                });
                size_t unique_idx = 0;
                for (const auto &unique_txin: unique_inputs) {
                    observer(tx_input { unique_txin.hash, unique_txin.idx, unique_idx++ });
                }
            });
        }
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_BABBAGE_HPP