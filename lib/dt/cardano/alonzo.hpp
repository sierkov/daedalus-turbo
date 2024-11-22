/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_ALONZO_HPP
#define DAEDALUS_TURBO_CARDANO_ALONZO_HPP

#include <dt/cardano/common.hpp>
#include <dt/cardano/mary.hpp>
#include <dt/cbor.hpp>
#include <dt/plutus/types.hpp>

namespace daedalus_turbo::cardano::alonzo {
    struct tx;

    inline param_update parse_alonzo_param_update(const cbor::value &proposal, const config &)
    {
        param_update upd {};
        for (const auto &[idx, val]: proposal.map()) {
            switch (idx.uint()) {
                case 0:
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                case 8:
                case 9:
                case 10:
                case 11:
                case 12:
                case 13:
                case 14:
                    shelley::parse_shelley_param_update_common(upd, idx.uint(), val);
                    break;
                case 16: upd.min_pool_cost.emplace(val.uint()); break;
                case 17: upd.lovelace_per_utxo_byte.emplace(val.uint()); break;
                case 18: upd.plutus_cost_models.emplace(val); break;
                case 19:
                    upd.ex_unit_prices.emplace(
                        rational_u64 { val.at(0).tag().second->at(0).uint(), val.at(0).tag().second->at(1).uint() },
                        rational_u64 { val.at(1).tag().second->at(0).uint(), val.at(1).tag().second->at(1).uint() }
                    );
                    break;
                case 20:
                    upd.max_tx_ex_units.emplace(val);
                    break;
                case 21:
                    upd.max_block_ex_units.emplace(val);
                    break;
                case 22: upd.max_value_size.emplace(val.uint()); break;
                case 23: upd.max_collateral_pct.emplace(val.uint()); break;
                case 24: upd.max_collateral_inputs.emplace(val.uint()); break;
                default:
                    throw error("unsupported parameter id: {} val: {}", idx, val);
            }
        }
        return upd;
    }

    struct block: mary::block {
        using mary::block::block;

        void foreach_tx(const std::function<void(const cardano::tx &)> &observer) const override;
        void foreach_invalid_tx(const std::function<void(const cardano::tx &)> &observer) const override;

        const cbor_array &invalid_transactions() const
        {
            return _block.array().at(4).array();
        }
    };

    struct tx: mary::tx {
        using mary::tx::tx;

        void foreach_param_update(const std::function<void(const param_update_proposal &)> &observer) const override {
            _if_item_present(6, [&](const auto &update) {
                const uint64_t epoch = update.array().at(1).uint();
                for (const auto &[genesis_deleg_hash, proposal]: update.array().at(0).map()) {
                    param_update_proposal prop { genesis_deleg_hash.buf(), epoch, parse_alonzo_param_update(proposal, _blk.config()) };
                    prop.update.rehash();
                    observer(prop);
                }
            });
        }

        void foreach_output(const std::function<void(const tx_output &)> &observer) const override
        {
            const cbor_array *outputs = nullptr;
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 1)
                    outputs = &entry.array();
            }
            if (outputs) {
                for (size_t i = 0; i < outputs->size(); ++i)
                    observer(tx_output::from_cbor(_blk.era(), i, outputs->at(i)));
            }
        }

        void foreach_collateral(const std::function<void(const tx_input &)> &observer) const override
        {
            _if_item_present(13, [&](const auto &collateral_raw) {
                foreach_set(collateral_raw, [&](const auto &txin_raw, const size_t i) {
                    const auto &txin = txin_raw.array();
                    observer(tx_input { txin.at(0).buf(), txin.at(1).uint(), i });
                });
            });
        }

        void foreach_required_signer(const std::function<void(buffer)> &observer) const override
        {
            _if_item_present(14, [&](const auto &signers_raw) {
                foreach_set(signers_raw, [&](const auto &vkey_hash, const size_t) {
                    observer(vkey_hash.buf());
                });
            });
        }

        void foreach_script(const std::function<void(script_info &&)> &, const plutus::context *ctx=nullptr) const override;
        void foreach_redeemer(const std::function<void(const tx_redeemer &)> &) const override;
        virtual wit_cnt witnesses_ok_plutus(const plutus::context &ctx) const;
        wit_cnt witnesses_ok_other(const plutus::context *ctx=nullptr) const override;
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_ALONZO_HPP