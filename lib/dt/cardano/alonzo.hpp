/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_ALONZO_HPP
#define DAEDALUS_TURBO_CARDANO_ALONZO_HPP

#include <dt/cardano/common.hpp>
#include <dt/cardano/mary.hpp>
#include <dt/cbor.hpp>

namespace daedalus_turbo::cardano::alonzo {
    struct tx;

    inline param_update parse_alonzo_param_update(const cbor::value &proposal, const config &cfg)
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
                case 18: {
                    plutus_cost_models cost_mdls {};
                    for (const auto &[model_id, values]: val.map()) {
                        switch (model_id.uint()) {
                            case 0:
                                cost_mdls.v1.emplace(
                                    plutus_cost_model::from_cbor(cfg.plutus_v1_cost_model, values.array()));
                                break;
                            case 1:
                                cost_mdls.v2.emplace(
                                    plutus_cost_model::from_cbor(cfg.plutus_v2_cost_model, values.array()));
                                break;
                            default:
                                throw error("unsupported cost model id: {}", model_id);
                        }
                    }
                    upd.plutus_cost_models.emplace(std::move(cost_mdls));
                    break;
                }
                case 19:
                    upd.ex_unit_prices.emplace(
                        rational_u64 { val.at(0).tag().second->at(0).uint(), val.at(0).tag().second->at(1).uint() },
                        rational_u64 { val.at(1).tag().second->at(0).uint(), val.at(1).tag().second->at(1).uint() }
                    );
                    break;
                case 20:
                    upd.max_tx_ex_units.emplace(val.at(0).uint(), val.at(1).uint());
                    break;
                case 21:
                    upd.max_block_ex_units.emplace(val.at(0).uint(), val.at(1).uint());
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
                if (entry_type.uint() == 1) outputs = &entry.array();
            }
            if (outputs == nullptr) return;
            for (size_t i = 0; i < outputs->size(); ++i) {
                const cbor_value *address = nullptr;
                const cbor_value *amount = nullptr;
                const cbor_value *datum = nullptr;
                switch (outputs->at(i).type) {
                    case CBOR_ARRAY: {
                        const auto &out = outputs->at(i).array();
                        address = &out.at(0);
                        amount = &out.at(1);
                        if (out.size() > 2)
                            datum = &out.at(2);
                        break;
                    }
                    case CBOR_MAP:
                        for (const auto &[o_type, o_entry]: outputs->at(i).map()) {
                            switch (o_type.uint()) {
                            case 0: address = &o_entry; break;
                            case 1: amount = &o_entry; break;
                            case 2: datum = &o_entry; break;
                            default: break;
                            }
                        }
                        break;
                    default:
                        throw cardano_error("unsupported transaction output format era: {}, slot: {}!", _blk.era(), (uint64_t)_blk.slot());
                }
                if (address == nullptr)
                    throw cardano_error("transaction output misses address field!");
                if (amount == nullptr)
                    throw cardano_error("transaction output misses amount field!");
                auto tx_out = _extract_assets(*address, *amount, i);
                tx_out.datum = datum;
                observer(tx_out);
            }
        }

        void foreach_collateral(const std::function<void(const tx_input &)> &observer) const override
        {
            _if_item_present(13, [&](const auto &collateral_raw) {
                const auto &collaterals = collateral_raw.array();
                for (size_t i = 0; i < collaterals.size(); ++i) {
                    const auto &txin = collaterals.at(i).array();
                    observer(tx_input { txin.at(0).buf(), txin.at(1).uint(), i });
                }
            });
        }
    };

    inline void block::foreach_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        std::set<size_t> invalid_tx_idxs {};
        if (protocol_ver().major >= 6) {
            for (const auto &tx_idx: invalid_transactions())
                invalid_tx_idxs.emplace(tx_idx.uint());
        }
        for (size_t i = 0; i < txs.size(); ++i)
            if (!invalid_tx_idxs.contains(i))
                observer(tx { txs.at(i), *this, &wits.at(i), i });
    }

    inline void block::foreach_invalid_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        if (protocol_ver().major >= 6) {
            const auto &txs = transactions();
            const auto &wits = witnesses();
            for (const auto &tx_idx: invalid_transactions())
                observer(tx { txs.at(tx_idx.uint()), *this, &wits.at(tx_idx.uint()), tx_idx.uint() });
        }
    }
}

#endif // !DAEDALUS_TURBO_CARDANO_ALONZO_HPP