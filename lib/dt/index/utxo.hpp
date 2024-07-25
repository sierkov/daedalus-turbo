/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_UTXO_HPP
#define DAEDALUS_TURBO_INDEX_UTXO_HPP

#include <dt/cardano/common.hpp>
#include <dt/cbor-encoder.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/index/common.hpp>
#include <dt/partitioned-map.hpp>

namespace daedalus_turbo::index::utxo {
    struct chunk_indexer: chunk_indexer_one_epoch_base<partitioned_map<cardano::tx_out_ref, cardano::tx_out_data>> {
        using chunk_indexer_one_epoch_base::chunk_indexer_one_epoch_base;
    protected:
        void index_tx(const cardano::tx &tx) override
        {
            tx.foreach_output([&](const auto &tx_out) {
                _add_utxo(_data, tx, tx_out);
            });
            // the set is necessary since some transactions contain duplicate inputs and Cardano Node allows it!
            std::set<cardano::tx_out_ref> inputs {};
            tx.foreach_input([&](const auto &tx_in) {
                inputs.emplace(tx_in.tx_hash, tx_in.txo_idx);
            });
            for (const auto &txo_id: inputs)
                _del_utxo(_data, txo_id);
        }

        void index_invalid_tx(const cardano::tx &tx) override
        {
            // UTXOs used as collaterals are processed in validator.cpp:_apply_ledger_state_updates_for_epoch
            if (const auto *babbage_tx = dynamic_cast<const cardano::babbage::tx *>(&tx); babbage_tx) {
                if (const auto c_ret = babbage_tx->collateral_return(); c_ret) {
                    logger::debug("slot: {} found collateral refund {}#{}: {}", tx.block().slot(), tx.hash(), c_ret->idx, *c_ret);
                    _add_utxo(_data, tx, *c_ret);
                }
            }
        }
    private:
        void _del_utxo(data_type &idx, const cardano::tx_out_ref &txo_id)
        {
            auto [it, created] = idx.try_emplace(txo_id);
            // If a txo is created and consumed within the same chunk, don't report it.
            if (!created) [[unlikely]] {
                if (!it->second.address.empty()) [[likely]] {
                    idx.erase(it);
                } else {
                    throw error("found a non-unique TXO in the same chunk {}#{}", txo_id);
                }
            }
        }

        static std::optional<uint8_vector> _normalize_assets(const buffer policies_buf)
        {
            std::optional<uint8_vector> res {};
            const cbor::zero::value policies = cbor::zero::parse(policies_buf);
            if (policies.size()) [[likely]] {
                map<buffer, uint8_vector> ok_policies {};
                auto p_it = policies.map();
                while (!p_it.done()) [[likely]] {
                    const auto [policy_id, assets] = p_it.next();
                    if (assets.size()) [[likely]] {
                        // create a map to sort the assets
                        map<buffer, cbor::zero::value> ok_assets {};
                        auto a_it = assets.map();
                        while (!a_it.done()) [[likely]] {
                            const auto [asset_id, coin] = a_it.next();
                            if (coin.uint())
                                ok_assets.emplace(asset_id.bytes(), coin);
                        }
                        if (!ok_assets.empty()) [[likely]] {
                            cbor::encoder p_enc {};
                            p_enc.map_compact(ok_assets.size(), [&] {
                                for (const auto &[asset_id, coin]: ok_assets)
                                    p_enc.bytes(asset_id).raw_cbor(coin.raw_span());
                            });
                            ok_policies.emplace(policy_id.bytes(), std::move(p_enc.cbor()));
                        }
                    }
                }
                if (!ok_policies.empty()) [[likely]] {
                    cbor::encoder final_enc {};
                    final_enc.map_compact(ok_policies.size(), [&] {
                        for (const auto &[policy_id, assets]: ok_policies)
                            final_enc.bytes(policy_id).raw_cbor(assets);
                    });
                    res.emplace(std::move(final_enc.cbor()));
                }
            }
            return res;
        }

        static void _add_utxo(data_type &idx, const cardano::tx &tx, const cardano::tx_output &tx_out)
        {
            auto [it, created] = idx.try_emplace(cardano::tx_out_ref { tx.hash(), tx_out.idx }, tx_out.amount);
            if (!created) [[unlikely]]
                throw error("found a non-unique TXO {}#{}", tx.hash(), tx_out.idx);
            it->second.address = tx_out.address.bytes();
            if (tx_out.assets)
                it->second.assets = _normalize_assets(tx_out.assets->raw_span());
            if (tx_out.datum) {
                switch (tx_out.datum->type) {
                    case CBOR_BYTES:
                        it->second.datum.emplace(cardano::datum_hash { tx_out.datum->buf() });
                        break;
                    case CBOR_ARRAY: {
                        switch (tx_out.datum->at(0).uint()) {
                            case 0:
                                it->second.datum.emplace(cardano::datum_hash { tx_out.datum->at(1).buf() });
                                break;
                            case 1:
                                it->second.datum.emplace(uint8_vector { tx_out.datum->at(1).tag().second->buf() });
                                break;
                            default:
                                throw error("unexpected datum value: {} in TXO {}#{}", *tx_out.datum, tx.hash(), tx_out.idx);
                        }
                        break;
                    }
                    default:
                        throw error("unexpected datum value: {} in TXO {}#{}", *tx_out.datum, tx.hash(), tx_out.idx);
                }
            }
            if (tx_out.script_ref)
                it->second.script_ref.emplace(tx_out.script_ref->tag().second->buf());
        }
    };
    using indexer = indexer_one_epoch<chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_UTXO_HPP