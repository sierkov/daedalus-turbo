/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_UTXO_HPP
#define DAEDALUS_TURBO_INDEX_UTXO_HPP

#include <dt/cardano/common.hpp>
#include <dt/index/common.hpp>

namespace daedalus_turbo::index::utxo {
    struct chunk_indexer: chunk_indexer_one_epoch_base<cardano::txo_map> {
        using chunk_indexer_one_epoch_base::chunk_indexer_one_epoch_base;
    protected:
        void index_tx(const cardano::tx &tx) override
        {
            tx.foreach_output([&](const auto &tx_out) {
                _add_utxo(_data, tx, tx_out);
            });
            tx.foreach_input([&](const auto &tx_in) {
                _del_utxo(_data, cardano::tx_out_ref { tx_in.tx_hash, tx_in.txo_idx });
            });
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

        static void _add_utxo(data_type &idx, const cardano::tx &tx, const cardano::tx_output &tx_out)
        {
            if (const auto [it, created] = idx.try_emplace(cardano::tx_out_ref { tx.hash(), tx_out.idx }, cardano::tx_out_data::from_output(tx_out) ); !created) [[unlikely]]
                throw error("found a non-unique TXO {}#{}", tx.hash(), tx_out.idx);
        }
    };
    using indexer = indexer_one_epoch<chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_UTXO_HPP