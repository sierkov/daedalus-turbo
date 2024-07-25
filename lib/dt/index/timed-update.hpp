/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_TIMED_UPDATE_HPP
#define DAEDALUS_TURBO_INDEX_TIMED_UPDATE_HPP

#include <dt/cardano.hpp>
#include <dt/index/common.hpp>

namespace daedalus_turbo::index::timed_update {
    struct stake_reg {
        cardano::stake_ident stake_id {};
    };
    struct stake_del {
        cardano::stake_ident stake_id {};
    };
    struct stake_deleg {
        cardano::stake_ident stake_id  {};
        cardano::pool_hash pool_id {};
    };
    struct stake_withdraw {
        cardano::stake_ident stake_id {};
        uint64_t amount = 0;
    };
    struct instant_reward_single {
        cardano::stake_ident stake_id {};
        uint64_t amount {};
        cardano::reward_source source {};
    };
    struct collected_collateral_input {
        cardano::tx_hash tx_hash {};
        cardano::tx_out_idx txo_idx {};
    };
    struct collected_collateral_refund {
        cardano::amount refund {};
    };
    struct gen_deleg {
        cardano::key_hash hash {};
        cardano::pool_hash pool_id {};
        cardano::vrf_vkey vrf_vkey {};
    };
    using variant = std::variant<
        stake_reg,
        cardano::pool_reg,
        instant_reward_single,
        stake_deleg,
        stake_withdraw,
        stake_del,
        cardano::pool_unreg,
        cardano::param_update_proposal,
        cardano::param_update_vote,
        collected_collateral_input,
        collected_collateral_refund,
        gen_deleg
    >;
    struct item {
        uint64_t slot = 0;
        size_t tx_idx = 0;
        size_t cert_idx = 0;
        variant update;

        bool operator<(const auto &b) const
        {
            if (slot != b.slot)
                return slot < b.slot;
            if (tx_idx != b.tx_idx)
                return tx_idx < b.tx_idx;
            if (cert_idx != b.cert_idx)
                return cert_idx < b.cert_idx;
            return update.index() < b.update.index();
        }
    };

    struct chunk_indexer: chunk_indexer_one_epoch<item> {
        using chunk_indexer_one_epoch::chunk_indexer_one_epoch;
    protected:
        void index_tx(const cardano::tx &tx) override
        {
            const auto slot = tx.block().slot();
            tx.foreach_stake_reg([&](const auto &stake_id, size_t cert_idx) {
                _data.emplace_back(slot, tx.index(), cert_idx, stake_reg { stake_id });
            });
            tx.foreach_pool_reg([&](const auto &reg) {
                _data.emplace_back(slot, tx.index(), 0, reg);
            });
            tx.foreach_instant_reward([&](const auto &ir) {
                for (const auto &[stake_id, reward]: ir.rewards)
                    _data.emplace_back(slot, tx.index(), 0, instant_reward_single { stake_id, reward, ir.source });
            });
            tx.foreach_stake_deleg([&](const auto &deleg) {
                _data.emplace_back(slot, tx.index(), deleg.cert_idx, stake_deleg { deleg.stake_id, deleg.pool_id });
            });
            tx.foreach_withdrawal([&](const auto &with) {
                _data.emplace_back(slot, tx.index(), 0, stake_withdraw { with.address.stake_id(), with.amount });
            });
            tx.foreach_stake_unreg([&](const auto &stake_id, size_t cert_idx) {
                _data.emplace_back(slot, tx.index(), cert_idx, stake_del { stake_id });
            });
            tx.foreach_pool_unreg([&](const auto &unreg) {
                _data.emplace_back(slot, tx.index(), 0, unreg);
            });
            tx.foreach_genesis_deleg([&](const auto &deleg, const size_t cert_idx) {
                _data.emplace_back(slot, tx.index(), cert_idx, gen_deleg { deleg.hash, deleg.pool_id, deleg.vrf_vkey });
            });
        }

        void index_invalid_tx(const cardano::tx &tx) override
        {
            const auto slot = tx.block().slot();
            if (const auto *babbage_tx = dynamic_cast<const cardano::babbage::tx *>(&tx); babbage_tx) {
                if (const auto c_ret = babbage_tx->collateral_return(); c_ret)
                    _data.emplace_back(slot, tx.index(), 0, collected_collateral_refund { c_ret->amount });
            }
            tx.foreach_collateral([&](const auto &tx_in) {
                logger::debug("collect collateral {}#{}", tx_in.tx_hash, tx_in.txo_idx);
                _data.emplace_back(slot, tx.index(), 0, collected_collateral_input { tx_in.tx_hash, tx_in.txo_idx });
            });
        }

        void _index_epoch(const cardano::block_base &blk, data_type &idx) override
        {
            blk.foreach_update_proposal([&](const auto &prop) {
                idx.emplace_back(blk.slot(), 0, 0, prop);
            });
            blk.foreach_update_vote([&](const auto &vote) {
                idx.emplace_back(blk.slot(), 0, 0, vote);
            });
        }
    };
    using indexer = indexer_one_epoch<chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_TIMED_UPDATE_HPP