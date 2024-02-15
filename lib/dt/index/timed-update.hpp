/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
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
        stake_ident stake_id  {};
        cardano_hash_28 pool_id {};
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
    struct collected_collateral {
        cardano::tx_hash tx_hash {};
        cardano::tx_out_idx txo_idx {};
    };
    using variant = std::variant<
        stake_reg,
        cardano::pool_reg,
        instant_reward_single,
        stake_deleg,
        stake_withdraw,
        stake_del,
        cardano::pool_unreg,
        cardano::param_update,
        collected_collateral>;
    struct item {
        uint64_t slot {};
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

    struct chunk_indexer: public chunk_indexer_multi_epoch_zpp<item> {
        using chunk_indexer_multi_epoch_zpp<item>::chunk_indexer_multi_epoch_zpp;
    protected:
        void _index_epoch(const cardano::block_base &blk, std::vector<item> &idx) override
        {
            blk.foreach_tx([&](const auto &tx) {
                tx.foreach_stake_reg([&](const auto &stake_id, size_t cert_idx) {
                    idx.emplace_back(blk.slot(), tx.index(), cert_idx, stake_reg { stake_id });
                });
                tx.foreach_pool_reg([&](const auto &reg) {
                    idx.emplace_back(blk.slot(), tx.index(), 0, reg);
                });
                tx.foreach_instant_reward([&](const auto &ir) {
                    for (const auto &[stake_id, reward]: ir.rewards)
                        idx.emplace_back(blk.slot(), tx.index(), 0, instant_reward_single { stake_id, reward, ir.source });
                });
                tx.foreach_stake_deleg([&](const auto &deleg) {
                    idx.emplace_back(blk.slot(), tx.index(), deleg.cert_idx, stake_deleg { deleg.stake_id, deleg.pool_id });
                });
                tx.foreach_withdrawal([&](const auto &with) {
                    idx.emplace_back(blk.slot(), tx.index(), 0, stake_withdraw { with.address.stake_id(), with.amount });
                });
                tx.foreach_stake_unreg([&](const auto &stake_id, size_t cert_idx) {
                    idx.emplace_back(blk.slot(), tx.index(), cert_idx, stake_del { stake_id });
                });
                tx.foreach_pool_unreg([&](const auto &unreg) {
                    idx.emplace_back(blk.slot(), tx.index(), 0, unreg);
                });
                tx.foreach_param_update([&](const auto &upd) {
                    idx.emplace_back(blk.slot(), tx.index(), 0, upd);
                });
            });
            blk.foreach_invalid_tx([&](const auto &tx) {
                tx.foreach_collateral([&](const auto &tx_in) {
                    idx.emplace_back(blk.slot(), tx.index(), 0, collected_collateral { tx_in.tx_hash, tx_in.txo_idx });
                });
            });
        }
    };
    using indexer = indexer_multi_epoch<item, chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_TIMED_UPDATE_HPP