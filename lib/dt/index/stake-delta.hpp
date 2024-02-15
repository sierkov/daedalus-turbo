/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_STAKE_DELTA_HPP
#define DAEDALUS_TURBO_INDEX_STAKE_DELTA_HPP

#include <dt/cardano/common.hpp>
#include <dt/index/common.hpp>

namespace daedalus_turbo::index::stake_delta {
    struct item {
        cardano::stake_ident_hybrid stake_id {};
        int64_t delta = 0;

        bool operator<(const auto &b) const
        {
            return stake_id < b.stake_id;
        }
    };

    struct chunk_indexer: public chunk_indexer_multi_epoch_zpp<item> {
        using chunk_indexer_multi_epoch_zpp<item>::chunk_indexer_multi_epoch_zpp;
        ~chunk_indexer()
        {
            for (const auto &[epoch, deltas]: _updates) {
                auto &data = _epoch_data(epoch);
                for (const auto &[stake_id, delta]: deltas)
                    data.emplace_back(stake_id, delta);
            }
        }
    protected:
        void _index_epoch(const cardano::block_base &blk, std::vector<item> &) override
        {
            blk.foreach_tx([&](const auto &tx) {
                uint64_t epoch = blk.slot().epoch();
                auto [up_it, up_created] = _updates.try_emplace(epoch);
                tx.foreach_output([&](const auto &txo) {
                    if (txo.address.has_stake_id()) {
                        auto [stake_it, stake_created] = up_it->second.try_emplace(txo.address.stake_id(), txo.amount);
                        if (!stake_created)
                            stake_it->second += txo.amount;
                    } else if (txo.address.has_pointer()) {
                        auto [stake_it, stake_created] = up_it->second.try_emplace(txo.address.pointer(), txo.amount);
                        if (!stake_created)
                            stake_it->second += txo.amount;
                    }
                });
            });
        }
    private:
        std::map<uint64_t, std::map<cardano::stake_ident_hybrid, int64_t>> _updates {};
    };

    using indexer = indexer_multi_epoch<item, chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_STAKE_DELTA_HPP