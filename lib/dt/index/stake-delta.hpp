/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
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

    struct chunk_indexer: chunk_indexer_one_epoch<item> {
        using chunk_indexer_one_epoch::chunk_indexer_one_epoch;
        ~chunk_indexer()
        {
            for (const auto &[stake_id, delta]: _deltas)
                _data.emplace_back(stake_id, delta);
        }
    protected:
        void _index_epoch(const cardano::block_base &blk, data_list &) override
        {
            blk.foreach_tx([&](const auto &tx) {
                tx.foreach_output([&](const auto &txo) {
                    if (txo.address.has_stake_id()) {
                        auto [stake_it, stake_created] = _deltas.try_emplace(txo.address.stake_id(), txo.amount);
                        if (!stake_created)
                            stake_it->second += txo.amount;
                    } else if (txo.address.has_pointer()) {
                        auto [stake_it, stake_created] = _deltas.try_emplace(txo.address.pointer(), txo.amount);
                        if (!stake_created)
                            stake_it->second += txo.amount;
                    }
                });
            });
        }
    private:
        std::map<cardano::stake_ident_hybrid, int64_t> _deltas {};
    };

    using indexer = indexer_one_epoch<item, chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_STAKE_DELTA_HPP