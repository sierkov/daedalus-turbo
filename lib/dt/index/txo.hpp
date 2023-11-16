/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_TXO_HPP
#define DAEDALUS_TURBO_INDEX_TXO_HPP

#include <dt/cardano.hpp>
#include <dt/index/common.hpp>

namespace daedalus_turbo::index::txo {
    struct __attribute__((packed)) item {
        cardano_hash_32 hash {};
        cardano::tx_out_idx out_idx {};
        uint64_t amount = 0;
        uint64_t offset = 0;
        stake_ident stake_id {};
        
        bool operator<(const auto &b) const
        {
            int cmp = memcmp(hash.data(), b.hash.data(), hash.size());
            if (cmp != 0) return cmp < 0;
            if (out_idx != b.out_idx) return out_idx < b.out_idx;
            return amount < b.amount;
        }

        bool index_less(const item &b) const
        {
            int cmp = memcmp(hash.data(), b.hash.data(), hash.size());
            if (cmp != 0) return cmp < 0;
            return out_idx < b.out_idx;
        }

        bool operator==(const item &b) const
        {
            int cmp = memcmp(hash.data(), b.hash.data(), hash.size());
            if (cmp != 0) return false;
            return out_idx == b.out_idx;
        }
    };

    struct chunk_indexer: public chunk_indexer_multi_part<item> {
        using chunk_indexer_multi_part<item>::chunk_indexer_multi_part;
    protected:
        void _index(const cardano::block_base &blk) override
        {
            blk.foreach_tx([&](const auto &tx) {
                tx.foreach_output([&](const auto &txo) {
                    if (txo.address.has_stake_id())
                        _idx.emplace_part(tx.hash().data()[0] / _part_range, tx.hash(), txo.idx, txo.amount, tx.offset(), txo.address.stake_id());
                });
            });
        }
    };

    using indexer = indexer_offset<item, chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_TXO_HPP