/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_TXO_USE_HPP
#define DAEDALUS_TURBO_INDEX_TXO_USE_HPP

#include <dt/cardano.hpp>
#include <dt/index/common.hpp>
#include <dt/index/block-meta.hpp>
#include <dt/index/tx.hpp>

namespace daedalus_turbo::index::txo_use {

    struct __attribute__((packed)) item {
        cardano_hash_32 hash;
        cardano::tx_out_idx out_idx;
        uint64_t offset = 0;
        cardano::tx_size size {};
        
        bool operator<(const auto &b) const
        {
            int cmp = memcmp(hash.data(), b.hash.data(), hash.size());
            if (cmp != 0) return cmp < 0;
            if (out_idx != b.out_idx) return out_idx < b.out_idx;
            return offset < b.offset;
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
                // necessary since some transactions contain duplicate inputs and Cardano Node allows it!
                std::set<std::pair<cardano_hash_32, cardano::tx_out_idx>> inputs {};
                tx.foreach_input([&](const auto &tx_in) {
                    inputs.emplace(tx_in.tx_hash, tx_in.txo_idx);
                });
                for (const auto &[tx_hash, txo_idx]: inputs) {
                    _idx.emplace_part(
                        tx_hash[0] / _part_range,
                        tx_hash,
                        txo_idx,
                        tx.offset(),
                        tx.size());
                }
            });
        }
    };

    using indexer = indexer_offset<item, chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_TXO_USE_HPP