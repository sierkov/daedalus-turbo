/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_BLOCK_FEES_HPP
#define DAEDALUS_TURBO_INDEX_BLOCK_FEES_HPP

#include <dt/cardano.hpp>
#include <dt/index/common.hpp>

namespace daedalus_turbo::index::block_fees {
    struct item {
        cardano::pool_hash issuer_id {};
        uint64_t fees = 0;
        uint64_t end_offset = 0;
        uint8_t era = 0;

        bool operator<(const auto &b) const
        {
            int cmp = memcmp(issuer_id.data(), b.issuer_id.data(), issuer_id.size());
            if (cmp != 0)
                return cmp < 0;
            return fees < b.fees;
        }
    };

    struct chunk_indexer: public chunk_indexer_multi_epoch_zpp<item> {
        using chunk_indexer_multi_epoch_zpp<item>::chunk_indexer_multi_epoch_zpp;
    protected:
        void _index_epoch(const cardano::block_base &blk, std::vector<item> &idx) override
        {
            uint64_t fees = 0;
            blk.foreach_tx([&](const auto &tx) {
                fees += tx.fee();
            });
            idx.emplace_back(blk.issuer_hash(), fees, blk.offset() + blk.size(), blk.era());
        }
    };
    using indexer = indexer_multi_epoch<item, chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_BLOCK_FEES_HPP