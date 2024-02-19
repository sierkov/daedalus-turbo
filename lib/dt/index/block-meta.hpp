/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_BLOCK_META_HPP
#define DAEDALUS_TURBO_INDEX_BLOCK_META_HPP

#include <dt/cardano.hpp>
#include <dt/index/common.hpp>

namespace daedalus_turbo::index::block_meta {
    struct item {
        uint64_t offset = 0;
        cardano::slot slot {};
        uint64_t size: 24 = 0;
        uint64_t era: 8 = 0;

        bool operator<(const auto &b) const {
            return offset < b.offset;
        }

        bool index_less(const auto &b) const
        {
            return offset < b.offset;
        }

        bool operator==(const auto &b) const
        {
            return offset == b.offset;
        }
    };

    struct chunk_indexer: public chunk_indexer_one_part<item> {
        using chunk_indexer_one_part<item>::chunk_indexer_one_part;
    protected:
        void _index(const cardano::block_base &blk) override
        {
            if (blk.era() >= (1 << 8)) throw error("era is too big: {}!", blk.era());
            if (blk.size() >= (1 << 24)) throw error("block size is too big: {}!", blk.size());
            _idx.emplace(blk.offset(), blk.slot(), blk.size(), blk.era());
        }
    };

    using indexer = indexer_offset<item, chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_BLOCK_META_HPP