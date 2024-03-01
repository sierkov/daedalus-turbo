/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_TX_HPP
#define DAEDALUS_TURBO_INDEX_TX_HPP

#include <dt/cardano.hpp>
#include <dt/index/common.hpp>

namespace daedalus_turbo::index::tx {
    struct item {
        cardano_hash_32 hash;
        uint64_t offset = 0;
        cardano::tx_size size {};

        bool operator<(const auto &b) const
        {
            int cmp = memcmp(hash.data(), b.hash.data(), hash.size());
            if (cmp != 0) return cmp < 0;
            return offset < b.offset;
        }

        bool index_less(const auto &b) const
        {
            return memcmp(hash.data(), b.hash.data(), hash.size()) < 0;
        }

        bool operator==(const auto &b) const
        {
            return memcmp(hash.data(), b.hash.data(), hash.size()) == 0;
        }
    };

    struct chunk_indexer: chunk_indexer_multi_part<item> {
        using chunk_indexer_multi_part<item>::chunk_indexer_multi_part;
    protected:
        void _index(const cardano::block_base &blk) override
        {
            blk.foreach_tx([this](const auto &tx) {
                const auto &tx_hash = tx.hash();
                _idx.emplace_part(tx_hash.data()[0] / _part_range, tx_hash, tx.offset(), tx.size());
            });
        }
    };

    using indexer = indexer_offset<item, chunk_indexer>;
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::index::tx::item>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "tx::item(hash: {} offset: {} size: {})",
                v.hash, v.offset, static_cast<size_t>(v.size));
        }
    };
}

#endif //!DAEDALUS_TURBO_INDEX_TX_HPP