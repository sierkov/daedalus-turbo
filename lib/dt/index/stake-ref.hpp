/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_STAKE_REF_HPP
#define DAEDALUS_TURBO_INDEX_STAKE_REF_HPP

#include <dt/cardano.hpp>
#include <dt/index/common.hpp>

namespace daedalus_turbo::index::stake_ref {

    struct item {
        cardano::stake_ident id;
        uint64_t offset = 0;
        cardano::tx_size size {};
        cardano::tx_out_idx out_idx {};

        bool operator<(const auto &b) const
        {
            int cmp = memcmp(&id, &b.id, sizeof(id));
            if (cmp != 0) return cmp < 0;
            if (offset != b.offset) return offset < b.offset;
            return out_idx < b.out_idx;
        }

        bool index_less(const auto &b) const
        {
            return memcmp(&id, &b.id, sizeof(id)) < 0;
        }

        bool operator==(const auto &b) const
        {
            return memcmp(&id, &b.id, sizeof(id)) == 0;
        }
    };

    struct chunk_indexer: chunk_indexer_multi_part<item> {
        using chunk_indexer_multi_part<item>::chunk_indexer_multi_part;
    protected:
        void index_tx(const cardano::tx &tx) override
        {
            tx.foreach_output([&](const auto &tx_out) {
                if (!tx_out.address.has_stake_id())
                    return;
                const auto id = tx_out.address.stake_id();
                _idx.emplace_part(id.hash.data()[0] / _part_range, std::move(id), tx.offset(), tx.size(), tx_out.idx);
            });
        }
    };

    using indexer = indexer_offset<item, chunk_indexer>;
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::index::stake_ref::item>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "stake-ref::item(id: {}, offset: {}, size: {}, out_idx: {})",
                v.id, static_cast<uint64_t>(v.offset), static_cast<size_t>(v.size), static_cast<size_t>(v.out_idx));
        }
    };
}

#endif //!DAEDALUS_TURBO_INDEX_STAKE_REF_HPP