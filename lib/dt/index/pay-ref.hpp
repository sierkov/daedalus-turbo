/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_PAY_REF_HPP
#define DAEDALUS_TURBO_INDEX_PAY_REF_HPP

#include <dt/index/common.hpp>

namespace daedalus_turbo::index::pay_ref {
    struct item {
        cardano::pay_ident id;
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
        void index_tx(const cardano::tx_base &tx) override
        {
            size_t out_idx = 0;
            tx.foreach_output([&](const auto &tx_out) {
                const auto addr = tx_out.addr();
                if (addr.has_pay_id()) {
                    const auto id = addr.pay_id();
                    _idx.emplace_part(id.hash.data()[0] / _part_range, std::move(id), tx.offset(), tx.size(), out_idx);
                }
                ++out_idx;
            });
        }
    };

    using indexer = indexer_offset<item, chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_PAY_REF_HPP