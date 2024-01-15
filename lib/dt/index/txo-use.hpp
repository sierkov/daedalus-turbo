/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_TXO_USE_HPP
#define DAEDALUS_TURBO_INDEX_TXO_USE_HPP

#include <dt/cardano.hpp>
#include <dt/index/common.hpp>

namespace daedalus_turbo::index::txo_use {

    struct __attribute__((packed)) item {
        cardano::tx_hash hash;
        cardano::tx_out_idx out_idx;
        uint64_t offset = 0;
        cardano::tx_size size {};
        cardano::epoch epoch {};
        
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
                    _idx.emplace_part(tx_hash[0] / _part_range,
                        tx_hash, txo_idx, tx.offset(), tx.size(), blk.slot().epoch());
                }
            });
            blk.foreach_invalid_tx([&](const auto &tx) {
                std::set<std::pair<cardano_hash_32, cardano::tx_out_idx>> inputs {};
                tx.foreach_collateral([&](const auto &tx_in) {
                    inputs.emplace(tx_in.tx_hash, tx_in.txo_idx);
                });
                for (const auto &[tx_hash, txo_idx]: inputs) {
                    _idx.emplace_part(tx_hash[0] / _part_range,
                        tx_hash, txo_idx, tx.offset(), tx.size(), blk.slot().epoch());
                }
            });
        }
    };

    using indexer = indexer_offset<item, chunk_indexer>;
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::index::txo_use::item>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "txo_use::item(hash: {} out_idx: {} offset: {} size: {} epoch: {})",
                v.hash, static_cast<size_t>(v.out_idx), static_cast<uint64_t>(v.offset), static_cast<size_t>(v.size), static_cast<uint64_t>(v.epoch));
        }
    };
}

#endif //!DAEDALUS_TURBO_INDEX_TXO_USE_HPP