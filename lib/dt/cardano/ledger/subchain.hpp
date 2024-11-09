/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_LEDGER_SUBCHAIN_HPP
#define DAEDALUS_TURBO_CARDANO_LEDGER_SUBCHAIN_HPP

#include <functional>
#include <map>
#include <dt/cardano/types.hpp>
#include <dt/error.hpp>

namespace daedalus_turbo::cardano::ledger {
    struct subchain {
        size_t offset = 0;
        size_t num_bytes = 0;
        size_t num_blocks = 0;
        size_t valid_blocks = 0;
        size_t first_block_slot = 0;
        cardano::block_hash first_block_hash {};
        size_t last_block_slot = 0;
        cardano::block_hash last_block_hash {};

        void merge(const subchain &right)
        {
            if (end_offset() != right.offset)
                throw error("unmergeable subchains left end: {} right start: {}", end_offset(), right.offset);
            if (right.first_block_slot < first_block_slot)
                throw error("unmergeable subchains left first_block_slot: {} right first_block_slot: {}", first_block_slot, right.first_block_slot);
            if (right.last_block_slot < last_block_slot)
                throw error("unmergeable subchains left last_block_slot: {} right last_block_slot: {}", last_block_slot, right.last_block_slot);
            num_bytes += right.num_bytes;
            num_blocks += right.num_blocks;
            valid_blocks += right.valid_blocks;
            last_block_slot = right.last_block_slot;
            last_block_hash = right.last_block_hash;
        }

        size_t end_offset() const
        {
            return offset + num_bytes;
        }

        bool operator==(const auto &o) const
        {
            return offset == o.offset && num_bytes == o.num_bytes && num_blocks == o.num_blocks
                && valid_blocks == o.valid_blocks && first_block_slot == o.first_block_slot && last_block_slot == o.last_block_slot
                && first_block_hash == o.first_block_hash && last_block_hash == o.last_block_hash;
        }

        bool operator<(const auto &v) const
        {
            if (offset != v.offset)
                return offset < v.offset;
            return num_bytes < v.num_bytes;
        }

        explicit operator bool() const
        {
            return num_bytes > 0 && num_blocks > 0 && num_blocks == valid_blocks;
        }
    };

    struct subchain_list: std::map<uint64_t, subchain> {
        void add(subchain &&sc)
        {
            if (sc.first_block_slot > sc.last_block_slot)
                throw error("a subchain with an invalid slot range: [{}, {}]", sc.first_block_slot, sc.last_block_slot);
            auto [it, created] = emplace(sc.offset + sc.num_bytes - 1, std::move(sc));
            if (!created)
                throw error("duplicate subchain starting a offset {} size {}", sc.offset, sc.num_bytes);
            if (it->second)
                merge_valid();
        }

        void add(const subchain &sc)
        {
            add(subchain { sc });
        }

        iterator find(uint64_t offset)
        {
            auto it = lower_bound(offset);
            if (it == end() || !(it->second.offset <= offset && it->first >= offset))
                throw error("internal error: can't find subchain for blockchain offset {}", offset);
            return it;
        }

        uint64_t valid_size() const
        {
            if (!empty() && begin()->second && begin()->second.offset == 0) [[likely]]
                return begin()->second.num_bytes;
            return 0;
        }

        cardano::optional_point max_valid_point() const
        {
            if (const auto it = begin(); it != end() && it->second && it->second.offset == 0) [[likely]]
                return cardano::point { it->second.last_block_hash, it->second.last_block_slot, 0, it->second.num_bytes };
            return {};
        }

        void merge_valid()
        {
            if (!empty() && begin()->second) {
                auto it = begin();
                for (auto next_it = std::next(it);
                    next_it != end() && it->second.end_offset() == next_it->second.offset && next_it->second;
                    next_it = erase(next_it))
                {
                    it->second.merge(next_it->second);
                }
                _adjust_updated_subchain(it);
            }
        }

        void merge_same_epoch(const cardano::config &cfg)
        {
            for (auto it = begin(); it != end(); ) {
                auto next_it = std::next(it);
                while (next_it != end() && it->second.end_offset() == next_it->second.offset) {
                    const auto first_block_slot = cardano::slot { it->second.first_block_slot, cfg };
                    const auto last_block_slot = cardano::slot { it->second.last_block_slot, cfg };
                    if (!it->second && first_block_slot.epoch() != last_block_slot.epoch())
                        throw error("an unvalidated subchain at [{}:{}) has slots from different epochs: first slot: {} last_slot: {}",
                            it->second.offset, it->second.end_offset(), first_block_slot, last_block_slot);
                    const auto next_first_block_slot = cardano::slot { next_it->second.first_block_slot, cfg };
                    const auto next_last_block_slot = cardano::slot { next_it->second.last_block_slot, cfg };
                    if (!next_it->second && next_first_block_slot.epoch() != next_last_block_slot.epoch())
                        throw error("an unvalidated subchain at [{}:{}) has slots from different epochs: first slot: {} last_slot: {}",
                            next_it->second.offset, next_it->second.end_offset(), next_first_block_slot, next_last_block_slot);
                    if (last_block_slot.epoch() != next_first_block_slot.epoch())
                        break;
                    it->second.merge(next_it->second);
                    next_it = erase(next_it);
                }
                _adjust_updated_subchain(it);
                it = next_it;
            }
        }
    private:
        std::function<void(const subchain &)> _take_snapshot {};

        void _adjust_updated_subchain(iterator it)
        {
            uint64_t last_offset = it->second.end_offset() - 1;
            if (it->first != last_offset) {
                auto node = extract(it);
                node.key() = last_offset;
                auto [new_it, created, nt] = insert(std::move(node));
                if (!created)
                    throw error("duplicate subchain found with last_offset {}", last_offset);
            }
        }
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_LEDGER_SUBCHAIN_HPP