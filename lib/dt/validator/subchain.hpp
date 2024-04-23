/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_VALIDATOR_SUBCHAIN_HPP
#define DAEDALUS_TURBO_VALIDATOR_SUBCHAIN_HPP

#include <functional>
#include <map>
#include <zpp_bits.h>
#include <dt/cardano/type.hpp>
#include <dt/error.hpp>

namespace daedalus_turbo::validator {
    struct kes_interval {
        using serialize = zpp::bits::members<2>;
        size_t first_counter = 0;
        size_t last_counter = 0;

        kes_interval() =default;

        kes_interval(size_t fc, size_t lc)
            : first_counter { fc }, last_counter { lc }
        {
            if (first_counter > last_counter)
                throw error("KES interval must be non decreasing but got first: {} last: {}",
                    first_counter, last_counter);
        }

        bool can_merge(const kes_interval &right) const
        {
            return last_counter <= right.first_counter;
        }

        void can_merge(const kes_interval &right, const cardano::pool_hash &pool_id, const uint64_t chunk_offset) const
        {
            if (!can_merge(right))
                throw error("KES intervals from chunk at offset: {} do not merge for pool: {}", chunk_offset, pool_id);
        }

        void merge(const kes_interval &right, const cardano::pool_hash &pool_id, const uint64_t chunk_offset)
        {
            can_merge(right, pool_id, chunk_offset);
            last_counter = right.last_counter;
        }

        void merge_right(const kes_interval &left, const cardano::pool_hash &pool_id, const uint64_t chunk_offset)
        {
            left.can_merge(*this, pool_id, chunk_offset);
            first_counter = left.first_counter;
        }

        bool operator==(const auto &b) const
        {
            return first_counter == b.first_counter && last_counter == b.last_counter;
        }
    };

    struct kes_interval_map: std::map<cardano::pool_hash, kes_interval> {
        using std::map<cardano::pool_hash, kes_interval>::map;

        void merge(const kes_interval_map &right, const uint64_t chunk_offset)
        {
            for (const auto &[pool_id, right_interval]: right) {
                auto [left_it, created] = try_emplace(pool_id, right_interval);
                if (!created)
                    left_it->second.merge(right_interval, pool_id, chunk_offset);
            }
        }
    };

    struct subchain {
        size_t offset = 0;
        size_t num_bytes = 0;
        size_t num_blocks = 0;
        size_t ok_eligibility = 0;
        kes_interval_map kes_intervals {};
        // these fields are carried only and managed externally
        size_t epoch = 0;
        bool snapshot = false;

        void merge(const subchain &right)
        {
            if (end_offset() != right.offset)
                throw error("unmergeable subchains left end: {} right start: {}",
                    end_offset(), right.offset);
            num_bytes += right.num_bytes;
            num_blocks += right.num_blocks;
            ok_eligibility += right.ok_eligibility;
            kes_intervals.merge(right.kes_intervals, right.offset);
        }

        size_t end_offset() const
        {
            return offset + num_bytes;
        }

        bool operator<(const auto &v) const
        {
            if (offset != v.offset)
                return offset < v.offset;
            return num_bytes < v.num_bytes;
        }

        explicit operator bool() const
        {
            return num_bytes > 0 && num_blocks > 0 && num_blocks == ok_eligibility;
        }
    };

    struct subchain_list: std::map<uint64_t, subchain> {
        explicit subchain_list(const std::function<void(const subchain &)> &take_snapshot)
            : _take_snapshot { take_snapshot }
        {
        }

        void add(subchain &&sc)
        {
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
            uint64_t offset = 0;
            if (!empty() && begin()->second && begin()->second.offset == 0)
                offset = begin()->second.num_bytes;
            return offset;
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
                    //if (next_it->second.snapshot)
                    // experimental support for on-the-go checkpoints
                    _take_snapshot(it->second);
                }
                _adjust_updated_subchain(it);
            }
        }

        void merge_same_epoch()
        {
            for (auto it = begin(); it != end(); ) {
                auto next_it = std::next(it);
                while (next_it != end() && it->second.end_offset() == next_it->second.offset && it->second.epoch == next_it->second.epoch) {
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

#endif // !DAEDALUS_TURBO_VALIDATOR_SUBCHAIN_HPP