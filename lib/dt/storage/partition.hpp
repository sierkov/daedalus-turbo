/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_STORAGE_PARTITION_HPP
#define DAEDALUS_TURBO_STORAGE_PARTITION_HPP

#include <dt/chunk-registry.hpp>

namespace daedalus_turbo::storage {
    struct partition {
        using storage_type = vector<const chunk_info *>;
        using const_iterator = storage_type::const_iterator;

        partition() =delete;
        partition(const partition &) =delete;

        partition(partition &&o): _chunks { std::move(o._chunks) }
        {
        }

        partition(storage_type &&chunks): _chunks { std::move(chunks) }
        {
            if (_chunks.empty()) [[unlikely]]
                throw error("a partition must contain at least one chunk!");
        }

        uint64_t offset() const
        {
            return _chunks.front()->offset;
        }

        uint64_t end_offset() const
        {
            return _chunks.back()->end_offset();
        }

        uint64_t size() const
        {
            return _chunks.back()->end_offset() - _chunks.front()->offset;
        }

        const_iterator begin() const
        {
            return _chunks.begin();
        }

        const_iterator end() const
        {
            return _chunks.end();
        }
    private:
        vector<const chunk_info *> _chunks {};
    };

    struct partition_map {
        using storage_type = const vector<partition>;
        using const_iterator = storage_type::const_iterator;

        explicit partition_map(const chunk_registry &cr, const size_t num_parts=256):
            _parts { _chunk_partitions(cr, num_parts) }
        {
        }

        size_t find_no(const uint64_t offset) const
        {
            const auto it = _find_it(offset);
            return it - _parts.begin();
        }

        const partition &find(const uint64_t offset) const
        {
            return *_find_it(offset);
        }

        size_t size() const
        {
            return _parts.size();
        }

        const partition &at(const size_t idx) const
        {
            return _parts.at(idx);
        }
    private:
        const vector<partition> _parts;

        static vector<partition> _chunk_partitions(const chunk_registry &cr, size_t num_parts);

        const_iterator _find_it(const uint64_t offset) const
        {
            const auto it = std::lower_bound(_parts.begin(), _parts.end(), offset,
                [](const partition &p, const uint64_t off) { return p.end_offset() <= off; });
            if (it != _parts.end()) [[likely]]
                return it;
            throw error("an offset that belongs to no partition: {}", offset);
        }
    };

    extern void parse_parallel(const chunk_registry &cr, size_t num_parts,
        const std::function<void(cardano::block_base &blk, std::any &)> &on_block,
        const std::function<std::any(size_t)> &on_part_init,
        const std::function<void(size_t, std::any &&)> &on_part_done,
        const std::optional<std::string> &progress_tag={});
}

#endif //DAEDALUS_TURBO_STORAGE_PARTITION_HPP