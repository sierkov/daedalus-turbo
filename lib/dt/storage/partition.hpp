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

        partition(const partition &o): _chunks { o._chunks }
        {
        }

        partition(partition &&o): _chunks { std::move(o._chunks) }
        {
        }

        partition(storage_type &&chunks): _chunks { std::move(chunks) }
        {
            if (_chunks.empty()) [[unlikely]]
                throw error("a partition must contain at least one chunk!");
        }

        uint64_t first_slot() const
        {
            return _chunks.front()->first_slot;
        }

        uint64_t last_slot() const
        {
            return _chunks.back()->last_slot;
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
        using storage_type = vector<partition>;
        using const_iterator = storage_type::const_iterator;

        explicit partition_map(const chunk_registry &cr, const size_t num_parts=256):
            partition_map { _chunk_partitions(cr, num_parts) }
        {
        }

        partition_map(const const_iterator begin, const const_iterator end):
            partition_map { storage_type { begin, end } }
        {
        }

        const_iterator begin() const
        {
            return _parts.begin();
        }

        const_iterator end() const
        {
            return _parts.end();
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
    protected:
        partition_map(vector<partition> &&parts): _parts { std::move(parts) }
        {
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
            throw error(fmt::format("an offset that belongs to no partition: {}", offset));
        }
    };

    struct epoch_partition_map: partition_map {
        explicit epoch_partition_map(const chunk_registry &cr): partition_map { _make_partitions(cr) }
        {
        }
    private:
        const vector<partition> _parts;

        static vector<partition> _make_partitions(const chunk_registry &cr);
    };

    struct chunk_partition_map: partition_map {
        explicit chunk_partition_map(const chunk_registry &cr): partition_map { _make_partitions(cr) }
        {
        }
    private:
        const vector<partition> _parts;

        static vector<partition> _make_partitions(const chunk_registry &cr);
    };

    struct part_info {
        size_t idx = 0;
        uint64_t offset = 0;
        uint64_t size = 0;
    };

    template<typename T>
    void parse_parallel(const chunk_registry &cr, const partition_map &pm,
        const std::function<void(T&, const cardano::block_base &blk)> &on_block,
        const std::function<T(size_t, const partition &)> &on_part_init,
        const std::function<void(T &&, size_t, const partition &)> &on_part_done,
        const std::optional<std::string> &progress_tag={})
    {
        std::optional<progress_guard> pg {};
        if (progress_tag)
            pg.emplace({ *progress_tag });
        const uint64_t total_size = cr.num_bytes();
        std::atomic_size_t parsed_size { 0 };
        auto &sched = cr.sched();
        for (size_t part_no = 0; part_no < pm.size(); ++part_no) {
            sched.submit_void("parse-chunk", -static_cast<int64_t>(part_no), [&, part_no] {
                const auto &part = pm.at(part_no);
                auto tmp = on_part_init(part_no, part);
                for (const auto *chunk: part) {
                    auto canon_path = cr.full_path(chunk->rel_path());
                    const auto data = file::read(canon_path);
                    cbor_parser block_parser { data };
                    cbor_value block_tuple {};
                    while (!block_parser.eof()) {
                        block_parser.read(block_tuple);
                        const auto blk = cardano::make_block(block_tuple, chunk->offset + block_tuple.data - data.data(), cr.config());
                        try {
                            on_block(tmp, *blk);
                        } catch (const std::exception &ex) {
                            throw error(fmt::format("failed to parse block at slot: {} hash: {}: {}", blk->slot(), blk->hash(), ex.what()));
                        }
                    }
                }
                try {
                    on_part_done(std::move(tmp), part_no, part);
                } catch (const std::exception &ex) {
                    throw error(fmt::format("failed to complete partition [{}:{}]: {}", part.offset(), part.end_offset(), ex.what()));
                }
                if (progress_tag) {
                    const auto done = parsed_size.fetch_add(part.size(), std::memory_order::relaxed) + part.size();
                    auto &p = progress::get();
                    p.update(*progress_tag, done, total_size);
                    p.inform();
                }
            });
        }
        sched.process();
    }

    template<typename T>
    void parse_parallel(const chunk_registry &cr, size_t num_parts,
        const std::function<void(T&, const cardano::block_base &blk)> &on_block,
        const std::function<T(size_t, const partition &)> &on_part_init,
        const std::function<void(T &&, size_t, const partition &)> &on_part_done,
        const std::optional<std::string> &progress_tag={})
    {
        const partition_map pm { cr, num_parts };
        parse_parallel(cr, pm, on_block, on_part_init, on_part_done, progress_tag);
    }

    template<typename T>
    void parse_parallel_chunk(const chunk_registry &cr,
        const std::function<void(T&, const cardano::block_base &blk)> &on_block,
        const std::function<T(size_t, const partition &)> &on_part_init,
        const std::function<void(T &&, size_t, const partition &)> &on_part_done,
        const std::optional<std::string> &progress_tag={})
    {
        const chunk_partition_map pm { cr };
        parse_parallel(cr, pm, on_block, on_part_init, on_part_done, progress_tag);
    }

    template<typename T>
    void parse_parallel_epoch(const chunk_registry &cr,
        const std::function<void(T&, const cardano::block_base &blk)> &on_block,
        const std::function<T(size_t, const partition &)> &on_part_init,
        const std::function<void(T &&, size_t, const partition &)> &on_part_done,
        const std::optional<std::string> &progress_tag={})
    {
        const epoch_partition_map pm { cr };
        parse_parallel(cr, pm, on_block, on_part_init, on_part_done, progress_tag);
    }
}

#endif //DAEDALUS_TURBO_STORAGE_PARTITION_HPP