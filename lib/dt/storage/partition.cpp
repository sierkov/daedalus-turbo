/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/storage/partition.hpp>

namespace daedalus_turbo::storage {
    vector<partition> partition_map::_chunk_partitions(const chunk_registry &cr, const size_t num_parts)
    {
        vector<partition> parts {};
        partition::storage_type chunks {};
        uint64_t part_size = 0;
        for (const auto &[chunk_last_byte, chunk]: cr.chunks()) {
            const auto part_edge = cr.num_bytes() * (parts.size() + 1) / num_parts;
            const auto potential_size = part_size + chunk.data_size;
            if (chunk_last_byte < part_edge) [[likely]] {
                chunks.emplace_back(&chunk);
                part_size = potential_size;
            } else {
                const auto excess = potential_size - part_edge;
                const auto lack = part_edge - part_size;
                if (chunks.empty() || lack > excess) {
                    chunks.emplace_back(&chunk);
                    parts.emplace_back(std::move(chunks));
                    chunks.clear();
                    part_size = 0;
                } else {
                    parts.emplace_back(std::move(chunks));
                    chunks.clear();
                    chunks.emplace_back(&chunk);
                    part_size = chunk.data_size;
                }
            }
        }
        if (!chunks.empty())
            parts.emplace_back(std::move(chunks));
        if (parts.size() > num_parts) [[unlikely]]
            throw error("invariant failed: the number of actual partitions: {} is greater than requested: {}", parts.size(), num_parts);
        return parts;
    }

    void parse_parallel(const chunk_registry &cr, const size_t num_parts,
        const std::function<void(cardano::block_base &blk, std::any &)> &on_block,
        const std::function<std::any(size_t)> &on_part_init,
        const std::function<void(size_t, std::any &&)> &on_part_done,
        const std::optional<std::string> &progress_tag)
    {
        std::optional<progress_guard> pg {};
        if (progress_tag)
            pg.emplace({ *progress_tag });
        const partition_map pm { cr, num_parts };
        const uint64_t total_size = cr.num_bytes();
        std::atomic_size_t parsed_size { 0 };
        auto &sched = cr.sched();
        for (size_t part_no = 0; part_no < pm.size(); ++part_no) {
            sched.submit_void("parse-chunk", -static_cast<int64_t>(part_no), [&, part_no] {
                const auto &part = pm.at(part_no);
                auto tmp = on_part_init(part_no);
                for (const auto *chunk: part) {
                    auto canon_path = cr.full_path(chunk->rel_path());
                    const auto data = file::read(canon_path);
                    cbor_parser block_parser { data };
                    cbor_value block_tuple {};
                    while (!block_parser.eof()) {
                        block_parser.read(block_tuple);
                        const auto blk = cardano::make_block(block_tuple, chunk->offset + block_tuple.data - data.data(), cr.config());
                        try {
                            on_block(*blk, tmp);
                        } catch (const std::exception &ex) {
                            throw error("failed to parse block at slot: {} hash: {}: {}", blk->slot(), blk->hash(), ex.what());
                        }
                    }
                }
                try {
                    on_part_done(part_no, std::move(tmp));
                } catch (const std::exception &ex) {
                    throw error("failed to complete partition [{}:{}]: {}", part.offset(), part.end_offset(), ex.what());
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
}