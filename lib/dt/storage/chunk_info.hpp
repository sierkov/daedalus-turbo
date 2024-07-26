/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_STORAGE_CHUNK_INFO_HPP
#define DAEDALUS_TURBO_STORAGE_CHUNK_INFO_HPP

#include <string>
#include <boost/container/flat_set.hpp>
#include <dt/cardano/common.hpp>
#include <dt/format.hpp>

namespace daedalus_turbo::storage {
    struct block_info {
        cardano::block_hash hash {};
        uint64_t offset = 0;
        uint32_t size = 0;
        uint32_t slot = 0;
        uint32_t height = 0;
        uint32_t chk_sum = 0;
        uint16_t header_offset = 0;
        uint16_t header_size = 0;
        cardano::pool_hash pool_id {};
        uint8_t era = 0; // necessary to exclude boundary blocks (era=0) during density estimation, etc.

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.hash, self.offset, self.size, self.slot, self.height, self.chk_sum,
                self.header_offset, self.header_size, self.pool_id, self.era);
        }

        [[nodiscard]] uint64_t end_offset() const
        {
            return offset + size;
        }

        [[nodiscard]] cardano::point point() const
        {
            return { hash, slot, height, end_offset() };
        }
    };
    using block_list = std::vector<block_info>;

    struct chunk_info {
        size_t data_size = 0;
        size_t compressed_size = 0;
        size_t num_blocks = 0; // needed when chunk info is serialized without the blocks fields
        uint64_t first_slot = 0;
        uint64_t last_slot {};
        cardano::block_hash data_hash {};
        cardano::block_hash prev_block_hash {};
        cardano::block_hash last_block_hash {};
        uint64_t offset = 0;
        // fields that are not serialized to json:
        vector<block_info> blocks {};

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(
                self.data_size, self.compressed_size,
                self.num_blocks, self.first_slot, self.last_slot,
                self.data_hash, self.prev_block_hash, self.last_block_hash,
                self.offset, self.blocks
            );
        }

        static std::string rel_path_from_hash(const cardano::block_hash &data_hash)
        {
            return fmt::format("chunk/{}.zstd", data_hash.span());
        }

        [[nodiscard]] std::string rel_path() const
        {
            return rel_path_from_hash(data_hash);
        }

        [[nodiscard]] uint64_t era() const
        {
            if (!blocks.empty()) [[likely]] {
                const auto first_era = blocks.front().era;
                const auto last_era = blocks.back().era;
                if (first_era == last_era || (first_era == 0 && last_era == 1)) [[likely]]
                    return last_era;
                throw error("chunk {} has blocks from different eras {} and {}", rel_path(), first_era, last_era);
            }
            throw error("chunk cannot be empty!");
        }

        [[nodiscard]] const cardano::block_hash &first_block_hash() const
        {
            if (!blocks.empty()) [[likely]]
                return blocks.front().hash;
            throw error("chunk cannot be empty!");
        }

        [[nodiscard]] uint64_t block_data_size() const
        {
            uint64_t sz = 0;
            for (const auto &b: blocks)
                sz += b.size;
            return sz;
        }

        [[nodiscard]] uint64_t end_offset() const
        {
            return offset + data_size;
        }

        static chunk_info from_json(const json::object &j)
        {
            chunk_info chunk {};
            if (j.contains("offset"))
                chunk.offset = json::value_to<size_t>(j.at("offset"));
            chunk.data_size = json::value_to<size_t>(j.at("size"));
            chunk.compressed_size = json::value_to<size_t>(j.at("compressedSize"));
            chunk.num_blocks = json::value_to<size_t>(j.at("numBlocks"));
            chunk.first_slot = json::value_to<uint64_t>(j.at("firstSlot"));
            chunk.last_slot = json::value_to<uint64_t>(j.at("lastSlot"));
            chunk.data_hash = bytes_from_hex(json::value_to<std::string_view>(j.at("hash")));
            chunk.prev_block_hash = bytes_from_hex(json::value_to<std::string_view>(j.at("prevBlockHash")));
            chunk.last_block_hash = bytes_from_hex(json::value_to<std::string_view>(j.at("lastBlockHash")));
            return chunk;
        }

        [[nodiscard]] json::object to_json() const
        {
            return json::object {
                { "size", data_size },
                { "compressedSize", compressed_size },
                { "numBlocks", num_blocks },
                { "firstSlot", static_cast<uint64_t>(first_slot) },
                { "lastSlot", static_cast<uint64_t>(last_slot) },
                { "hash", fmt::format("{}", data_hash.span()) },
                { "prevBlockHash", fmt::format("{}", prev_block_hash.span()) },
                { "lastBlockHash", fmt::format("{}", last_block_hash.span()) }
            };
        }
    };
}

#endif //DAEDALUS_TURBO_STORAGE_CHUNK_INFO_HPP