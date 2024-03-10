/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_STORAGE_CHUNK_INFO_HPP
#define DAEDALUS_TURBO_STORAGE_CHUNK_INFO_HPP

#include <string>
#include <dt/cardano/common.hpp>
#include <dt/format.hpp>

namespace daedalus_turbo::storage {
    struct chunk_info {
        std::string orig_rel_path {};
        size_t data_size = 0;
        size_t compressed_size = 0;
        size_t num_blocks = 0;
        cardano::slot first_slot {};
        cardano::slot last_slot {};
        cardano::block_hash data_hash {};
        cardano::block_hash prev_block_hash {};
        cardano::block_hash last_block_hash {};
        uint64_t offset = 0;

        static std::string rel_path_from_hash(const cardano::block_hash &data_hash)
        {
            return fmt::format("chunk/{}.zstd", data_hash.span());
        }

        std::string rel_path() const
        {
            return rel_path_from_hash(data_hash);
        }

        uint64_t end_offset() const
        {
            return offset + data_size;
        }

        uint64_t epoch() const
        {
            return first_slot.epoch();
        }

        static chunk_info from_json(const json::object &j)
        {
            chunk_info chunk {};
            chunk.orig_rel_path = json::value_to<std::string_view>(j.at("relPath"));
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

        json::object to_json() const
        {
            return json::object {
                { "relPath", orig_rel_path },
                { "size", data_size },
                { "compressedSize", compressed_size },
                { "numBlocks", num_blocks },
                { "firstSlot", (size_t)first_slot },
                { "lastSlot", (size_t)last_slot },
                { "hash", fmt::format("{}", data_hash.span()) },
                { "prevBlockHash", fmt::format("{}", prev_block_hash.span()) },
                { "lastBlockHash", fmt::format("{}", last_block_hash.span()) }
            };
        }
    };
}

#endif //DAEDALUS_TURBO_STORAGE_CHUNK_INFO_HPP