/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEXER_MERGER_HPP
#define DAEDALUS_TURBO_INDEXER_MERGER_HPP

#include <functional>
#include <map>
#include <string>
#include <zpp_bits.h>
#include <dt/error.hpp>
#include <dt/json.hpp>

namespace daedalus_turbo::indexer::merger {
    static constexpr uint64_t part_size = static_cast<uint64_t>(1) << 33;

    struct slice {
        using serialize = zpp::bits::members<3>;
        uint64_t offset = 0;
        uint64_t size = 0;
        std::string slice_id {};

        static slice from_json(const json::object &j)
        {
            auto prefix = static_cast<std::string_view>(j.at("prefix").as_string());
            return slice { json::value_to<uint64_t>(j.at("offset")), json::value_to<uint64_t>(j.at("size")), prefix };
        }

        slice()
        {
        }

        slice(uint64_t offset_, uint64_t size_, const std::string_view &prefix="slice")
            : offset { offset_ }, size { size_ }, slice_id { fmt::format("{}-{:013}-{:013}", prefix, offset, end_offset()) }
        {
        }

        json::object to_json() const
        {
            return json::object {
                { "offset", offset },
                { "size", size },
                { "prefix", slice_id.substr(0, slice_id.find('-')) }
            };
        }

        uint64_t end_offset() const
        {
            return offset + size;
        }

        bool operator<(const auto &b) const
        {
            return end_offset() < b.end_offset();
        }
    };

    struct tree: std::map<uint64_t, slice> {
        void add(const slice &s, bool allow_same=false)
        {
            auto [it, created] = try_emplace(s.offset, s);
            if (!created) {
                if (!allow_same && it->second.size != s.size)
                    throw error("internal error: a duplicate slice with offset {}!", it->first);
            }
        }

        uint64_t continuous_size() const
        {
            uint64_t size = 0;
            for (const auto &[offset, info]: *this) {
                if (offset == size)
                    size += info.size;
            }
            return size;
        }
    };
}

#endif // !DAEDALUS_TURBO_INDEXER_MERGER_HPP