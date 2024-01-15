/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEXER_MERGER_HPP
#define DAEDALUS_TURBO_INDEXER_MERGER_HPP

#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <dt/error.hpp>
#include <dt/index/common.hpp>
#include <dt/json.hpp>

namespace daedalus_turbo::indexer::merger {
    struct slice {
        static constexpr uint64_t slice_size = static_cast<uint64_t>(1) << 34;
        uint64_t offset = 0;
        uint64_t size = 0;
        std::set<std::string> indices_awaited {};
        mutable std::optional<uint64_t> _part_id {};
        mutable std::optional<std::string> _slice_id {};

        static slice from_json(const json::object &j)
        {
            return slice { json::value_to<uint64_t>(j.at("offset")), json::value_to<uint64_t>(j.at("size")) };
        }

        slice() =default;
        slice(const slice &) =default;
        slice(slice &&) =default;

        slice(uint64_t offset_, uint64_t size_): offset { offset_ }, size { size_ }
        {
        }

        slice(const std::string &slice_id): _slice_id { slice_id }
        {
            if (!slice_id.starts_with("slice-"))
                throw error("invalid format of slice_id: {}", slice_id);
            size_t sep1 = slice_id.find('-');
            if (sep1 == slice_id.npos)
                throw error("invalid format of slice_id: '{}'", slice_id);
            size_t sep2 = slice_id.find('-', sep1 + 1);
            if (sep2 == slice_id.npos)
                throw error("invalid format of slice_id: '{}'", slice_id);
            offset = std::stoull(slice_id.substr(sep1 + 1, sep2 - (sep1 + 1)));
            uint64_t end_offset = std::stoull(slice_id.substr(sep2 + 1));
            if (end_offset <= offset)
                throw error("the end offset of the slice_id is too small: '{}'", slice_id);
            size = end_offset - offset;
        }

        slice &operator=(const slice &) =default;
        slice &operator=(slice &&) =default;

        bool combinable_with(const slice &b) const
        {
            if (!indices_awaited.empty() || !b.indices_awaited.empty())
                return false;
            if (offset + size != b.offset)
                return false;
            return part_id() == b.part_id();
        }

        uint64_t part_id() const
        {
            if (!_part_id)
                _part_id.emplace(offset / slice_size);
            return *_part_id;
        }

        const std::string &slice_id() const
        {
            if (!_slice_id)
                _slice_id.emplace(_default_slice_id());
            return *_slice_id;
        }

        json::object to_json() const
        {
            if (slice_id() != _default_slice_id())
                throw error("can't create json for a slice with non-default slice_id: {}", slice_id());
            if (!indices_awaited.empty())
                throw error("can't create json for a slice with awaited indices: {}: {}", slice_id(), indices_awaited);
            return json::object {
                { "offset", offset },
                { "size", size }
            };
        }
    private:
        std::string _default_slice_id() const
        {
            return fmt::format("slice-{:013}-{:013}", offset, offset + size);
        }
    };

    struct proposal {
        merger::slice new_slice {};
        std::vector<uint64_t> input_slices {};
    };

    struct tree: std::map<uint64_t, slice> {
        std::map<uint64_t, slice>::iterator add(slice &&s, bool allow_same=false)
        {
            auto [it, created] = try_emplace(s.offset, std::move(s));
            if (!created) {
                if (!allow_same && it->second.size != s.size)
                    throw error("internal error: a duplicate slice with offset {}!", it->first);
            }
            auto slice_end = it->second.offset + it->second.size;
            if (_offset_end < slice_end)
                _offset_end = slice_end;
            return it;
        }

        void del(uint64_t offset)
        {
            auto it = find(offset);
            if (it != end()) {
                if (it->second.offset + it->second.size == _offset_end) {
                    if (it != begin()) {
                        auto prev_it = it;
                        prev_it--;
                        _offset_end = prev_it->second.offset + prev_it->second.size;
                    } else {
                        _offset_end = 0;
                    }
                }
                erase(it);
            }
        }

        uint64_t offset_end() const
        {
            return _offset_end;
        }

        uint64_t continuous_size() const
        {
            uint64_t size = 0;
            for (const auto &[offset, info]: *this) {
                if (info.indices_awaited.empty() && info.offset == size)
                    size = info.offset + info.size;
                else
                    break;
            }
            return size;
        }

        void find_mergeable(const std::function<void(proposal &&)> &observer)
        {
            proposal p {};
            for (auto next_it = begin(), prev_it = next_it++; next_it != end(); prev_it = next_it++) {
                if (prev_it->second.combinable_with(next_it->second)) {
                    if (p.input_slices.empty()) {
                        p.input_slices.emplace_back(prev_it->first);
                        p.new_slice = prev_it->second;
                        p.new_slice._part_id.reset();
                        p.new_slice._slice_id.reset();
                    }
                    p.input_slices.emplace_back(next_it->first);
                    p.new_slice.size += next_it->second.size;
                    if (p.input_slices.size() == index::two_step_merge_num_files) {
                        observer(std::move(p));
                        p.input_slices.clear();
                        prev_it = next_it++;
                    }
                } else if (!p.input_slices.empty()) {
                    observer(std::move(p));
                    p.input_slices.clear();
                }
            }
            if (!p.input_slices.empty())
                observer(std::move(p));
        }

    private:
        uint64_t _offset_end = 0;
    };
}

#endif // !DAEDALUS_TURBO_INDEXER_MERGER_HPP