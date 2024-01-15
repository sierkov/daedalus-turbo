/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEXER_HPP
#define DAEDALUS_TURBO_INDEXER_HPP

#ifndef _WIN32
#   include <sys/resource.h>
#endif
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <execution>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <dt/cardano.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/file.hpp>
#include <dt/index/common.hpp>
#include <dt/index/merge.hpp>
#include <dt/index/block-meta.hpp>
#include <dt/index/pay-ref.hpp>
#include <dt/index/stake-ref.hpp>
#include <dt/index/tx.hpp>
#include <dt/index/txo-use.hpp>
#include <dt/indexer/merger.hpp>
#include <dt/logger.hpp>
#include <dt/progress.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo::indexer {
    inline std::vector<std::string> multi_reader_slices(const std::string &base_path, const std::string &idx_name)
    {
        std::vector<std::string> slices {};
        auto dir_path = std::filesystem::path { base_path } / idx_name;
        for (const auto &entry: std::filesystem::directory_iterator(dir_path)) {
            if (!entry.is_regular_file() || !entry.path().filename().string().starts_with("index-slice-") || entry.path().extension() != ".data")
                continue;
            auto slice_name = entry.path().filename().string();
            slices.emplace_back(slice_name.substr(6, slice_name.size() - 6 - 5));
        }
        std::sort(slices.begin(), slices.end());
        return slices;
    }

    inline std::vector<std::string> multi_reader_paths(const std::string &base_path, const std::string &idx_name)
    {
        std::vector<std::string> slices {};
        auto dir_path = std::filesystem::path { base_path } / idx_name;
        for (const auto &entry: std::filesystem::directory_iterator(dir_path)) {
            if (!entry.is_regular_file() || !entry.path().filename().string().starts_with("index-slice-") || entry.path().extension() != ".data")
                continue;
            auto slice_path = entry.path().string();
            slices.emplace_back(slice_path.substr(0, slice_path.size() - 5));
        }
        std::sort(slices.begin(), slices.end());
        return slices;
    }

    using chunk_indexer_list = std::vector<std::unique_ptr<index::chunk_indexer_base>>;
    constexpr int min_no_open_files = 2048;

    struct indexer_map: public std::map<std::string, std::unique_ptr<index::indexer_base>> {
        using std::map<std::string, std::unique_ptr<index::indexer_base>>::map;

        void emplace(std::unique_ptr<index::indexer_base> &&idxr)
        {
            try_emplace(idxr->name(), std::move(idxr));
        }
    };

    struct incremental: public chunk_registry {
        incremental(scheduler &sched, const std::string &db_dir, indexer_map &indexers)
            : chunk_registry { sched, db_dir }, _indexers { indexers }, _index_state_path { (_db_dir / "indexer-state.json").string() }
        {
#           ifdef _WIN32
                if (_setmaxstdio(min_no_open_files) < min_no_open_files)
                    throw error("can't increase the max number of open files to {}!", min_no_open_files);
#           else
                struct rlimit lim;
                if (getrlimit(RLIMIT_NOFILE, &lim) != 0)
                    throw error_sys("getrlimit failed");
                if (lim.rlim_cur < min_no_open_files || lim.rlim_max < min_no_open_files) {
                    lim.rlim_cur = min_no_open_files;
                    lim.rlim_max = min_no_open_files;
                    if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
                        throw error_sys("failed to increase the max number of open files to {}", min_no_open_files);
                }
#           endif
        }

        void clean_up() override
        {
            chunk_registry::clean_up();
            for (auto &[name, idxr_ptr]: _indexers)
                idxr_ptr->clean_up();
        }

        file_set load_state(bool strict=true) override
        {
            auto deletable_files = chunk_registry::load_state(strict);
            if (std::filesystem::exists(_index_state_path)) {
                auto json = file::read(_index_state_path);
                auto j_slices = json::parse(json.span().string_view()).as_array();
                uint64_t end_offset = 0;
                bool stop = false;
                for (auto &j: j_slices) {
                    auto slice = merger::slice::from_json(j.as_object());
                    for (auto &[name, idxr_ptr]: _indexers) {
                        if (!idxr_ptr->exists(slice.slice_id())) {
                            logger::warn("missing slice {} of index {} - truncating to the previous slice", slice.slice_id(), name);
                            stop = true;
                            break;
                        }
                    }
                    if (stop)
                        break;                    
                    if (slice.offset != end_offset) {
                        logger::warn("offset of slice {} is not continuous - truncating to the previous slice", slice.slice_id());
                        break;
                    }
                    _slices.add(std::move(slice));
                    end_offset = slice.offset + slice.size;
                }
                logger::info("indices have data up to offset {}", end_offset);
                for (auto &&path: truncate(end_offset, false))
                    deletable_files.emplace(std::move(path));
            }
            return deletable_files;
        }

        void import(const chunk_registry &src_cr)
        {
            uint8_vector raw_data {}, compressed_data {};
            for (const auto &[last_byte_offset, src_chunk]: src_cr.chunks()) {
                file::read_raw(src_cr.full_path(src_chunk.rel_path()), compressed_data);
                zstd::decompress(raw_data, compressed_data);
                auto dst_chunk = parse(src_chunk.offset, src_chunk.orig_rel_path, raw_data, compressed_data.size());
                file::write(full_path(dst_chunk.rel_path()), compressed_data);
                add(std::move(dst_chunk), false);
            }
            save_state();
        }

        chunk_info parse(uint64_t offset, const std::string &rel_path, const buffer &raw_data, size_t compressed_size) const override
        {
            return _parse_normal(offset, rel_path, raw_data, compressed_size, [](const auto &){});
        }

        file_set truncate(size_t max_end_offset, bool del=true) override
        {
            auto deleted_files = chunk_registry::truncate(max_end_offset, del);
            timer t { fmt::format("truncate indices to max offset {}", max_end_offset) };
            struct op {
                merger::slice before {};
                merger::slice after {};
            };
            std::vector<op> ops {};
            for (const auto &[offset, s]: _slices) {
                if (s.offset + s.size > max_end_offset) {
                    logger::debug("truncate index slice {}", s.slice_id());
                    if (s.offset < max_end_offset) {
                        merger::slice new_slice { s.offset, std::min(s.size, max_end_offset - s.offset) };
                        ops.emplace_back(s, new_slice);
                        for (auto &[name, idxr_ptr]: _indexers) {
                            _sched.submit("truncate-init-" + name, 25, [this, &idxr_ptr, s] {
                                idxr_ptr->truncate(s.slice_id(), num_bytes());
                                return true;
                            });
                        }
                    } else {
                        for (auto &[name, idxr_ptr]: _indexers) {
                            index::writer<int>::remove(idxr_ptr->reader_path(s.slice_id()));
                        }
                    }
                } else {
                    logger::debug("truncate indices: skipping slice {} - all offsets are smaller", s.slice_id());
                }
            }
            _sched.process(true);
            for (auto &&[before, after]: ops) {
                for (auto &[name, idxr_ptr]: _indexers)
                    index::writer<int>::rename(idxr_ptr->reader_path(before.slice_id()), idxr_ptr->reader_path(after.slice_id()));
                _slices.del(before.offset);
                _slices.add(std::move(after));
            }                                   
            return deleted_files;
        }

        void save_state() override
        {
            timer t { "indexer::save_state" };
            chunk_registry::save_state();
            if (!_updated_chunks.empty() || !_slices.empty()) {
                for (size_t ci = 1; ; ci++) {
                    size_t num_tasks = 0;
                    {
                        std::unique_lock lk { _updates_mutex };
                        num_tasks = _schedule_premerge(std::move(lk));
                    }
                    if (num_tasks > 0) {
                        _sched.process(true);
                        logger::info("combine indices iteration {} - launched {} combine tasks", ci, num_tasks);
                    } else
                        break;
                }
            }
            std::ostringstream json_s {};
            json_s << "[\n";
            for (const auto &[offset, slice]: _slices) {
                json_s << "  " << json::serialize(slice.to_json());
                if (slice.offset + slice.size < _slices.offset_end())
                    json_s << ',';
                json_s << '\n';
            }
            json_s << "]\n";
            file::write(_index_state_path, json_s.str());
        }

        void set_progress(const std::string &id, progress::info &info_ref) override
        {
            _progress.emplace(id, info_ref);
        }
    protected:
        using updated_chunks_map = std::map<uint64_t, chunk_registry::chunk_info>;
        struct progress_info {
            std::string id {};
            std::reference_wrapper<progress::info> info;
        };

        indexer_map &_indexers;
        const std::string _index_state_path;
        alignas(mutex::padding) mutable std::mutex _updates_mutex {};
        mutable updated_chunks_map _updated_chunks {};
        mutable size_t _updated_chunks_size = 0;
        alignas(mutex::padding) mutable std::mutex _slices_mutex {};
        mutable merger::tree _slices {};
        std::optional<progress_info> _progress {};

        size_t _schedule_premerge(std::unique_lock<auto> &&updates_lk, bool skippable=false) const
        {
            if (skippable && _sched.task_count() >= _sched.num_workers())
                return 0;
            size_t scheduled_tasks = 0;
            uint64_t end_offset = 0;
            std::vector<merger::proposal> proposals {};
            {
                std::scoped_lock lk { _slices_mutex };
                logger::debug("index::schedule_premerge with {} chunks and {} bytes slices: {}", _updated_chunks.size(), _updated_chunks_size, _slices.size());
                // first, insert the recently parsed chunks
                for (auto &[offset, chunk]: _updated_chunks) {
                    auto slice_it = _slices.add(merger::slice { offset, chunk.data_size });
                    slice_it->second._slice_id.emplace(fmt::format("update-{}", offset));
                }
                _updated_chunks.clear();
                _updated_chunks_size = 0;
                updates_lk.unlock();
                if (_slices.empty())
                    throw error("internal error: slice list cannot be empty!");
                // next, analyze the existing slices and schedule necessary merge operations
                // save proposals since processing updates _slices which influences iteration within find_mergeable
                _slices.find_mergeable([&](auto &&prop) {
                    proposals.emplace_back(std::move(prop));
                });
                end_offset = _slices.offset_end();
            }
            
            std::set<std::string> merged_indices {};
            for (const auto &[idxr_name, idxr_ptr]: _indexers) {
                    if (idxr_ptr->mergeable())
                        merged_indices.emplace(idxr_name);
            }
            for (auto &&[new_slice, input_offsets]: proposals) {
                logger::debug("indexer::premerge slice {} from {}", new_slice.slice_id(), input_offsets);
                std::vector<std::string> input_slices {};
                merger::slice slice_copy {};
                {
                    std::scoped_lock lk { _slices_mutex };
                    for (uint64_t offset: input_offsets) {
                        input_slices.emplace_back(_slices.at(offset).slice_id());
                        _slices.del(offset);
                    }
                    new_slice.indices_awaited = merged_indices;
                    auto slice_iter = _slices.add(std::move(new_slice));
                    // creating a copy since concurrent deletions from _slices can corrupt the iterator
                    slice_copy = slice_iter->second;
                }
                
                for (const auto &[idxr_name, idxr_ptr]: _indexers) {
                    if (!idxr_ptr->mergeable())
                        continue;
                    std::vector<std::string> input_paths {};
                    for (const auto &slice_id: input_slices) {
                        if (idxr_ptr->disk_size(slice_id) > 0)
                            input_paths.emplace_back(idxr_ptr->reader_path(slice_id));
                    }
                    auto output_path = idxr_ptr->reader_path(slice_copy.slice_id());
                    size_t priority = (end_offset - slice_copy.offset) * 100 / end_offset;
                    logger::debug("scheduling merge task with prio {} output: {} inputs: {}", priority, output_path, input_paths);
                    auto scheduled = std::make_shared<std::atomic_bool>(false);
                    auto slice_offset = slice_copy.offset;
                    _sched.on_result(output_path, [this, slice_offset, output_path, idxr_name, scheduled] (const auto &res) {
                        if (res.type() == typeid(scheduled_task_error))
                            return;
                        if (!*scheduled || _sched.task_count(output_path) > 0)
                            return;
                        {
                            std::scoped_lock lk { _slices_mutex };
                            auto &slice = _slices.at(slice_offset);
                            slice.indices_awaited.erase(idxr_name);
                            logger::debug("merge task ready: {} offset: {} size: {} awaited_indices: {}",
                                output_path, slice.offset, slice.size, slice.indices_awaited);
                            if (slice.indices_awaited.empty()) {
                                logger::debug("merged slice: {} total slices: {}", slice.slice_id(), _slices.size());
                                if (_progress) {
                                    _progress->info.get().completed = _slices.continuous_size();
                                    logger::debug("merge progress completed: {}", _progress->info.get().completed);
                                    progress::get().update(_progress->id, fmt::format("{:0.3f}%", static_cast<double>(_progress->info.get().completed) * 100 / _progress->info.get().total));
                                }
                            }
                        }
                        _sched.clear_observers(output_path);
                    });
                    scheduled_tasks++;
                    _sched.submit("schedule-" + output_path, priority, [&idxr_ptr, output_path, priority, input_paths, scheduled] {
                        idxr_ptr->merge(output_path, priority, input_paths, output_path);
                        *scheduled = true;
                        return output_path;
                    });
                }
            }
            return scheduled_tasks;
        }

        chunk_info _parse_normal(uint64_t offset, const std::string &rel_path,
            const buffer &raw_data, size_t compressed_size, const block_processor &extra_proc) const
        {
            chunk_info info {};
            {
                chunk_indexer_list chunk_indexers {};
                for (auto &[name, idxr_ptr]: _indexers)
                    chunk_indexers.emplace_back(idxr_ptr->make_chunk_indexer("update", offset));
                info = chunk_registry::_parse_normal(offset, rel_path, raw_data, compressed_size, [&chunk_indexers, &extra_proc](const auto &blk) {
                    for (auto &idxr: chunk_indexers)
                        idxr->index(blk);
                    extra_proc(blk);
                });
            }
            // ensure that chunk_indexers are properly destroyed by this point.
            {
                std::unique_lock lk { _updates_mutex };
                auto [it, created] = _updated_chunks.try_emplace(offset, info);
                if (!created)
                    throw error("duplicate chunk starting at offset {} detected!", offset);
                _updated_chunks_size += info.data_size;
                logger::debug("parsed: {}, parsed chunks: {}", info.orig_rel_path, _updated_chunks.size());
                if (_updated_chunks_size >= static_cast<size_t>(1) << 30)
                    _schedule_premerge(std::move(lk), true);
            }
            return info;
        }
    };

    inline indexer_map default_list(scheduler &sched, const std::string &idx_dir)
    {
        indexer::indexer_map indexers {};
        indexers.emplace(std::make_unique<index::block_meta::indexer>(sched, idx_dir, "block-meta"));
        indexers.emplace(std::make_unique<index::stake_ref::indexer>(sched, idx_dir, "stake-ref"));
        indexers.emplace(std::make_unique<index::pay_ref::indexer>(sched, idx_dir, "pay-ref"));
        indexers.emplace(std::make_unique<index::tx::indexer>(sched, idx_dir, "tx"));
        indexers.emplace(std::make_unique<index::txo_use::indexer>(sched, idx_dir, "txo-use"));
        return indexers;
    }
}

#endif // !DAEDALUS_TURBO_INDEXER_HPP