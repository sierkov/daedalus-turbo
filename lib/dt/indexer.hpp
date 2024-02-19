/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEXER_HPP
#define DAEDALUS_TURBO_INDEXER_HPP

#ifndef _WIN32
#   include <sys/resource.h>
#endif
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>
#include <dt/atomic.hpp>
#include <dt/cardano.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/file.hpp>
#include <dt/index/common.hpp>
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
    using slice_list = std::vector<merger::slice>;

    struct indexer_map: public std::map<std::string, std::unique_ptr<index::indexer_base>> {
        using std::map<std::string, std::unique_ptr<index::indexer_base>>::map;

        void emplace(std::unique_ptr<index::indexer_base> &&idxr)
        {
            try_emplace(idxr->name(), std::move(idxr));
        }
    };

    struct incremental: public chunk_registry {
        static std::string storage_dir(const std::string &data_dir)
        {
            return chunk_registry::init_db_dir(data_dir + "/index");
        }

        incremental(scheduler &sched, const std::string &data_dir, indexer_map &indexers)
            : chunk_registry { sched, data_dir }, _indexers { indexers },
                _idx_dir { storage_dir(data_dir) },
                _index_state_path { (_idx_dir / "state.json").string() }
        {
#           ifdef _WIN32
                if (_setmaxstdio(min_no_open_files) < min_no_open_files)
                    throw error("can't increase the max number of open files to {}!", min_no_open_files);
#           else
                struct rlimit lim;
                if (getrlimit(RLIMIT_NOFILE, &lim) != 0)
                    throw error_sys("getrlimit failed");
                logger::trace("before RLIMIT_NOFILE to cur: {} max: {}", lim.rlim_cur, lim.rlim_max);
                if (lim.rlim_cur < min_no_open_files || lim.rlim_max < min_no_open_files) {
                    lim.rlim_cur = min_no_open_files;
                    lim.rlim_max = min_no_open_files;
                    logger::trace("setting RLIMIT_NOFILE to cur: {} max: {}", lim.rlim_cur, lim.rlim_max);
                    if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
                        throw error_sys("failed to increase the max number of open files to {}", min_no_open_files);
                    if (getrlimit(RLIMIT_NOFILE, &lim) != 0)
                        throw error_sys("getrlimit failed");
                    logger::trace("after RLIMIT_NOFILE to cur: {} max: {}", lim.rlim_cur, lim.rlim_max);
                }
#           endif
            _update_mergeable();
        }

        void clean_up() override
        {
            chunk_registry::clean_up();
            for (auto &[name, idxr_ptr]: _indexers)
                idxr_ptr->clean_up();
        }

        void import(const chunk_registry &src_cr)
        {
            uint8_vector raw_data {}, compressed_data {};
            target_offset(src_cr.num_bytes());
            for (const auto &[last_byte_offset, src_chunk]: src_cr.chunks()) {
                file::read_raw(src_cr.full_path(src_chunk.rel_path()), compressed_data);
                zstd::decompress(raw_data, compressed_data);
                auto dst_chunk = parse(src_chunk.offset, src_chunk.orig_rel_path, raw_data, compressed_data.size());
                file::write(full_path(dst_chunk.rel_path()), compressed_data);
                add(std::move(dst_chunk), false);
            }
            save_state();
        }

        slice_list slices(std::optional<uint64_t> end_offset={}) const
        {
            slice_list copy {};
            std::scoped_lock lk { _slices_mutex };
            copy.reserve(_slices.size());
            for (const auto &[offset, s]: _slices) {
                if (!end_offset || *end_offset >= s.end_offset())
                    copy.emplace_back(s);
            }
            return copy;
        }

        file_set truncate(size_t max_end_offset, bool del=true) override
        {
            auto deleted_files = chunk_registry::truncate(max_end_offset, del);
            timer t { fmt::format("truncate indices to max offset {}", max_end_offset) };
            std::vector<merger::slice> updated {};
            for (auto it = _slices.begin(); it != _slices.end(); ) {
                const auto &s = it->second;
                if (s.end_offset() <= max_end_offset) {
                    ++it;
                } else { // s.end_offset() > max_end_offset
                    logger::trace("truncate index slice {}", s.slice_id);
                    if (s.offset >= max_end_offset) {
                        if (del) {
                            for (auto &[name, idxr_ptr]: _indexers)
                                index::writer<int>::remove(idxr_ptr->reader_path(s.slice_id));
                        }
                    } else {
                        merger::slice new_slice { s.offset, std::min(s.size, max_end_offset - s.offset) };
                        updated.emplace_back(new_slice);
                        for (auto &[name, idxr_ptr]: _indexers) {
                            _sched.submit_void("truncate-init-" + name, 25, [&idxr_ptr, s, new_slice, max_end_offset] {
                                idxr_ptr->schedule_truncate(s.slice_id, max_end_offset, [&idxr_ptr, s, new_slice] {
                                    index::writer<int>::rename(idxr_ptr->reader_path(s.slice_id), idxr_ptr->reader_path(new_slice.slice_id));
                                });
                            });
                        }
                    }
                    it = _slices.erase(it);
                }
            }
            _sched.process(true);
            for (auto &&new_slice: updated) {
                _slices.add(new_slice);
            }
            return deleted_files;
        }

        void save_state() override
        {
            timer t { "indexer::save_state" };
            chunk_registry::save_state();
            // ensure that all scheduled tasks have completed by now
            _sched.process(true);
            // merge final not-yet merged epochs
            {
                std::unique_lock lk { _epoch_slices_mutex };
                _schedule_final_merge(std::move(lk), true);
            }
            _sched.process(true);
            std::ostringstream json_s {};
            json_s << "[\n";
            if (!_slices.empty()) {
                auto end_offset = _slices.rbegin()->second.end_offset();
                for (const auto &[offset, slice]: _slices) {
                    json_s << "  " << json::serialize(slice.to_json());
                    if (slice.offset + slice.size < end_offset)
                        json_s << ',';
                    json_s << '\n';
                }
            }
            json_s << "]\n";
            file::write(_index_state_path, json_s.str());
            _epoch_merged = 0;
            _final_merged = 0;
        }
    protected:
        indexer_map &_indexers;
        const std::filesystem::path _idx_dir;
        const std::string _index_state_path;
        std::set<std::string> _mergeable {};
        alignas(mutex::padding) mutable std::mutex _slices_mutex {};
        merger::tree _slices {};
        std::atomic_uint64_t _epoch_merged = 0;
        std::atomic_uint64_t _final_merged = 0;
        uint64_t _merge_next_offset = 0;
        uint64_t _merge_start_offset = 0;
        alignas(mutex::padding) mutable std::mutex _epoch_slices_mutex {};
        std::map<uint64_t, merger::slice> _epoch_slices {};

        std::pair<uint64_t, file_set> _load_state(bool strict=true) override
        {
            auto [cr_truncate_offset, deletable_files] = chunk_registry::_load_state(strict);
            uint64_t end_offset = 0;
            if (std::filesystem::exists(_index_state_path)) {
                auto j_slices = json::load(_index_state_path).as_array();    
                bool stop = false;
                for (auto &j: j_slices) {
                    auto slice = merger::slice::from_json(j.as_object());
                    for (auto &[name, idxr_ptr]: _indexers) {
                        if (idxr_ptr->mergeable() && !idxr_ptr->exists(slice.slice_id)) {
                            logger::warn("missing slice {} of index {} - truncating to the previous slice", slice.slice_id, name);
                            stop = true;
                            break;
                        }
                    }
                    if (stop)
                        break;             
                    if (slice.offset != end_offset) {
                        logger::warn("offset of slice {} is not continuous - truncating to the previous slice", slice.slice_id);
                        break;
                    }
                    _slices.add(std::move(slice));
                    end_offset = slice.offset + slice.size;
                }
                
            }
            logger::info("indices have data up to offset {}", end_offset);
            _merge_next_offset = _merge_start_offset = end_offset;
            return std::make_pair(std::min(cr_truncate_offset, end_offset), deletable_files);
        }

        void _update_mergeable()
        {
            _mergeable.clear();
            if (!_indexers.empty()) {
                for (const auto &[idxr_name, idxr_ptr]: _indexers) {
                    if (idxr_ptr && idxr_ptr->mergeable())
                        _mergeable.emplace(idxr_name);
                }
            }
        }

        virtual void _on_slice_ready(uint64_t first_epoch, uint64_t last_epoch, const merger::slice &slice)
        {
            logger::info("on_slice_ready first_epoch: {} last_epoch: {} start_offset: {} end_offset: {}",
                first_epoch, last_epoch, slice.offset, slice.end_offset());
        }

        void _on_epoch_merge(uint64_t epoch, const epoch_info &info) override
        {
            chunk_registry::_on_epoch_merge(epoch, info);
            std::vector<std::string> input_slices {};
            for (const auto &chunk_ptr: info.chunk_ids) {
                input_slices.emplace_back(fmt::format("update-{}", chunk_ptr->offset));
            }
            merger::slice output_slice { info.start_offset, info.end_offset - info.start_offset, fmt::format("epoch-{}", epoch) };
            _merge_slice(output_slice, input_slices, 100, [this, epoch, output_slice] {
                std::unique_lock lk { _epoch_slices_mutex };
                _epoch_slices.emplace(epoch, std::move(output_slice));
                auto new_epoch_merged = atomic_add(_epoch_merged, output_slice.size);
                if (_target_offset) {
                    progress::get().update("merge", new_epoch_merged + _final_merged, (*_target_offset - _merge_start_offset) * 2);
                }
                _schedule_final_merge(std::move(lk));
            });
        }

        void _merge_slice(const merger::slice &output_slice, const std::vector<std::string> &input_slices, size_t prio_base, const std::function<void()> &on_merge)
        {
            auto indices_awaited = std::make_shared<std::set<std::string>>(_mergeable);
            for (const auto &idxr_name: _mergeable) {
                auto idxr_ptr = _indexers.at(idxr_name).get();
                std::vector<std::string> input_paths {};
                for (const auto &slice_id: input_slices) {
                    if (idxr_ptr->disk_size(slice_id) > 0)
                        input_paths.emplace_back(idxr_ptr->reader_path(slice_id));
                }
                auto output_path = idxr_ptr->reader_path(output_slice.slice_id);
                auto end_offset = _target_offset ? *_target_offset : _end_offset;
                if (end_offset < output_slice.offset)
                    end_offset = output_slice.offset;
                size_t priority = prio_base + (end_offset - output_slice.offset) * 50 / end_offset; // [prio_base;prio_base+50) range
                auto done_parts = std::make_shared<std::atomic_size_t>(0);
                auto todo_parts = std::make_shared<std::atomic_size_t>(idxr_ptr->merge_task_count(input_paths));
                _sched.on_result(output_path, [this, priority, todo_parts, done_parts, output_slice, indices_awaited, output_path, idxr_name, on_merge] (const auto &res) {
                    if (res.type() == typeid(scheduled_task_error))
                        return;
                    if (++*done_parts >= *todo_parts) {
                        indices_awaited->erase(idxr_name);
                        if (indices_awaited->empty()) {
                            _sched.submit_void("ready-" + output_path, priority, on_merge);
                            _sched.clear_observers(output_path);
                        }
                    }
                });
                _sched.submit_void("schedule-" + output_path, priority, [idxr_ptr, output_path, priority, input_paths, todo_parts] {
                    // merge tasks must have a higher priority + 50 so that the actual merge tasks free up file handles
                    // and other tied resources quicker than they are consumed
                    idxr_ptr->merge(output_path, priority + 50, input_paths, output_path);
                });
            }
        }
        
        void _schedule_final_merge(std::unique_lock<std::mutex> &&epoch_slices_lk, bool force=false)
        {
            while (!_epoch_slices.empty()) {
                uint64_t total_size = 0;
                for (const auto &[epoch, slice]: _epoch_slices) {
                    if (slice.offset == _merge_next_offset + total_size) {
                        total_size += slice.size;
                    } else {
                        break;
                    }
                }
                if (total_size == 0)
                    break;
                if (total_size < merger::part_size && !force && (!_target_offset || *_target_offset > _merge_next_offset + total_size))
                    break;
                auto first_epoch = _epoch_slices.begin()->first;
                auto last_epoch = first_epoch;
                std::vector<std::string> input_slices {};
                while (!_epoch_slices.empty() && _epoch_slices.begin()->second.offset < _merge_next_offset + total_size) {
                    input_slices.emplace_back(_epoch_slices.begin()->second.slice_id);
                    last_epoch = _epoch_slices.begin()->first;
                    _epoch_slices.erase(_epoch_slices.begin());
                }   
                merger::slice output_slice { _merge_next_offset, total_size };
                _merge_next_offset += total_size;
                epoch_slices_lk.unlock();
                _merge_slice(output_slice, input_slices, 200, [this, output_slice, first_epoch, last_epoch] {
                    {
                        std::scoped_lock lk { _slices_mutex };
                        _slices.add(std::move(output_slice));
                        _final_merged = _slices.continuous_size();
                    }
                    if (_target_offset) {
                        progress::get().update("merge", _epoch_merged + _final_merged, (*_target_offset - _merge_start_offset) * 2);
                    }
                    _on_slice_ready(first_epoch, last_epoch, output_slice);
                });
                epoch_slices_lk.lock();
            }
        }

        chunk_info _parse_normal(uint64_t offset, const std::string &rel_path,
            const buffer &raw_data, size_t compressed_size, const block_processor &extra_proc) const override
        {
            chunk_indexer_list chunk_indexers {};
            for (auto &[name, idxr_ptr]: _indexers)
                chunk_indexers.emplace_back(idxr_ptr->make_chunk_indexer("update", offset));
            return chunk_registry::_parse_normal(offset, rel_path, raw_data, compressed_size, [&chunk_indexers, &extra_proc](const auto &blk) {
                for (auto &idxr: chunk_indexers)
                    idxr->index(blk);
                extra_proc(blk);
            });
        }
    };

    inline indexer_map default_list(scheduler &sched, const std::string &data_dir)
    {
        const auto idx_dir = incremental::storage_dir(data_dir);
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