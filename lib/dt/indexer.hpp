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
#include <mutex>
#include <string>
#include <vector>
#include <dt/atomic.hpp>
#include <dt/cardano.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/index/common.hpp>
#include <dt/index/block-meta.hpp>
#include <dt/index/pay-ref.hpp>
#include <dt/index/stake-ref.hpp>
#include <dt/index/txo.hpp>
#include <dt/index/txo-use.hpp>
#include <dt/indexer/merger.hpp>
#include <dt/logger.hpp>
#include <dt/progress.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo::indexer {
    using chunk_indexer_list = std::vector<std::shared_ptr<index::chunk_indexer_base>>;
    constexpr int min_no_open_files = 2048;
    using slice_list = std::vector<merger::slice>;
    using slice_path_list = std::vector<std::string>;

    inline slice_path_list multi_reader_paths(const std::string &idx_dir, const std::string &name, const slice_list &slices)
    {
        slice_path_list paths {};
        for (const auto &slice: slices)
            paths.emplace_back(index::indexer_base::reader_path(idx_dir, name, slice.slice_id));
        logger::trace("multi_reader_paths paths for index {}: {}", name, paths);
        return paths;
    }

    struct indexer_map: std::map<std::string, std::shared_ptr<index::indexer_base>> {
        using std::map<std::string, std::shared_ptr<index::indexer_base>>::map;

        void emplace(std::shared_ptr<index::indexer_base> &&idxr) {
            auto [ it, created ] = try_emplace(idxr->name(), std::move(idxr));
            if (!created)
                throw error("duplicate index: {}", it->first);
        }
    };

    struct incremental: chunk_registry {
        static std::string storage_dir(const std::string &data_dir)
        {
            return chunk_registry::init_db_dir(data_dir + "/index").string();
        }

        incremental(indexer_map &&indexers, const std::string &data_dir, bool strict=true, scheduler &sched=scheduler::get(), file_remover &fr=file_remover::get())
            : chunk_registry { data_dir, strict, sched, fr }, _indexers { std::move(indexers) },
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
            for (auto &[name, idxr_ptr]: _indexers) {
                if (idxr_ptr && idxr_ptr->mergeable())
                    _mergeable.emplace(name);
                idxr_ptr->clean_up();
            }
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
            if (end_offset != indexed_bytes())
                throw error("internal error: indexed size calculation is incorrect: {} vs {}", end_offset, indexed_bytes());
            if (end_offset != num_bytes())
                incremental::truncate(std::min(end_offset, num_bytes()));
            logger::info("indices have data up to offset {}", end_offset);
            _merge_next_offset = _merge_start_offset = end_offset;
            _epoch_slices.clear();
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

        slice_path_list reader_paths(const std::string &name, const slice_list &slcs) const
        {
            return indexer::multi_reader_paths(_idx_dir.string(), name, slcs);
        }

        slice_path_list reader_paths(const std::string &name) const
        {
            return indexer::multi_reader_paths(_idx_dir.string(), name, slices());
        }

        void truncate(size_t max_end_offset) override
        {
            chunk_registry::truncate(max_end_offset);
            // merge final not-yet merged epochs
            timer t { fmt::format("truncate indices to max offset {}", max_end_offset) };
            if (indexed_bytes() > max_end_offset) {
                std::vector<merger::slice> updated {};
                for (auto it = _slices.begin(); it != _slices.end(); ) {
                    const auto &s = it->second;
                    if (s.end_offset() <= max_end_offset) {
                        ++it;
                    } else { // s.end_offset() > max_end_offset
                        logger::trace("truncate index slice {}", s.slice_id);
                        if (s.offset >= max_end_offset) {
                            for (auto &[name, idxr_ptr]: _indexers)
                                _file_remover.mark(idxr_ptr->reader_path(s.slice_id));
                        } else {
                            merger::slice new_slice { s.offset, std::min(s.size, max_end_offset - s.offset) };
                            updated.emplace_back(new_slice);
                            for (auto &[name, idxr_ptr]: _indexers) {
                                _sched.submit_void("truncate-init-" + name, 25, [&idxr_ptr, s, new_slice, max_end_offset] {
                                    idxr_ptr->schedule_truncate(s.slice_id, max_end_offset, [&idxr_ptr, s, new_slice] {
                                        std::filesystem::rename(idxr_ptr->reader_path(s.slice_id), idxr_ptr->reader_path(new_slice.slice_id));
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
                _merge_next_offset = _merge_start_offset = num_bytes();
                _epoch_slices.clear();
            }
        }

        void save_state() override
        {
            timer t { "indexer::save_state" };
            chunk_registry::save_state();
            // merge final not-yet merged epochs
            {
                std::unique_lock lk { _epoch_slices_mutex };
                _schedule_final_merge(std::move(lk), true);
            }
            _sched.process(true);
            // combine small recent slices
            {
                uint64_t input_offset = 0;
                uint64_t input_size = 0;
                std::vector<std::string> input_slices {};
                for (auto rit = _slices.rbegin(); rit != _slices.rend(); ++rit) {
                    if (rit->second.size + input_size <= merger::part_size) {
                        input_slices.emplace_back(rit->second.slice_id);
                        input_size += rit->second.size;
                        input_offset = rit->second.offset;
                    } else {
                        break;
                    }
                }
                if (input_slices.size() >= 2) {
                    while (!_slices.empty() && _slices.rbegin()->second.offset >= input_offset) {
                        _slices.erase(_slices.rbegin()->first);
                    }
                    logger::info("combining small index slices between offsets {} and {} ...", input_offset, input_offset + input_size);
                    merger::slice output_slice { input_offset, input_size };
                    _merge_slice(output_slice, input_slices, 200, [this, output_slice, input_slices] {
                        _slices.add(std::move(output_slice));
                    });
                    _sched.process(true);
                }
            }
            json::array j_slices {};
            for (const auto &[offset, slice]: _slices)
                j_slices.emplace_back(slice.to_json());
            json::save_pretty(_index_state_path, j_slices);
            _epoch_slices.clear();
            _epoch_merged = 0;
            _final_merged = 0;
            _merge_next_offset = _merge_start_offset = _slices.empty() ? 0 : _slices.rbegin()->second.end_offset();
        }

        uint64_t indexed_bytes() const
        {
            std::scoped_lock lk { _slices_mutex };
            return _slices.continuous_size();
        }
    protected:
        const indexer_map _indexers;
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

        virtual void _on_slice_ready(uint64_t first_epoch, uint64_t last_epoch, const merger::slice &slice)
        {
            logger::info("on_slice_ready first_epoch: {} last_epoch: {} start_offset: {} end_offset: {}",
                first_epoch, last_epoch, slice.offset, slice.end_offset());
        }

        void _on_epoch_merge(uint64_t epoch, const epoch_info &info) override
        {
            chunk_registry::_on_epoch_merge(epoch, info);
            std::vector<std::string> input_slices {};
            for (const auto &chunk_ptr: info.chunks) {
                input_slices.emplace_back(fmt::format("update-{}", chunk_ptr->offset));
            }
            merger::slice output_slice { info.start_offset(), info.end_offset() - info.start_offset(), fmt::format("epoch-{}", epoch) };
            _merge_slice(output_slice, input_slices, 100, [this, epoch, output_slice] {
                std::unique_lock lk { _epoch_slices_mutex };
                _epoch_slices.emplace(epoch, std::move(output_slice));
                if (output_slice.end_offset() > _merge_start_offset) {
                    auto newly_merged = output_slice.offset >= _merge_start_offset ? output_slice.size : output_slice.end_offset() - _merge_start_offset;
                    auto new_epoch_merged = atomic_add(_epoch_merged, newly_merged);
                    if (_target_offset)
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
                auto end_offset = _target_offset ? *_target_offset : num_bytes();
                if (end_offset < output_slice.offset)
                    end_offset = output_slice.offset;
                size_t priority = prio_base + (end_offset - output_slice.offset) * 50 / end_offset; // [prio_base;prio_base+50) range
                auto done_parts = std::make_shared<std::atomic_size_t>(0);
                auto todo_parts = std::make_shared<std::atomic_size_t>(idxr_ptr->merge_task_count(input_paths));
                _sched.on_result(output_path, [this, priority, todo_parts, done_parts, indices_awaited, output_path, idxr_name, on_merge] (const auto &res) {
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
                _sched.submit_void("schedule-" + output_path, priority, [idxr_ptr, output_path, priority, input_paths] {
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
                if (total_size < merger::part_size && !force && (!_target_offset || _merge_next_offset + total_size < *_target_offset))
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
                        _final_merged = _slices.continuous_size() - _merge_start_offset;
                    }
                    if (_target_offset) {
                        progress::get().update("merge", _epoch_merged + _final_merged, (*_target_offset - _merge_start_offset) * 2);
                    }
                    _on_slice_ready(first_epoch, last_epoch, output_slice);
                });
                epoch_slices_lk.lock();
            }
        }

        chunk_info _parse (uint64_t offset, const std::string &rel_path, const buffer &raw_data, size_t compressed_size, const block_processor &blk_proc) const override
        {
            chunk_indexer_list chunk_indexers {};
            for (auto &[name, idxr_ptr]: _indexers)
                chunk_indexers.emplace_back(idxr_ptr->make_chunk_indexer("update", offset));
            return chunk_registry::_parse(offset, rel_path, raw_data, compressed_size, [&](const auto &blk) {
                blk_proc(blk);
                for (auto &idxr: chunk_indexers)
                    idxr->index(blk);
            });
        }
    };

    inline indexer_map default_list(const std::string &data_dir, scheduler &sched=scheduler::get())
    {
        const auto idx_dir = incremental::storage_dir(data_dir);
        indexer_map indexers {};
        indexers.emplace(std::make_shared<index::block_meta::indexer>(idx_dir, "block-meta", sched));
        indexers.emplace(std::make_shared<index::stake_ref::indexer>(idx_dir, "stake-ref", sched));
        indexers.emplace(std::make_shared<index::pay_ref::indexer>(idx_dir, "pay-ref", sched));
        indexers.emplace(std::make_shared<index::txo::indexer>(idx_dir, "txo", sched));
        indexers.emplace(std::make_shared<index::txo_use::indexer>(idx_dir, "txo-use", sched));
        return indexers;
    }
}

#endif // !DAEDALUS_TURBO_INDEXER_HPP