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
#include <dt/index/block-meta.hpp>
#include <dt/index/pay-ref.hpp>
#include <dt/index/stake-ref.hpp>
#include <dt/index/tx.hpp>
#include <dt/index/txo-use.hpp>
#include <dt/logger.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo::indexer {

    using indexer_list = std::vector<std::unique_ptr<index::indexer_base>>;
    using chunk_indexer_list = std::vector<std::unique_ptr<index::chunk_indexer_base>>;
    constexpr int min_no_open_files = 2048;

    struct incremental: public chunk_registry {
        incremental(scheduler &sched, const std::string &db_dir, indexer_list &indexers)
            : chunk_registry { sched, db_dir }, _indexers { indexers }
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

        chunk_info parse(uint64_t offset, const std::string &rel_path, const buffer &raw_data, size_t compressed_size) override
        {
            chunk_indexer_list chunk_indexers {};
            for (auto &idxr: _indexers)
                chunk_indexers.emplace_back(idxr->make_chunk_indexer("update", offset));
            auto info = _parse_normal(offset, rel_path, raw_data, compressed_size, [&chunk_indexers](const auto &blk) {
                for (auto &idxr: chunk_indexers)
                    idxr->index(blk);
            });
            {
                std::scoped_lock lk { _updates_mutex };
                _updates.emplace(offset);
            }
            return info;
        }

        file_set truncate(size_t max_end_offset, bool del=true) override
        {
            auto deleted_files = chunk_registry::truncate(max_end_offset, del);
            timer t { fmt::format("truncate indices to max offset {}", max_end_offset) };
            for (auto &idxr_ptr: _indexers) {
                _sched.submit("truncate-init-" + idxr_ptr->name(), 25, [this, &idxr_ptr] {
                    idxr_ptr->truncate("", num_bytes());
                    idxr_ptr->truncate("delta", num_bytes());
                    return true;
                });
            }
            _sched.process(true);
            return deleted_files;
        }

        void save_state() override
        {
            timer t { "update indices" };
            chunk_registry::save_state();
            for (auto &idxr_ptr: _indexers) {
                _sched.submit("finalize-init-" + idxr_ptr->name(), 25, [this, &idxr_ptr] {
                    idxr_ptr->finalize("update", _updates);
                    return true;
                });
            }
            _sched.process(true);
            // combine delta in base in case when delta is already too big to accommodate for another update
            for (auto &idxr_ptr: _indexers) {
                if (idxr_ptr->disk_size("delta") >= idxr_ptr->disk_size("") / 8) {
                    _sched.submit("combine-base-init-" + idxr_ptr->name(), 25, [&idxr_ptr] {
                        idxr_ptr->combine("", "delta");
                        return true;
                    });
                }
            }
            _sched.process(true);
            _updates.clear();
            for (auto &idxr_ptr: _indexers) {
                _sched.submit("combine-delta-init-" + idxr_ptr->name(), 25, [&idxr_ptr] {
                    idxr_ptr->combine("delta", "update");
                    return true;
                });
            }
            _sched.process(true);
        }
    
    private:
        indexer_list &_indexers;
        alignas(mutex::padding) std::mutex _updates_mutex {};
        index::chunk_id_list _updates {};
    };

    inline indexer_list default_list(scheduler &sched, const std::string &idx_dir)
    {
        indexer::indexer_list indexers {};
        indexers.emplace_back(std::make_unique<index::block_meta::indexer>(sched, idx_dir, "block-meta"));
        indexers.emplace_back(std::make_unique<index::stake_ref::indexer>(sched, idx_dir, "stake-ref"));
        indexers.emplace_back(std::make_unique<index::pay_ref::indexer>(sched, idx_dir, "pay-ref"));
        indexers.emplace_back(std::make_unique<index::tx::indexer>(sched, idx_dir, "tx"));
        indexers.emplace_back(std::make_unique<index::txo_use::indexer>(sched, idx_dir, "txo-use"));
        return indexers;
    }

    inline std::vector<std::string> multi_reader_paths(const std::string &base_path, const std::string &idx_name)
    {
        std::vector<std::string> slices {};
        for (const auto &slice_id: { "", "delta" }) {
            auto slice_path = index::indexer_base::reader_path(base_path, idx_name, slice_id);
            if (index::writer<int>::exists(slice_path))
                slices.emplace_back(std::move(slice_path));
        }
        return slices;
    }
}

#endif // !DAEDALUS_TURBO_INDEXER_HPP