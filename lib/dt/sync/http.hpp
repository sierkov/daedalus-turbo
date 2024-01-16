/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SYNC_HTTP_HPP
#define DAEDALUS_TURBO_SYNC_HTTP_HPP

#include <dt/cardano.hpp>
#include <dt/http/download-queue.hpp>
#include <dt/indexer.hpp>
#include <dt/progress.hpp>

namespace daedalus_turbo::sync::http {
    struct syncer {
        syncer(scheduler &sched, indexer::incremental &cr, const std::string &src_host, bool report_progress=true)
            : _sched { sched }, _cr { cr }, _host { src_host }, _report_progress { report_progress }, _dlq {}
        {
            auto deletable_chunks = _cr.init_state();
            for (auto &&path: deletable_chunks) {
                logger::trace("unknown chunk found at startup {} - scheduling it for deletion", path);
                _deletable_chunks.emplace(std::move(path));
            }
        }

        void sync()
        {
            timer t { "http synchronization" };
            _cr.clean_up();
            auto epoch_groups = _get_json<json::array>("/chain.json");
            if (epoch_groups.empty())
                throw error("the remote chain is empty - nothing to synchronize!");
            auto task = _find_sync_start_position(epoch_groups);
            if (task) {
                logger::info("synchronization starts from chain offset {} in epoch {}", task->start_offset, task->start_epoch);
                auto deleted_chunks = _cr.truncate(task->start_offset, false);
                progress_guard pg { "download", "parse", "merge" };
                sync_progress progress {};
                progress.merge.completed = task->start_offset;
                _cr.set_progress("merge", progress.merge);
                auto updated_chunks = _download_data(progress, epoch_groups, task->start_epoch);
                _cr.save_state();
                for (auto &&path: deleted_chunks)
                    _deletable_chunks.emplace(std::move(path));
                // remove updated chunks from the to-be-deleted list
                for (auto &&path: updated_chunks) {
                    logger::trace("updated chunk: {}", path);
                    _deletable_chunks.erase(path);
                }
            } else {
                logger::info("local chain is up to date - nothing to do");
            }
            for (auto &&path: _deletable_chunks) {
                logger::trace("deleting chunk: {}", path);
                std::filesystem::remove(path);
            }
            logger::info("synced last_slot: {} last_block: {} took: {:0.1f} secs",
                            json::value_to<uint64_t>(epoch_groups.back().at("lastSlot")),
                            json::value_to<std::string_view>(epoch_groups.back().at("lastBlockHash")),
                            t.stop(false));
        }

    private:
        using download_queue = daedalus_turbo::http::download_queue;

        struct sync_task {
            uint64_t start_epoch = 0;
            uint64_t start_offset = 0;
        };

        struct sync_progress {
            progress::info download {};
            progress::info parse {};
            progress::info merge {};
        };

        scheduler &_sched;
        indexer::incremental &_cr;
        std::string _host;
        const bool _report_progress;
        download_queue _dlq;
        chunk_registry::file_set _deletable_chunks {};
        alignas(mutex::padding) std::mutex _epoch_json_cache_mutex {};
        std::map<uint64_t, std::string> _epoch_json_cache {};

        std::string _get_sync(const std::string &target)
        {
            file::tmp tmp { "sync-http-download-sync.bin" };
            std::atomic_bool ready { false };
            std::optional<std::string> err {};
            auto url = fmt::format("http://{}{}", _host, target);
            _dlq.download(url, tmp.path(), 0, [&](const auto &res) {
                err = std::move(res.error);
                ready = true;
            });;
            while (!ready) {
                std::this_thread::sleep_for(std::chrono::milliseconds { 100 });
            }
            if (err)
                throw error("download of {} failed: {}", url, *err);
            auto buf = file::read(tmp.path());
            return std::string { buf.span().string_view() };
        }

        void _get_sync(const std::string &target, uint8_vector &data)
        {
            data = _get_sync(target);
        }

        template<typename T>
        T _get_json(const std::string &target)
        {
            try {
                return json::value_to<T>(json::parse(_get_sync(target)));
            } catch (std::exception &ex) {
                throw error("GET {} failed with error: {}", target, ex.what());
            }
        }

        std::optional<sync_task> _find_sync_start_position(const json::array &epoch_groups)
        {
            timer t { "find first epoch to sync" };
            sync_task task {};
            auto last_synced_epoch_it = _cr.epochs().end();
            uint64_t remote_chain_size = 0;
            _epoch_json_cache.clear();
            for (const auto &group: epoch_groups)
                remote_chain_size += json::value_to<uint64_t>(group.at("size"));
            // find first differing epoch group
            for (const auto &group: epoch_groups) {
                const auto &epochs = group.at("epochs").as_array();
                if (epochs.empty())
                    throw error("remote peer reported an empty epoch group!");
                auto first_it = _cr.epochs().find(json::value_to<uint64_t>(epochs.front().at("id")));
                if (first_it == _cr.epochs().end())
                    break;
                if (first_it->second.prev_block_hash != bytes_from_hex((std::string_view)group.at("prevBlockHash").as_string()))
                    break;
                auto last_it = _cr.epochs().find(json::value_to<uint64_t>(epochs.back().at("id")));
                if (last_it == _cr.epochs().end())
                    break;
                if (last_it->second.last_block_hash != bytes_from_hex((std::string_view)group.at("lastBlockHash").as_string()))
                    break;
                last_synced_epoch_it = last_it;
            }
            auto &progress = progress::get();
            progress.update("download-metadata", "0.000%");
            progress::info dm_progress {};
            if (last_synced_epoch_it != _cr.epochs().end()) {
                for (auto it = std::next(last_synced_epoch_it); it != _cr.epochs().end(); it++) {
                    uint64_t epoch = it->first;
                    dm_progress.total++;
                    auto save_path = _cr.full_path(fmt::format("remote/epoch-{}.json", epoch));
                    _dlq.download(fmt::format("http://{}/epoch-{}.json", _host, epoch), save_path, epoch, [this, &dm_progress, &progress, epoch, save_path](auto &&res) {
                        if (res) {
                            auto buf = file::read(save_path);
                            {
                                std::scoped_lock lk { _epoch_json_cache_mutex };
                                _epoch_json_cache[epoch] = buf.span().string_view();
                            }
                            dm_progress.completed++;
                            progress.update("download-metadata", fmt::format("{:0.3f}%", static_cast<double>(dm_progress.completed) * 100 / dm_progress.total));
                        }
                    });
                }
            }
            _dlq.process(_report_progress);
            progress.retire("download-metadata");
            if (last_synced_epoch_it != _cr.epochs().end()) {
                for (auto it = std::next(last_synced_epoch_it); it != _cr.epochs().end(); it++) {
                    static std::string_view volatile_prefix { "volatile/" };
                    auto epoch_meta = json::parse(_epoch_json_cache.at(it->first)).as_object();
                    auto &epoch_chunks = epoch_meta.at("chunks").as_array();
                    if (epoch_chunks.empty())
                        break;
                    // volatile chunks require context dependent parsing, so boundary checks are insufficient and chunks must be compared
                    if (static_cast<std::string_view>(epoch_chunks.back().at("relPath").as_string()).substr(0, volatile_prefix.size()) == volatile_prefix)
                        break;
                    if (it->second.prev_block_hash != bytes_from_hex((std::string_view)epoch_meta.at("prevBlockHash").as_string()))
                        break;
                    if (it->second.last_block_hash != bytes_from_hex((std::string_view)epoch_meta.at("lastBlockHash").as_string()))
                        break;
                    last_synced_epoch_it = it;
                }
                // identify first differing chunk in the first differing epoch
                uint64_t new_end_offset = last_synced_epoch_it->second.end_offset;
                auto next_epoch_it = std::next(last_synced_epoch_it);
                if (next_epoch_it != _cr.epochs().end()) {
                    const auto epoch = json::parse(_epoch_json_cache.at(next_epoch_it->first)).as_object();
                    uint8_vector data {}, compressed {};
                    for (const auto &chunk: epoch.at("chunks").as_array()) {
                        auto data_hash = bytes_from_hex(json::value_to<std::string_view>(chunk.at("hash")));
                        auto chunk_it = _cr.find(data_hash);
                        if (chunk_it == _cr.chunks().end())
                            break;
                        new_end_offset = chunk_it->second.offset + chunk_it->second.data_size;
                    }
                }
                task.start_epoch = last_synced_epoch_it->first + 1;
                task.start_offset = new_end_offset;
            }
            cardano::slot remote_slot { json::value_to<uint64_t>(epoch_groups.back().at("lastSlot")) };
            logger::info("remote chain size: {} latest epoch: {} slot: {}", remote_chain_size, remote_slot.epoch(), remote_slot);
            if (remote_chain_size == 0 || remote_chain_size == task.start_offset)
                return std::optional<sync_task> {};
            return task;
        }

        using download_task_list = std::vector<chunk_registry::chunk_info>;

        chunk_registry::chunk_info _parse_local_chunk(const chunk_registry::chunk_info &chunk, const std::string &save_path)
        {
            try {
                auto compressed = file::read_raw(save_path);
                uint8_vector data {};
                zstd::decompress(data, compressed);
                auto parsed_chunk = _cr.parse(chunk.offset, chunk.orig_rel_path, data, compressed.size());
                if (parsed_chunk.data_hash != chunk.data_hash)
                    throw error("data hash does not match for the chunk: {}", save_path);
                return parsed_chunk;
            } catch (std::exception &ex) {
                std::filesystem::path orig_path { save_path };
                auto debug_path = _cr.full_path(fmt::format("error/{}", orig_path.filename().string()));
                logger::warn("moving an unparsable chunk {} to {}", save_path, debug_path);
                std::filesystem::rename(save_path, debug_path);
                throw error("can't parse {}: {}", save_path, ex.what());
            }
        }

        void _register_parsed_chunks(std::vector<chunk_registry::chunk_info> &new_chunks, chunk_registry::file_set &updated_chunks)
        {
            timer t { fmt::format("register_parsed_chunks {}", new_chunks.size()) };
            if (!new_chunks.empty()) {
                std::sort(new_chunks.begin(), new_chunks.end(),
                    [](const auto &a, const auto &b) { return a.offset < b.offset; });
                for (auto &&chunk: new_chunks) {
                    updated_chunks.emplace(_cr.full_path(chunk.rel_path()));
                    logger::debug("adding chunk {} to the registry at offset {}", chunk.orig_rel_path, chunk.offset);
                    _cr.add(std::move(chunk));
                }
            }
        }

        void _download_chunks(sync_progress &sp, const download_task_list &download_tasks, uint64_t max_offset, chunk_registry::file_set &updated_chunks)
        {
            timer t { fmt::format("download chunks: {}", download_tasks.size()) };
            struct saved_chunk {
                std::string path {};
                chunk_registry::chunk_info info {};
            };
            const std::string parse_task = "parse";
            const std::string save_task = "save";
            std::vector<chunk_registry::chunk_info> new_chunks {};
            std::vector<saved_chunk> volatile_chunks {};
            auto &progress = progress::get();
            std::function<void(const std::any&)> parsed_proc = [&](const std::any &res) {
                if (res.type() == typeid(scheduled_task_error))
                    return;
                const auto &chunk = std::any_cast<chunk_registry::chunk_info>(res);
                new_chunks.emplace_back(chunk);
                sp.parse.completed += chunk.compressed_size;
                progress.update("parse", fmt::format("{:0.3f}%", static_cast<double>(sp.parse.completed) * 100 / sp.parse.total));
            };
            std::function<void(const std::any&)> saved_proc = [&](const auto &res) {
                if (res.type() == typeid(scheduled_task_error))
                    return;
                const auto &chunk = std::any_cast<saved_chunk>(res);
                sp.download.completed += chunk.info.compressed_size;
                progress.update("download", fmt::format("{:0.3f}%", static_cast<double>(sp.download.completed) * 100 / sp.download.total));
                if (!chunk.info.is_volatile()) {
                    _sched.submit(parse_task, 100 + 100 * (max_offset - chunk.info.offset) / max_offset, [this, chunk]() {
                        return _parse_local_chunk(chunk.info, chunk.path);
                    });
                } else {
                    volatile_chunks.emplace_back(chunk.path, chunk.info);
                }
            };
            _sched.on_result(parse_task, parsed_proc);
            _sched.on_result(save_task, saved_proc);
            {
                timer t { "download all chunks and parse immutable ones" };
                // compute totals before starting the execution to ensure correct progress percentages
                sp.merge.total = max_offset;
                for (const auto &chunk: download_tasks) {
                    sp.download.total += chunk.compressed_size;
                    sp.parse.total += chunk.compressed_size;
                }
                for (const auto &chunk: download_tasks) {
                    auto data_url = fmt::format("http://{}/{}", _host, chunk.rel_path());
                    auto save_path = _cr.full_path(chunk.rel_path());
                    if (!std::filesystem::exists(save_path)) {
                        _dlq.download(data_url, save_path + ".tmp", chunk.offset, [this, chunk, saved_proc, save_path](download_queue::result &&res) {
                            if (res) {
                                std::filesystem::rename(res.save_path, save_path);
                                saved_proc(saved_chunk { save_path, chunk });
                            } else {
                                logger::error("download of {} failed: {}", res.url, *res.error);
                            }
                        });
                    } else {
                        saved_proc(saved_chunk { save_path, chunk });
                    }
                }
            }
            _dlq.process(_report_progress, &_sched);
            _sched.process(_report_progress);
            _register_parsed_chunks(new_chunks, updated_chunks);
            if (!volatile_chunks.empty()) {
                {
                    timer t { "parse volatile chunks" };
                    new_chunks.clear();
                    _sched.on_result(parse_task, parsed_proc);
                    for (auto &&chunk: volatile_chunks) {
                        _sched.submit(parse_task, 100 + 100 * (max_offset - chunk.info.offset) / max_offset, [this, chunk]() {
                            return _parse_local_chunk(chunk.info, chunk.path);
                        });
                    }
                    _sched.process(_report_progress);
                }
                _register_parsed_chunks(new_chunks, updated_chunks);
            }
        }

        chunk_registry::file_set _download_data(sync_progress &sp, const json::array &epoch_groups, size_t first_synced_epoch)
        {
            timer t { "download data" };
            std::vector<chunk_registry::chunk_info> download_tasks {};
            uint64_t max_offset = 0;
            for (const auto &group: epoch_groups)
                max_offset += json::value_to<uint64_t>(group.at("size"));
            uint64_t start_offset = 0;
            logger::info("downloading metadata about the synchronized epochs");
            std::map<uint64_t, uint64_t> epoch_offsets {};
            for (const auto &group: epoch_groups) {
                for (const auto &epoch: group.at("epochs").as_array()) {
                    auto epoch_id = json::value_to<uint64_t>(epoch.at("id"));
                    auto epoch_size = json::value_to<uint64_t>(epoch.at("size"));
                    if (epoch_id >= first_synced_epoch) {
                        epoch_offsets[epoch_id] = start_offset;
                        if (!_epoch_json_cache.contains(epoch_id)) {
                            auto epoch_url = fmt::format("http://{}/epoch-{}.json", _host, epoch_id);
                            auto save_path = _cr.full_path(fmt::format("remote/epoch-{}.json", epoch_id));
                            _dlq.download(epoch_url, save_path, epoch_id, [this, epoch_id, save_path](auto &&res) {
                                if (res) {
                                    auto buf = file::read(save_path);
                                    std::scoped_lock { _epoch_json_cache_mutex };
                                    _epoch_json_cache[epoch_id] = buf.span().string_view();
                                }
                            });
                        }
                    }
                    start_offset += epoch_size;
                }
            }
            _dlq.process(_report_progress, &_sched);
            _sched.process(_report_progress);
            for (const auto &[epoch_id, epoch_start_offset]: epoch_offsets) {
                auto epoch = json::parse(_epoch_json_cache.at(epoch_id)).as_object();
                uint64_t chunk_start_offset = epoch_start_offset;
                for (const auto &j_chunk: epoch.at("chunks").as_array()) {
                    auto chunk = chunk_registry::chunk_info::from_json(j_chunk.as_object());
                    auto chunk_size = chunk.data_size;
                    const auto chunk_it = _cr.find(chunk.data_hash);
                    if (chunk_it == _cr.chunks().end()) {
                        chunk.offset = chunk_start_offset;
                        download_tasks.emplace_back(std::move(chunk));
                    } else if (chunk_it->second.data_size != chunk_size || chunk_it->second.offset != chunk_start_offset) {
                        throw error("remote chunk offset: {} and size: {} mismatch the local ones: {} and {}",
                            chunk_start_offset, chunk_size, chunk_it->second.offset, chunk_it->second.data_size);
                    }
                    chunk_start_offset += chunk_size;
                }
            }
            chunk_registry::file_set updated_chunks {};
            logger::info("downloading and parsing the differing chunks: {}", download_tasks.size());
            _download_chunks(sp, download_tasks, max_offset, updated_chunks);
            return updated_chunks;
        }
    };
}

#endif // !DAEDALUS_TURBO_SYNC_HTTP_HPP