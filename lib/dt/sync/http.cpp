/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/sync/http.hpp>
#include <dt/cardano.hpp>

namespace daedalus_turbo::sync::http {
    syncer::syncer(scheduler &sched, indexer::incremental &cr, const std::string &src_host, bool report_progress)
        : _sched { sched }, _cr { cr }, _host { src_host }, _report_progress { report_progress }, _dlq {}
    {
        for (auto &&path: _cr.init_state()) {
            logger::trace("excessive chunk found at startup {} - scheduling it for deletion", path);
            _deletable_chunks.emplace(std::move(path));
        }
    }

    void syncer::sync(std::optional<uint64_t> max_epoch)
    {
        timer t { "http synchronization" };
        progress_guard pg { "download", "parse", "merge", "leaders" };
        _cr.clean_up();
        auto [task, epoch_groups, remote_size] = _find_sync_start_position();
        if (max_epoch) {
            uint64_t max_offset = 0;
            for (auto g_it = epoch_groups.begin(); g_it != epoch_groups.end();) {
                auto &j_epochs = g_it->at("epochs").as_array();
                for (auto it = j_epochs.begin(); it != j_epochs.end();) {
                    if (json::value_to<uint64_t>(it->at("id")) <= max_epoch) {
                        max_offset += json::value_to<uint64_t>(it->at("size"));
                        ++it;
                    } else {
                        it = j_epochs.erase(it);
                    }
                }
                if (j_epochs.empty()) {
                    g_it = epoch_groups.erase(g_it);
                } else {
                    ++g_it;
                }
            }
            remote_size = max_offset;
            logger::info("user override max synced epoch: {} max synced offset: {}", *max_epoch, max_offset);
        }
        if (task) {
            logger::info("synchronization starts from chain offset {} in epoch {}", task->start_offset, task->start_epoch);
            _cr.target_offset(remote_size);
            auto deleted_chunks = _cr.truncate(task->start_offset, false);
            auto updated_chunks = _download_data(epoch_groups, task->start_epoch);
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

    std::string syncer::_get_sync(const std::string &target)
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

    template<typename T>
    T syncer::_get_json(const std::string &target)
    {
        try {
            return json::value_to<T>(json::parse(_get_sync(target)));
        } catch (std::exception &ex) {
            throw error("GET {} failed with error: {}", target, ex.what());
        }
    }

    std::tuple<std::optional<syncer::sync_task>, json::array, uint64_t> syncer::_find_sync_start_position()
    {
        timer t { "find first epoch to sync" };
        auto epoch_groups = _get_json<json::array>("/chain.json");
        if (epoch_groups.empty())
            throw error("the remote chain is empty - nothing to synchronize!");
        sync_task task_data {};
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
            last_synced_epoch_it = first_it;
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
                        progress.update("download-metadata", static_cast<double>(dm_progress.completed), dm_progress.total);
                        if (_report_progress)
                            progress.inform();
                    }
                });
            }
        }
        _dlq.process(_report_progress);
        progress.retire("download-metadata");
        if (last_synced_epoch_it != _cr.epochs().end()) {
            for (auto it = std::next(last_synced_epoch_it); it != _cr.epochs().end(); it++) {
                auto epoch_meta = json::parse(_epoch_json_cache.at(it->first)).as_object();
                auto &epoch_chunks = epoch_meta.at("chunks").as_array();
                if (epoch_chunks.empty())
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
            task_data.start_epoch = last_synced_epoch_it->first + 1;
            task_data.start_offset = new_end_offset;
        }
        std::optional<sync_task> task {};
        if (remote_chain_size > task_data.start_offset)
            task.emplace(std::move(task_data));
        cardano::slot remote_slot { json::value_to<uint64_t>(epoch_groups.back().at("lastSlot")) };
        logger::info("remote chain size: {} latest epoch: {} slot: {}", remote_chain_size, remote_slot.epoch(), remote_slot);
        return std::make_tuple(std::move(task), std::move(epoch_groups), remote_chain_size);
    }

    std::string syncer::_parse_local_chunk(const chunk_registry::chunk_info &chunk, const std::string &save_path)
    {
        try {
            auto compressed = file::read_raw(save_path);
            uint8_vector data {};
            zstd::decompress(data, compressed);
            auto parsed_chunk = _cr.parse(chunk.offset, chunk.orig_rel_path, data, compressed.size());
            if (parsed_chunk.data_hash != chunk.data_hash)
                throw error("data hash does not match for the chunk: {}", save_path);
            auto chunk_path = _cr.full_path(parsed_chunk.rel_path());                
            _cr.add(std::move(parsed_chunk));
            return chunk_path;
        } catch (std::exception &ex) {
            std::filesystem::path orig_path { save_path };
            auto debug_path = _cr.full_path(fmt::format("error/{}", orig_path.filename().string()));
            logger::warn("moving an unparsable chunk {} to {}", save_path, debug_path);
            std::filesystem::rename(save_path, debug_path);
            throw error("can't parse {}: {}", save_path, ex.what());
        }
    }

    void syncer::_download_chunks(const download_task_list &download_tasks, uint64_t max_offset, chunk_registry::file_set &updated_chunks)
    {
        timer t { fmt::format("download chunks: {}", download_tasks.size()) };
        struct saved_chunk {
            std::string path {};
            chunk_registry::chunk_info info {};
        };
        const std::string parse_task = "parse";
        uint64_t downloaded = 0;
        uint64_t download_start_offset = _cr.num_bytes();
        auto &progress = progress::get();
        std::function<void(const std::any&)> parsed_proc = [&](const std::any &res) {
            if (res.type() == typeid(scheduled_task_error))
                return;
            updated_chunks.emplace(std::any_cast<std::string>(res));
        };
        std::function<void(const std::any&)> saved_proc = [&](const auto &res) {
            if (res.type() == typeid(scheduled_task_error))
                return;
            const auto &chunk = std::any_cast<saved_chunk>(res);
            downloaded += chunk.info.data_size;
            if (_cr.target_offset()) {
                progress.update("download", downloaded, *_cr.target_offset() - download_start_offset);
            }
            _sched.submit(parse_task, 0 + 100 * (max_offset - chunk.info.offset) / max_offset, [this, chunk]() {
                return _parse_local_chunk(chunk.info, chunk.path);
            });
        };
        _sched.on_result(parse_task, parsed_proc);
        {
            timer t { "download all chunks and parse immutable ones" };
            // compute totals before starting the execution to ensure correct progress percentages            
            for (const auto &chunk: download_tasks) {
                auto data_url = fmt::format("http://{}/{}", _host, chunk.rel_path());
                auto save_path = _cr.full_path(chunk.rel_path());
                if (!std::filesystem::exists(save_path)) {
                    _dlq.download(data_url, save_path, chunk.offset, [chunk, saved_proc, save_path](download_queue::result &&res) {
                        if (res) {
                            saved_proc(saved_chunk { save_path, chunk });
                        } else {
                            logger::error("download of {} failed: {}", res.url, *res.error);
                        }
                    });
                } else {
                    saved_proc(saved_chunk { save_path, chunk });
                }
            }
            _dlq.process(_report_progress, &_sched);
            _sched.process(_report_progress);
        }
    }

    chunk_registry::file_set syncer::_download_data(const json::array &epoch_groups, size_t first_synced_epoch)
    {
        timer t { "download data" };
        std::vector<chunk_registry::chunk_info> download_tasks {};
        uint64_t max_offset = 0;
        for (const auto &group: epoch_groups)
            max_offset += json::value_to<uint64_t>(group.at("size"));
        uint64_t start_offset = 0;
        logger::info("downloading metadata about the synchronized epochs and chunks");
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
        logger::info("preparing the updated chunks to be downloaded, validated, and indexed: {}", download_tasks.size());
        _download_chunks(download_tasks, max_offset, updated_chunks);
        return updated_chunks;
    }
}