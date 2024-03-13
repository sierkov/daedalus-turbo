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
        progress_guard pg { "download", "parse", "merge", "validate" };
        _cr.clean_up();
        _epoch_json_cache.clear();
        auto j_chain = _get_json<json::object>("/chain.json");
        const auto &j_epochs = j_chain.at("epochs").as_array();
        for (;;) {
            auto [task, remote_size] = _find_sync_start_position(j_epochs);
            if (max_epoch) {
                remote_size = 0;
                for (size_t epoch = 0; epoch < j_epochs.size(); ++epoch) {
                    const auto &j_epoch_meta = j_epochs.at(epoch);
                    if (epoch <= *max_epoch)
                        remote_size += json::value_to<uint64_t>(j_epoch_meta.at("size"));
                }
                logger::info("user override max synced epoch: {} max synced offset: {}", *max_epoch, remote_size);
            }
            if (!task) {
                logger::info("local chain is up to date - nothing to do");
                break;
            } else if (task->start_offset != _cr.num_bytes()) {
                // truncation may require multiple iterations because the validator has snapshots only at certain points of the blockchain
                for (auto &&path: _cr.truncate(task->start_offset, false))
                    _deletable_chunks.emplace(std::move(path));
            } else {
                logger::info("synchronization starts from chain offset {} in epoch {}", task->start_offset, task->start_epoch);
                _cr.target_offset(remote_size);
                auto updated_chunks = _download_data(j_epochs, remote_size, task->start_epoch);
                _cr.save_state();
                // remove updated chunks from the to-be-deleted list
                for (auto &&path: updated_chunks) {
                    logger::trace("updated chunk: {}", path);
                    _deletable_chunks.erase(path);
                }
                for (auto &&path: _deletable_chunks) {
                    logger::trace("deleting chunk: {}", path);
                    std::filesystem::remove(path);
                }
                break;
            }
        }
        auto last_chunk = _cr.last_chunk();
        if (last_chunk) {
            logger::info("synced last_slot: {} last_block: {} took: {:0.1f} secs",
                last_chunk->last_slot, last_chunk->last_block_hash, t.stop(false));
        } else {
            logger::info("synced to an empty chain took: {:0.1f} secs", t.stop(false));
        }
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

    std::tuple<std::optional<syncer::sync_task>, uint64_t> syncer::_find_sync_start_position(const json::array &j_epochs)
    {
        timer t { "find first epoch to sync" };

        uint64_t remote_chain_size = 0;
        std::map<uint64_t, std::string> epoch_last_block_hash {};
        uint64_t check_from_epoch = 0;
        uint64_t check_from_offset = 0;
        for (size_t epoch = 0; epoch < j_epochs.size(); ++epoch) {
            const auto &j_epoch_meta = j_epochs[epoch];
            epoch_last_block_hash[epoch] = static_cast<std::string>(j_epoch_meta.at("lastBlockHash").as_string());
            auto epoch_size = json::value_to<uint64_t>(j_epoch_meta.at("size"));
            remote_chain_size += epoch_size;
            if (epoch == check_from_epoch) {
                auto epoch_it = _cr.epochs().find(epoch);
                if (epoch_it != _cr.epochs().end()
                    && epoch_it->second.last_block_hash() == cardano::block_hash::from_hex(j_epoch_meta.at("lastBlockHash").as_string()))
                {
                    check_from_epoch = epoch + 1;
                    check_from_offset += epoch_size;
                }
            }
        }
        if (check_from_epoch <= _cr.max_slot().epoch()) {
            auto check_epoch_it = _cr.epochs().find(check_from_epoch);
            if (check_epoch_it != _cr.epochs().end()) {
                auto j_epoch = _get_json<json::object>(fmt::format("/epoch-{}-{}.json", check_from_epoch, epoch_last_block_hash.at(check_from_epoch)));
                for (const auto &chunk: j_epoch.at("chunks").as_array()) {
                    auto data_hash = cardano::block_hash::from_hex(json::value_to<std::string_view>(chunk.at("hash")));
                    auto chunk_it = _cr.find(data_hash);
                    if (chunk_it == _cr.chunks().end() || chunk_it->second.offset != check_from_offset)
                        break;
                    check_from_offset += chunk_it->second.data_size;
                }
            }
        }
        std::optional<sync_task> task {};
        if (remote_chain_size > check_from_offset)
            task.emplace(check_from_epoch, check_from_offset);
        cardano::slot remote_slot { json::value_to<uint64_t>(j_epochs.back().at("lastSlot")) };
        logger::info("remote chain size: {} latest epoch: {} slot: {}", remote_chain_size, remote_slot.epoch(), remote_slot);
        return std::make_tuple(std::move(task), remote_chain_size);
    }

    std::string syncer::_parse_local_chunk(const chunk_registry::chunk_info &chunk, const std::string &save_path)
    {
        try {
            return _cr.add(chunk.offset, save_path, chunk.data_hash, chunk.orig_rel_path);
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
                auto data_url = fmt::format("http://{}/compressed/{}", _host, chunk.rel_path());
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

    chunk_registry::file_set syncer::_download_data(const json::array &j_epochs, uint64_t max_offset, uint64_t first_synced_epoch)
    {
        timer t { "download data" };
        std::vector<chunk_registry::chunk_info> download_tasks {};
        logger::info("downloading metadata about the synchronized epochs and chunks");
        std::map<uint64_t, uint64_t> epoch_offsets {};
        uint64_t current_offset = 0;
        for (size_t epoch = 0; epoch < j_epochs.size() && current_offset < max_offset; ++epoch) {
            const auto &j_epoch_meta = j_epochs[epoch];
            auto epoch_size = json::value_to<uint64_t>(j_epoch_meta.at("size"));
            auto epoch_last_block_hash = static_cast<std::string>(j_epoch_meta.at("lastBlockHash").as_string());
            if (epoch >= first_synced_epoch) {
                epoch_offsets[epoch] = current_offset;
                if (!_epoch_json_cache.contains(epoch)) {
                    auto epoch_url = fmt::format("http://{}/epoch-{}-{}.json", _host, epoch, epoch_last_block_hash);
                    auto save_path = _cr.full_path(fmt::format("remote/epoch-{}.json", epoch));
                    _dlq.download(epoch_url, save_path, epoch, [this, epoch, save_path](auto &&res) {
                        if (res) {
                            auto buf = file::read(save_path);
                            std::scoped_lock lk { _epoch_json_cache_mutex };
                            _epoch_json_cache[epoch] = buf.span().string_view();
                        }
                    });
                }
            }
            current_offset += epoch_size;
        }
        _dlq.process(_report_progress, &_sched);
        _sched.process(_report_progress);
        for (const auto &[epoch_id, epoch_start_offset]: epoch_offsets) {
            auto epoch = json::parse(_epoch_json_cache.at(epoch_id)).as_object();
            uint64_t chunk_start_offset = epoch_start_offset;
            for (const auto &j_chunk: epoch.at("chunks").as_array()) {
                auto chunk = chunk_registry::chunk_info::from_json(j_chunk.as_object());
                auto chunk_size = chunk.data_size;
                if (chunk_start_offset + chunk_size > max_offset)
                    break;
                const auto chunk_it = _cr.find(chunk.data_hash);
                if (chunk_it == _cr.chunks().end()) {
                    chunk.offset = chunk_start_offset;
                    download_tasks.emplace_back(std::move(chunk));
                } else if (chunk_it->second.data_size != chunk_size || chunk_it->second.offset != chunk_start_offset) {
                    throw error("remote chunk offset: {} and size: {} does not match the local ones: {} and {}",
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