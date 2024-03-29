/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano.hpp>
#include <dt/cardano/network.hpp>
#include <dt/http/download-queue.hpp>
#include <dt/sync/http.hpp>

namespace daedalus_turbo::sync::http {
    struct syncer::impl {
        impl(indexer::incremental &cr, peer_selection &ps, scheduler &sched, file_remover &fr)
            : _cr { cr }, _peer_selection { ps }, _sched { sched }, _file_remover { fr }
        {
        }

        void sync(std::optional<uint64_t> max_epoch)
        {
            timer t { "http synchronization" };
            progress_guard pg { "download", "parse", "merge", "validate" };
            _epoch_json_cache.clear();
            auto [turbo_host, j_chain] = _select_peer();
            const auto &j_epochs = j_chain.at("epochs").as_array();
            if (j_epochs.empty())
                throw error("Remote turbo node reports and empty chain!");
            auto [task, remote_size] = _find_sync_start_position(turbo_host, j_epochs);
            _verify_intersection(j_epochs);
            if (max_epoch) {
                remote_size = 0;
                for (size_t epoch = 0; epoch < j_epochs.size(); ++epoch) {
                    const auto &j_epoch_meta = j_epochs.at(epoch);
                    if (epoch <= *max_epoch)
                        remote_size += json::value_to<uint64_t>(j_epoch_meta.at("size"));
                }
                logger::info("user override max synced epoch: {} max synced offset: {}", *max_epoch, remote_size);
            }
            if (task) {
                if (task->start_offset != _cr.num_bytes()) {
                    logger::info("synchronization start {} != compressed db size {} - truncating it", task->start_offset, _cr.num_bytes());
                    // truncation may require multiple iterations because the validator has snapshots only at certain points of the blockchain
                    _cr.truncate(task->start_offset);
                }
                logger::info("synchronization starts from chain offset {} in epoch {}", task->start_offset, task->start_epoch);
                _cr.target_offset(remote_size);
                auto updated_chunks = _download_data(turbo_host, j_epochs, remote_size, task->start_epoch);
                _cr.save_state();
                // remove updated chunks from the to-be-deleted list
                for (auto &&path: updated_chunks) {
                    logger::trace("updated chunk: {}", path);
                    _file_remover.unmark(path);
                }
            } else {
                logger::info("local chain is up to date - nothing to do");
            }
            _file_remover.remove();
            auto last_chunk = _cr.last_chunk();
            if (last_chunk) {
                logger::info("synced last_slot: {} last_block: {} took: {:0.1f} secs",
                    last_chunk->last_slot, last_chunk->last_block_hash, t.stop(false));
            } else {
                logger::info("synced to an empty chain took: {:0.1f} secs", t.stop(false));
            }
        }
    private:
        using download_queue = daedalus_turbo::http::download_queue;
        using download_task_list = std::vector<chunk_registry::chunk_info>;
        struct sync_task {
            uint64_t start_epoch = 0;
            uint64_t start_offset = 0;
        };

        indexer::incremental &_cr;
        peer_selection &_peer_selection;
        scheduler &_sched;
        file_remover &_file_remover;
        download_queue _dlq {};
        chunk_registry::file_set _deletable_chunks {};
        alignas(mutex::padding) std::mutex _epoch_json_cache_mutex {};
        std::map<uint64_t, json::object> _epoch_json_cache {};

        std::pair<std::string, json::object> _select_peer()
        {
            static constexpr size_t max_retries = 10;
            for (size_t n_retries = 0; n_retries < max_retries; ++n_retries) {
                try {
                    auto turbo_host = _peer_selection.next_turbo();
                    logger::info("trying host {} as the compressed blockchain source", turbo_host);
                    auto j_chain = daedalus_turbo::http::fetch_json(fmt::format("http://{}/chain.json", turbo_host)).as_object();
                    return std::make_pair(std::move(turbo_host), std::move(j_chain));
                } catch (std::exception &ex) {
                    logger::warn(ex.what());
                }
            }
            throw error("failed to find an operational peer in {} attempts!", max_retries);
        }

        // j_epochs is checked to be non empty by the caller!
        void _verify_intersection(const json::array &j_epochs)
        {
            using namespace cardano::network;
            blockchain_point_list points {};
            for (auto rit = j_epochs.rbegin(), rend = j_epochs.rend(); rit != rend; ++rit) {
                const auto &j_epoch = rit->as_object();
                points.emplace_back(
                    cardano::block_hash::from_hex(j_epoch.at("lastBlockHash").as_string()),
                    json::value_to<uint64_t>(j_epoch.at("lastSlot"))
                );
                if (points.size() >= 2)
                    break;
            }
            client c {};
            client::find_response resp {};
            auto peer_addr = _peer_selection.next_cardano();
            c.find_intersection(peer_addr, points, [&](client::find_response &&r) {
                resp = std::move(r);
            });
            c.process();
            if (std::holds_alternative<blockchain_point_pair>(resp.res)) {
                const auto &[point, tip] = std::get<blockchain_point_pair>(resp.res);
                logger::info("Cardano network peer confirmed a mutually known block at slot {}", point.slot);
            } else if (std::holds_alternative<client::error_msg>(resp.res)) {
                throw error("{}", std::get<client::error_msg>(resp.res));
            } else {
                throw error("Cardano network peer reported no known intersection within the last two epochs - stopping!");
            }
        }

        std::tuple<std::optional<sync_task>, uint64_t> _find_sync_start_position(const std::string &host, const json::array &j_epochs)
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
                if (check_epoch_it != _cr.epochs().end() && epoch_last_block_hash.contains(check_from_epoch)) {
                    _epoch_json_cache[check_from_epoch] = daedalus_turbo::http::fetch_json(fmt::format("http://{}/epoch-{}-{}.json", host, check_from_epoch, epoch_last_block_hash.at(check_from_epoch))).as_object();
                    const auto &j_epoch = _epoch_json_cache.at(check_from_epoch);
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
            cardano::slot remote_slot {};
            if (!j_epochs.empty())
                remote_slot = json::value_to<uint64_t>(j_epochs.back().at("lastSlot"));
            logger::info("remote chain size: {} latest epoch: {} slot: {}", remote_chain_size, remote_slot.epoch(), remote_slot);
            return std::make_tuple(std::move(task), remote_chain_size);
        }

        std::string _parse_local_chunk(const chunk_registry::chunk_info &chunk, const std::string &save_path)
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

        void _download_chunks(const std::string &host, const download_task_list &download_tasks, uint64_t max_offset, chunk_registry::file_set &updated_chunks)
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
                    auto data_url = fmt::format("http://{}/compressed/{}", host, chunk.rel_path());
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
                _dlq.process(true, &_sched);
                _sched.process(true);
            }
        }

        chunk_registry::file_set _download_data(const std::string &host, const json::array &j_epochs, uint64_t max_offset, uint64_t first_synced_epoch)
        {
            timer t { "download data" };
            std::vector<chunk_registry::chunk_info> download_tasks {};
            logger::info("downloading metadata about the synchronized epochs and chunks");
            std::map<uint64_t, uint64_t> epoch_offsets {};
            uint64_t current_offset = 0;
            for (size_t epoch = 0; epoch < j_epochs.size() && current_offset < max_offset; ++epoch) {
                const auto &j_epoch_meta = j_epochs.at(epoch);
                auto epoch_size = json::value_to<uint64_t>(j_epoch_meta.at("size"));
                auto epoch_last_block_hash = static_cast<std::string>(j_epoch_meta.at("lastBlockHash").as_string());
                if (epoch >= first_synced_epoch) {
                    epoch_offsets[epoch] = current_offset;
                    if (!_epoch_json_cache.contains(epoch)) {
                        auto epoch_url = fmt::format("http://{}/epoch-{}-{}.json", host, epoch, epoch_last_block_hash);
                        auto save_path = _cr.full_path(fmt::format("remote/epoch-{}.json", epoch));
                        _dlq.download(epoch_url, save_path, epoch, [this, epoch, save_path](auto &&res) {
                            if (res) {
                                auto buf = file::read(save_path);
                                std::scoped_lock lk { _epoch_json_cache_mutex };
                                _epoch_json_cache[epoch] = json::parse(buf.span().string_view()).as_object();
                            }
                        });
                    }
                }
                current_offset += epoch_size;
            }
            _dlq.process(true, &_sched);
            _sched.process(true);
            for (const auto &[epoch_id, epoch_start_offset]: epoch_offsets) {
                if (!_epoch_json_cache.contains(epoch_id))
                    throw error("internal error: epoch cache is missing epoch {} known epochs: {} sync start: {}", epoch_id, j_epochs.size(), first_synced_epoch);
                uint64_t chunk_start_offset = epoch_start_offset;
                for (const auto &j_chunk: _epoch_json_cache.at(epoch_id).at("chunks").as_array()) {
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
            _download_chunks(host, download_tasks, max_offset, updated_chunks);
            return updated_chunks;
        }
    };

    syncer::syncer(indexer::incremental &cr, peer_selection &ps, scheduler &sched, file_remover &fr)
        : _impl { std::make_unique<impl>(cr, ps, sched, fr) }
    {
    }

    syncer::~syncer() =default;

    void syncer::sync(std::optional<uint64_t> max_epoch)
    {
        _impl->sync(max_epoch);
    }
}