/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano.hpp>
#include <dt/cardano/network.hpp>
#include <dt/config.hpp>
#include <dt/http/download-queue.hpp>
#include <dt/sync/http.hpp>
#include <dt/validator.hpp>

namespace daedalus_turbo::sync::http {
    struct syncer::impl {
        impl(indexer::incremental &cr, daedalus_turbo::http::download_queue &dq, cardano::network::client &cnc, peer_selection &ps, scheduler &sched, file_remover &fr)
            : _cr { cr }, _dlq { dq }, _cnc { cnc }, _peer_selection { ps }, _sched { sched }, _file_remover { fr },
                _vk { ed25519_vkey::from_hex(static_cast<std::string_view>(configs_dir::get().at("turbo").at("vkey").as_string())) }
        {
        }

        [[nodiscard]] peer_info find_peer() const
        {
            return _select_peer();
        }

        void sync(std::optional<peer_info> peer, const std::optional<uint64_t> max_epoch)
        {
            timer t { "http synchronization" };
            progress_guard pg { "download", "parse", "merge", "validate" };

            // determine the synchronization peer and task
            _epoch_json_cache.clear();
            _cancel_min_offset.reset();
            if (!peer)
                peer = _select_peer();
            const auto &j_epochs = peer->chain.at("epochs").as_array();
            if (j_epochs.empty())
                throw error("Remote turbo node reports and empty chain!");
            auto [task, remote_size] = _find_sync_start_position(peer->host, j_epochs);
            if (max_epoch) {
                remote_size = 0;
                for (size_t epoch = 0; epoch < j_epochs.size(); ++epoch) {
                    const auto &j_epoch_meta = j_epochs.at(epoch);
                    if (epoch <= *max_epoch)
                        remote_size += json::value_to<uint64_t>(j_epoch_meta.at("size"));
                }
                logger::info("user override max synced epoch: {} max synced offset: {}", *max_epoch, remote_size);
            }

            std::exception_ptr ex_ptr {};
            if (task) {
                logger::info("synchronization starts from chain offset {} in epoch {}", task->start_offset, task->start_epoch);
                uint64_t run_start_offset = task->start_offset;
                uint64_t run_start_epoch = task->start_epoch;
                // download metadata for the whole sync at once
                _download_metadata(peer->host, j_epochs, remote_size, task->start_epoch);
                while (run_start_offset < remote_size) {
                    const auto run_max_offset = _run_max_offset(j_epochs, run_start_offset, remote_size);
                    // set start and target offset to the full task for correct progress computation
                    _cr.start_tx(task->start_offset, remote_size, run_start_offset == task->start_offset);
                    chunk_registry::file_set updated_chunks {};
                    try {
                        timer td { "sync::http::download_data", logger::level::debug };
                        updated_chunks = _download_data(peer->host, j_epochs, run_max_offset, run_start_epoch);
                    } catch (const std::exception &ex) {
                        logger::error("sync error: {}", ex.what());
                        ex_ptr = std::current_exception();
                    }
                    _cr.prepare_tx();
                    // if no progress has been made, rethrow the exception
                    // Otherwise, try to record the progress and continue
                    if (_cr.valid_end_offset() <= run_start_offset) {
                        if (ex_ptr)
                            std::rethrow_exception(ex_ptr);
                        throw error("no progress has been made, refusing to accept the new state");
                    }

                    _cr.commit_tx();
                    // remove updated chunks from the to-be-deleted list
                    for (auto &&path: updated_chunks) {
                        logger::trace("updated chunk: {}", path);
                        _file_remover.unmark(path);
                    }
                    run_start_offset = _cr.valid_end_offset();
                    run_start_epoch = _cr.max_slot().epoch();
                }
                _verify_intersection();
            } else {
                logger::info("local chain is up to date - nothing to do");
            }
            if (!ex_ptr)
                _file_remover.remove();

            // inform about the tip
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
        download_queue &_dlq;
        cardano::network::client &_cnc;
        peer_selection &_peer_selection;
        scheduler &_sched;
        file_remover &_file_remover;
        ed25519::vkey _vk {};
        chunk_registry::file_set _deletable_chunks {};
        alignas(mutex::padding) mutex::unique_lock::mutex_type _epoch_json_cache_mutex {};
        std::map<uint64_t, json::object> _epoch_json_cache {};
        alignas(mutex::padding) mutex::unique_lock::mutex_type _cancel_mutex {};
        std::optional<uint64_t> _cancel_min_offset {};

        static uint64_t _run_max_offset(const json::array &j_epochs, const uint64_t start_offset, const uint64_t max_offset)
        {
            static constexpr uint64_t max_sync_part = static_cast<uint64_t>(1) << 34;
            uint64_t run_max_offset = 0;
            for (size_t epoch = 0; epoch < j_epochs.size(); ++epoch) {
                const auto &j_epoch_meta = j_epochs.at(epoch);
                auto epoch_size = json::value_to<uint64_t>(j_epoch_meta.at("size"));
                if (run_max_offset + epoch_size > start_offset && run_max_offset + epoch_size - start_offset > max_sync_part)
                    break;
                run_max_offset += epoch_size;
            }
            return std::min(run_max_offset, max_offset);
        }

        [[nodiscard]] peer_info _select_peer() const
        {
            static constexpr size_t max_supported_api_version = 2;
            static constexpr size_t max_retries = 10;
            for (size_t n_retries = 0; n_retries < max_retries; ++n_retries) {
                try {
                    auto turbo_host = _peer_selection.next_turbo();
                    logger::info("trying host {} as the compressed blockchain source", turbo_host);
                    auto j_chain = _dlq.fetch_json_signed(fmt::format("http://{}/chain.json", turbo_host), _vk).as_object();
                    if (max_supported_api_version < json::value_to<size_t>(j_chain.at("api").at("version")))
                        throw error("Please, upgrade the application to the latest version. Your current version does not support the latest network protocol version.");
                    return peer_info { std::move(turbo_host), std::move(j_chain) };
                } catch (const std::exception &ex) {
                    logger::warn(ex.what());
                }
            }
            throw error("failed to find an operational peer in {} attempts!", max_retries);
        }

        void _verify_intersection()
        {
            timer t { "verify_intersection", logger::level::debug };
            static constexpr size_t max_intersection_slots = 4000;
            using namespace cardano::network;
            uint64_t max_slot = _cr.max_slot();
            if (max_slot > 0) {
                blockchain_point_list points {};
                for (auto rit = _cr.epochs().rbegin(), rend = _cr.epochs().rend(); rit != rend; ++rit) {
                    if (max_slot - static_cast<uint64_t>(rit->second.last_slot()) > max_intersection_slots)
                        break;
                    points.emplace_back(rit->second.last_block_hash(), rit->second.last_slot());
                }
                for (size_t retry = 0; retry < peer_selection::max_retries; ++retry) {
                    client::find_response resp {};
                    auto peer_addr = _peer_selection.next_cardano();
                    _cnc.find_intersection(peer_addr, points, [&](client::find_response &&r) {
                        resp = std::move(r);
                    });
                    _cnc.process();
                    if (std::holds_alternative<blockchain_point_pair>(resp.res)) {
                        const auto &[point, tip] = std::get<blockchain_point_pair>(resp.res);
                        logger::info("a Cardano network peer confirmed a mutually known block at slot {}", point.slot);
                        return;
                    }
                    if (std::holds_alternative<client::error_msg>(resp.res))
                        logger::error("verify_intersect attempt: {} error: {}", retry, std::get<client::error_msg>(resp.res));
                    logger::warn("a Cardano network peer reports no know intersections within last {} slots; retrying ...", max_intersection_slots);
                }
                throw error("Failed to confirm an intersection point within {} slots with the Cardano network - stopping!", max_intersection_slots);
            }
        }

        std::tuple<std::optional<sync_task>, uint64_t> _find_sync_start_position(const std::string &host, const json::array &j_epochs)
        {
            timer t { "find first epoch to sync" };

            // necessary for robustness since a previous sync could have been interrupted
            auto max_start_offset = _cr.valid_end_offset();
            uint64_t remote_chain_size = 0;
            std::map<uint64_t, std::string> epoch_last_block_hash {};
            uint64_t check_from_epoch = 0;
            uint64_t check_from_offset = 0;
            for (size_t epoch = 0; epoch < j_epochs.size(); ++epoch) {
                const auto &j_epoch_meta = j_epochs[epoch];
                epoch_last_block_hash[epoch] = static_cast<std::string>(j_epoch_meta.at("lastBlockHash").as_string());
                auto epoch_size = json::value_to<uint64_t>(j_epoch_meta.at("size"));
                remote_chain_size += epoch_size;
                if (epoch == check_from_epoch && check_from_offset + epoch_size <= max_start_offset) {
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
                    _epoch_json_cache[check_from_epoch] = _dlq.fetch_json_signed(
                        fmt::format("http://{}/epoch-{}-{}.json", host, check_from_epoch, epoch_last_block_hash.at(check_from_epoch)), _vk).as_object();
                    const auto &j_epoch = _epoch_json_cache.at(check_from_epoch);
                    for (const auto &chunk: j_epoch.at("chunks").as_array()) {
                        auto data_hash = cardano::block_hash::from_hex(json::value_to<std::string_view>(chunk.at("hash")));
                        auto chunk_it = _cr.find(data_hash);
                        if (chunk_it == _cr.chunks().end() || chunk_it->second.offset != check_from_offset || chunk_it->second.end_offset() > max_start_offset)
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
                // delete if the error snapshot with the same name already exist
                std::filesystem::remove(debug_path);
                std::filesystem::rename(save_path, debug_path);
                throw error("can't parse {}: {}", save_path, ex.what());
            }
        }

        void _cancel_tasks(uint64_t new_failure_offset)
        {
            mutex::scoped_lock lk { _cancel_mutex };
            if (!_cancel_min_offset || *_cancel_min_offset > new_failure_offset) {
                const auto num_downloads = _dlq.cancel([new_failure_offset](const auto &req) {
                    return req.priority >= new_failure_offset;
                });
                const auto num_tasks = _sched.cancel([new_failure_offset](const auto &name, const auto &param) {
                    return param && param->type() == typeid(chunk_offset_t) && std::any_cast<chunk_offset_t>(*param) >= new_failure_offset;
                });
                logger::info("validation failure at offset {}: cancelled {} download tasks and {} scheduler tasks",
                    new_failure_offset, num_downloads, num_tasks);
                _cancel_min_offset = new_failure_offset;
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
            std::atomic<uint64_t> downloaded = 0;
            const uint64_t downloaded_base = _cr.num_bytes() - _cr.tx()->start_offset;
            auto &progress = progress::get();
            auto parsed_proc = [&](std::any &&res) {
                if (res.type() == typeid(scheduled_task_error)) {
                    const auto &task = std::any_cast<scheduled_task_error>(res).task();
                    _cancel_tasks(std::any_cast<chunk_offset_t>(*task.param));
                    return;
                }
                updated_chunks.emplace(std::any_cast<std::string>(res));
            };
            auto saved_proc = [&](saved_chunk &&chunk) {
                const auto new_downloaded = atomic_add(downloaded, static_cast<uint64_t>(chunk.info.data_size));
                progress.update("download", downloaded_base + new_downloaded, _cr.tx()->target_offset - _cr.tx()->start_offset);
                _sched.submit(parse_task, 100 * (max_offset - chunk.info.offset) / max_offset, [this, chunk]() {
                    return _parse_local_chunk(chunk.info, chunk.path);
                }, chunk_offset_t { chunk.info.offset });
            };
            _sched.on_result(std::string { daedalus_turbo::validator::validate_leaders_task }, [&](auto &&res) {
                if (res.type() == typeid(scheduled_task_error)) {
                    const auto &task = std::any_cast<scheduled_task_error>(res).task();
                    _cancel_tasks(std::any_cast<chunk_offset_t>(*task.param));
                }
            });
            _sched.on_result(parse_task, parsed_proc);
            {
                timer td { "download all chunks and parse immutable ones" };
                // compute totals before starting the execution to ensure correct progress percentages
                for (const auto &chunk: download_tasks) {
                    const auto data_url = fmt::format("http://{}/compressed/{}", host, chunk.rel_path());
                    const auto save_path = _cr.full_path(chunk.rel_path());
                    if (!std::filesystem::exists(save_path)) {
                        _dlq.download(data_url, save_path, chunk.offset, [this, chunk, saved_proc, save_path](download_queue::result &&res) {
                            if (res) {
                                saved_proc(saved_chunk { save_path, chunk });
                            } else {
                                logger::error("download of {} failed: {}", res.url, *res.error);
                                _cancel_tasks(chunk.offset);
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

        std::map<uint64_t, uint64_t> _download_metadata(const std::string &host, const json::array &j_epochs, const uint64_t max_offset, const uint64_t first_synced_epoch)
        {
            std::map<uint64_t, uint64_t> epoch_offsets {};
            uint64_t current_offset = 0;
            size_t epochs_to_fetch = 0;
            for (size_t epoch = 0; epoch <= j_epochs.size() && current_offset < max_offset; ++epoch) {
                const auto &j_epoch_meta = j_epochs.at(epoch);
                const auto epoch_size = json::value_to<uint64_t>(j_epoch_meta.at("size"));
                const auto epoch_last_block_hash = static_cast<std::string>(j_epoch_meta.at("lastBlockHash").as_string());
                if (epoch >= first_synced_epoch) {
                    epoch_offsets[epoch] = current_offset;
                    mutex::unique_lock lkr { _epoch_json_cache_mutex };
                    if (!_epoch_json_cache.contains(epoch)) {
                        lkr.unlock();
                        ++epochs_to_fetch;
                        const auto epoch_url = fmt::format("http://{}/epoch-{}-{}.json", host, epoch, epoch_last_block_hash);
                        const auto save_path = _cr.full_path(fmt::format("remote/epoch-{}.json", epoch));
                        _dlq.download(epoch_url, save_path, epoch, [this, epoch, save_path](auto &&res) {
                            if (res) {
                                const auto buf = file::read(save_path);
                                mutex::scoped_lock lkw { _epoch_json_cache_mutex };
                                _epoch_json_cache[epoch] = json::parse_signed(buf.span().string_view(), _vk).as_object();
                            }
                        });
                    }
                }
                current_offset += epoch_size;
            }
            if (epochs_to_fetch) {
                logger::info("downloading metadata about {} synchronized epochs", epochs_to_fetch);
                _dlq.process(true, &_sched);
                _sched.process(true);
            }
            return epoch_offsets;
        }

        chunk_registry::file_set _download_data(const std::string &host, const json::array &j_epochs, const uint64_t max_offset, const uint64_t first_synced_epoch)
        {
            timer t { "download data" };
            std::map<uint64_t, uint64_t> epoch_offsets = _download_metadata(host, j_epochs, max_offset, first_synced_epoch);
            std::vector<chunk_registry::chunk_info> download_tasks {};
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

    syncer::syncer(indexer::incremental &cr, daedalus_turbo::http::download_queue &dq, cardano::network::client &cnc, peer_selection &ps, scheduler &sched, file_remover &fr)
        : _impl { std::make_unique<impl>(cr, dq, cnc, ps, sched, fr) }
    {
    }

    syncer::~syncer() =default;

    [[nodiscard]] peer_info syncer::find_peer() const
    {
        return _impl->find_peer();
    }

    void syncer::sync(std::optional<peer_info> peer, const std::optional<uint64_t> max_epoch)
    {
        _impl->sync(std::move(peer), max_epoch);
    }
}