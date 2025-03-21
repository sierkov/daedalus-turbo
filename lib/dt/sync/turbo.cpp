/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano.hpp>
#include <dt/cardano/common/network.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/config.hpp>
#include <dt/http/download-queue.hpp>
#include <dt/sync/turbo.hpp>

namespace daedalus_turbo::sync::turbo {
    peer_info::peer_info(const std::string &host, json::object &&chain,
            const cardano::optional_point &tip, const cardano::optional_point &isect)
        : _host { host }, _chain { std::move(chain) }, _tip { tip }, _isect { isect }
    {
    }

    struct syncer::impl {
        impl(syncer &parent, daedalus_turbo::http::download_queue &dq)
            : _parent { parent }, _dlq { dq },
                _vk { ed25519::vkey::from_hex(static_cast<std::string_view>(_parent.local_chain().configs().at("turbo").at("vkey").as_string())) }
        {
        }

        std::shared_ptr<sync::peer_info> find_peer(std::optional<std::string> host) const
        {
            if (!host)
                host = _parent.peer_list().next_turbo();
            static constexpr size_t max_supported_api_version = 3;
            auto chain = _dlq.fetch_json_signed(fmt::format("http://{}/chain.json", *host), _vk).as_object();;
            const auto host_api_version = json::value_to<size_t>(chain.at("api").at("version"));
            if (max_supported_api_version < host_api_version)
                throw error(fmt::format("Please, upgrade. {} has API version {} while your client supports only version {}", *host, host_api_version, max_supported_api_version));
            return _peer_find_intersection(*host, std::move(chain));
        }

        void sync_attempt(peer_info &peer, cardano::optional_slot max_slot)
        {
            timer t { "http synchronization" };
            _cancel_min_offset.reset();
            if (const auto &j_epochs = peer.chain().at("epochs").as_array(); j_epochs.empty())
                throw error("Remote turbo node reports and empty chain!");
            if (peer.intersection() < peer.tip()) {
                chunk_registry::file_set updated_chunks {};
                updated_chunks = _download_data(peer, max_slot);
                for (auto &&path: updated_chunks)
                    _parent.local_chain().remover().unmark(path);
            }
        }

        void cancel_tasks(const uint64_t max_valid_offset)
        {
            mutex::scoped_lock lk { _cancel_mutex };
            if (!_cancel_min_offset || *_cancel_min_offset > max_valid_offset) {
                const auto num_downloads = _dlq.cancel([max_valid_offset](const auto &req) {
                    return req.priority >= max_valid_offset;
                });
                const auto num_tasks = _parent.local_chain().sched().cancel([max_valid_offset](const auto &, const auto &param) {
                    return param && param->type() == typeid(chunk_offset_t) && std::any_cast<chunk_offset_t>(*param) >= max_valid_offset;
                });
                logger::warn("validation failure at offset {}: cancelled {} download tasks and {} scheduler tasks",
                    max_valid_offset, num_downloads, num_tasks);
                _cancel_min_offset = max_valid_offset;
            }
        }
    private:
        using download_queue = daedalus_turbo::http::download_queue;
        using download_task_list = std::vector<chunk_registry::chunk_info>;
        struct sync_task {
            uint64_t start_epoch = 0;
            uint64_t start_offset = 0;
        };

        syncer &_parent;
        download_queue &_dlq;
        ed25519::vkey _vk {};
        chunk_registry::file_set _deletable_chunks {};
        mutex::unique_lock::mutex_type _epoch_json_cache_mutex alignas(mutex::alignment) {};
        mutable std::map<uint64_t, json::object> _epoch_json_cache {};
        mutex::unique_lock::mutex_type _cancel_mutex alignas(mutex::alignment) {};
        std::optional<uint64_t> _cancel_min_offset {};

        std::shared_ptr<sync::peer_info> _peer_find_intersection(const std::string &host, json::object &&chain) const
        {
            _epoch_json_cache.clear();
            // necessary for robustness since a previous sync could have been interrupted
            const auto &j_epochs = chain.at("epochs").as_array();
            std::map<uint64_t, cardano::block_hash> epoch_last_block_hash {};
            cardano::optional_point tip {};
            cardano::optional_point isect {};
            if (!j_epochs.empty()) {
                tip.emplace(
                    cardano::block_hash::from_hex(json::value_to<std::string>(j_epochs.back().at("lastBlockHash"))),
                    json::value_to<uint64_t>(j_epochs.back().at("lastSlot"))
                );
                uint64_t remote_chain_size = 0;
                for (uint64_t epoch = 0; epoch < j_epochs.size(); ++epoch) {
                    const auto &j_epoch = j_epochs.at(epoch);
                    const auto &last_block_hash = epoch_last_block_hash[epoch] = cardano::block_hash::from_hex(json::value_to<std::string>(j_epoch.at("lastBlockHash")));
                    const auto last_slot = json::value_to<uint64_t>(j_epoch.at("lastSlot"));
                    const auto data_size = json::value_to<uint64_t>(j_epoch.at("size"));
                    remote_chain_size += data_size;
                    if (const auto block = _parent.local_chain().find_block_by_slot_no_throw(last_slot, last_block_hash); block)
                        isect.emplace(block->point());
                }
                tip->end_offset = remote_chain_size;
                const auto test_epoch = isect ? _parent.local_chain().make_slot(isect->slot).epoch() : 0;
                const auto &j_epoch = _epoch_json_cache[test_epoch] = _dlq.fetch_json_signed(
                    fmt::format("http://{}/epoch-{}-{}.json", host, test_epoch, epoch_last_block_hash.at(test_epoch)), _vk).as_object();
                for (const auto &j_chunk: j_epoch.at("chunks").as_array()) {
                    const auto last_block_hash = cardano::block_hash::from_hex(json::value_to<std::string_view>(j_chunk.at("lastBlockHash")));
                    const auto last_slot = json::value_to<uint64_t>(j_chunk.at("lastSlot"));
                    if (const auto block = _parent.local_chain().find_block_by_slot_no_throw(last_slot, last_block_hash); block)
                        isect.emplace(block->point());
                    else
                        break;
                }
            }
            return std::make_shared<peer_info>(host, std::move(chain), tip, isect);
        }

        std::string _parse_local_chunk(const chunk_registry::chunk_info &chunk, const std::string &save_path)
        {
            try {
                return _parent.local_chain().add(chunk.offset, save_path);
            } catch (std::exception &ex) {
                std::filesystem::path orig_path { save_path };
                auto debug_path = _parent.local_chain().full_path(fmt::format("error/{}", orig_path.filename().string()));
                logger::warn("moving an unparsable chunk {} to {}", save_path, debug_path);
                // delete if the error snapshot with the same name already exist
                std::filesystem::remove(debug_path);
                std::filesystem::rename(save_path, debug_path);
                throw error(fmt::format("can't parse {}: {}", save_path, ex.what()));
            }
        }

        void _download_chunks(const peer_info &peer, uint64_t max_offset, const download_task_list &download_tasks, chunk_registry::file_set &updated_chunks)
        {
            timer t { fmt::format("download chunks: {}", download_tasks.size()) };
            struct saved_chunk {
                std::string path {};
                chunk_registry::chunk_info info {};
            };
            const std::string parse_task = "parse";
            auto &progress = progress::get();
            auto parsed_proc = [&](std::any &&res) {
                if (res.type() == typeid(scheduled_task_error)) {
                    const auto task = std::any_cast<scheduled_task_error>(std::move(res)).task();
                    cancel_tasks(std::any_cast<chunk_offset_t>(*task.param));
                    return;
                }
                updated_chunks.emplace(std::any_cast<std::string>(res));
            };
            const auto num_downloaded = std::make_shared<std::atomic_size_t>(0);
            auto saved_proc = [&, num_downloaded](saved_chunk &&chunk) {
                const auto & tx = _parent.local_chain().tx();
                if (tx->target->end_offset) {
                    const auto num_bytes = num_downloaded->fetch_add(chunk.info.data_size, std::memory_order_relaxed) + chunk.info.data_size;
                    progress.update("download", num_bytes, tx->target_offset() - tx->start_offset());
                } else {
                    progress.update("download", chunk.info.last_slot - tx->start_slot(), tx->target_slot() - tx->start_slot());
                }
                _parent.local_chain().sched().submit(parse_task, 100 * (max_offset - chunk.info.offset) / max_offset, [this, chunk]() {
                    return _parse_local_chunk(chunk.info, chunk.path);
                }, chunk_offset_t { chunk.info.offset });
            };
            _parent.local_chain().sched().on_result(parse_task, parsed_proc);
            {
                timer td { "download all chunks and parse immutable ones" };
                // compute totals before starting the execution to ensure correct progress percentages
                for (const auto &chunk: download_tasks) {
                    const auto data_url = fmt::format("http://{}/compressed/{}", peer.host(), chunk.rel_path());
                    const auto save_path = _parent.local_chain().full_path(chunk.rel_path());
                    if (!std::filesystem::exists(save_path)) {
                        _dlq.download(data_url, save_path, chunk.offset, [this, chunk, saved_proc, save_path](download_queue::result &&res) {
                            if (res) {
                                saved_proc(saved_chunk { save_path, chunk });
                            } else {
                                logger::error("download of {} failed: {}", res.url, *res.error);
                                cancel_tasks(chunk.offset);
                            }
                        });
                    } else {
                        saved_proc(saved_chunk { save_path, chunk });
                    }
                }
                _dlq.process(true, &_parent.local_chain().sched());
                _parent.local_chain().sched().process(true);
            }
        }

        std::map<uint64_t, uint64_t> _download_metadata(const peer_info &peer, const std::optional<uint64_t> max_slot)
        {
            std::map<uint64_t, uint64_t> epoch_offsets {};
            uint64_t current_offset = 0;
            size_t epochs_to_fetch = 0;
            uint64_t first_synced_epoch = 0;
            if (const auto &isect = peer.intersection(); isect)
                first_synced_epoch = _parent.local_chain().make_slot(isect->slot).epoch();
            const auto &j_epochs = peer.chain().at("epochs").as_array();
            for (size_t epoch = 0; epoch < j_epochs.size(); ++epoch) {
                const auto &j_epoch = j_epochs.at(epoch);
                const auto epoch_size = json::value_to<uint64_t>(j_epoch.at("size"));
                const auto epoch_last_block_hash = json::value_to<std::string>(j_epoch.at("lastBlockHash"));
                const auto epoch_last_slot = json::value_to<uint64_t>(j_epoch.at("lastSlot"));
                if (epoch >= first_synced_epoch && (!max_slot ||epoch_last_slot <= *max_slot)) {
                    epoch_offsets[epoch] = current_offset;
                    mutex::unique_lock lkr { _epoch_json_cache_mutex };
                    if (!_epoch_json_cache.contains(epoch)) {
                        lkr.unlock();
                        ++epochs_to_fetch;
                        const auto epoch_url = fmt::format("http://{}/epoch-{}-{}.json", peer.host(), epoch, epoch_last_block_hash);
                        const auto save_path = _parent.local_chain().full_path(fmt::format("remote/epoch-{}.json", epoch));
                        _dlq.download(epoch_url, save_path, epoch, [this, epoch, save_path](auto &&res) {
                            if (res) {
                                const auto buf = file::read(save_path);
                                mutex::scoped_lock lkw { _epoch_json_cache_mutex };
                                _epoch_json_cache[epoch] = json::parse_signed(buf.str(), _vk).as_object();
                            }
                        });
                    }
                }
                current_offset += epoch_size;
            }
            if (epochs_to_fetch) {
                logger::info("downloading metadata about {} synchronized epochs", epochs_to_fetch);
                _dlq.process(true, &_parent.local_chain().sched());
                _parent.local_chain().sched().process(true);
            }
            return epoch_offsets;
        }

        chunk_registry::file_set _download_data(const peer_info &peer, const std::optional<uint64_t> &max_slot)
        {
            timer t { "download data" };
            std::map<uint64_t, uint64_t> epoch_offsets = _download_metadata(peer, max_slot);
            std::vector<chunk_registry::chunk_info> download_tasks {};
            std::optional<uint64_t> max_offset {};
            uint64_t last_offset = 0;
            for (const auto &[epoch_id, epoch_start_offset]: epoch_offsets) {
                if (!_epoch_json_cache.contains(epoch_id))
                    throw error(fmt::format("internal error: epoch cache is missing epoch {} sync start: {}", epoch_id, peer.intersection()));
                uint64_t chunk_start_offset = epoch_start_offset;
                const auto &j_epoch = _epoch_json_cache.at(epoch_id);
                for (const auto &j_chunk: j_epoch.at("chunks").as_array()) {
                    auto chunk = chunk_registry::chunk_info::from_json(j_chunk.as_object());
                    auto chunk_size = chunk.data_size;
                    if (max_slot && chunk.last_slot > *max_slot) {
                        max_offset = chunk_start_offset;
                        break;
                    }
                    const auto chunk_it = _parent.local_chain().find_data_hash_it(chunk.data_hash);
                    if (chunk_it == _parent.local_chain().chunks().end()) {
                        chunk.offset = chunk_start_offset;
                        download_tasks.emplace_back(std::move(chunk));
                    } else if (chunk_it->second.data_size != chunk_size || chunk_it->second.offset != chunk_start_offset) {
                        throw error(fmt::format("remote chunk offset: {} and size: {} does not match the local ones: {} and {}",
                            chunk_start_offset, chunk_size, chunk_it->second.offset, chunk_it->second.data_size));
                    }
                    chunk_start_offset += chunk_size;
                }
                if (max_offset)
                    break;
                last_offset += json::value_to<uint64_t>(j_epoch.at("size"));
            }
            if (!max_offset)
                max_offset = last_offset;
            chunk_registry::file_set updated_chunks {};
            logger::info("preparing the updated chunks to be downloaded, validated, and indexed: {}", download_tasks.size());
            _download_chunks(peer, *max_offset, download_tasks, updated_chunks);
            return updated_chunks;
        }
    };

    syncer::syncer(chunk_registry &cr, peer_selection &ps, daedalus_turbo::http::download_queue &dq)
        : sync::syncer { cr, ps }, _impl { std::make_unique<impl>(*this, dq) }
    {
    }

    syncer::~syncer() =default;

    [[nodiscard]] std::shared_ptr<sync::peer_info> syncer::find_peer(const std::optional<std::string> &host) const
    {
        return _impl->find_peer(host);
    }

    void syncer::cancel_tasks(const uint64_t max_valid_offset)
    {
        _impl->cancel_tasks(max_valid_offset);
    }

    void syncer::sync_attempt(sync::peer_info &peer, const cardano::optional_slot max_slot)
    {
        _impl->sync_attempt(dynamic_cast<peer_info &>(peer), max_slot);
    }
}