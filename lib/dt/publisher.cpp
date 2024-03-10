/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <sstream>
#include <dt/cardano.hpp>
#include <dt/publisher.hpp>

namespace daedalus_turbo {
    publisher::publisher(scheduler &sched, chunk_registry &cr, const std::string &node_path, bool strict, size_t zstd_max_level)
        : _syncer { sched, cr, node_path, strict, zstd_max_level, volatile_data_lifespan },
            _cr { cr }
    {
    }

    size_t publisher::size() const
    {
        return _cr.num_chunks();
    }

    void publisher::publish()
    {
        timer tc { "publish cycle" };
        try {        
            auto res = _syncer.sync();
            _write_meta();
            _remove_old_meta();
            logger::info("errors: {} updated: {} deleted: {} dist: {}, size: {} max_slot: {} cycle time: {}",
                res.errors.size(), res.updated.size(), res.deleted.size(), _cr.chunks().size(),
                _cr.num_bytes(), _cr.max_slot(), tc.stop(false));
            std::sort(res.updated.begin(), res.updated.end());
            for (const auto &rel_path: res.updated)
                logger::debug("publisher updated: {}", rel_path);
            std::sort(res.deleted.begin(), res.deleted.end());
            for (const auto &rel_path: res.deleted)
                logger::debug("publisher deleted: {}", rel_path);
            std::sort(res.errors.begin(), res.errors.end());
            for (const auto &err: res.errors)
                logger::error("publisher error: {}", err);
        } catch (std::exception &ex) {
            logger::info("dist: {}, size: {} max_slot: {} cycle time: {}",
                    _cr.chunks().size(), _cr.num_bytes(), _cr.max_slot(), tc.stop(false));
            logger::error("publisher run error: {}\n", ex.what());
        }
    }

    void publisher::run(std::chrono::milliseconds update_interval)
    {
        for (;;) {
            auto next_run = std::chrono::system_clock::now() + update_interval;
            publish();
            auto now = std::chrono::system_clock::now();
            if (now < next_run) std::this_thread::sleep_for(next_run - now);
        }
    }

    void publisher::_write_index_html(uint64_t total_size, uint64_t total_compressed_size) const
    {
        for (const auto &entry: std::filesystem::directory_iterator("./publisher/www/")) {
            if (!entry.is_regular_file())
                continue;
            if (entry.path().extension() == ".html") {
                std::string html { file::read(entry.path().string()).span().string_view() };
                cardano::block_hash last_block_hash {};
                cardano::slot last_block_slot {};
                cardano::slot last_chunk_first_slot {};
                auto last_chunk_it = _cr.chunks().rbegin();
                if (last_chunk_it != _cr.chunks().rend()) {
                    last_block_hash = last_chunk_it->second.last_block_hash;
                    last_block_slot = last_chunk_it->second.last_slot;
                    last_chunk_first_slot = last_chunk_it->second.first_slot;
                }
                std::map<std::string, std::string> vars {};
                vars["total_size"] = fmt::format("{:0.1f}", static_cast<double>(total_size) / 1'000'000'000);
                vars["total_compressed_size"] = fmt::format("{:0.1f}", static_cast<double>(total_compressed_size) / 1'000'000'000);
                vars["compression_ratio"] = fmt::format("{:0.2f}", static_cast<double>(total_size) / total_compressed_size);
                vars["last_block_hash"] = fmt::format("{}", last_block_hash);
                vars["last_block_epoch"] = fmt::format("{}", last_block_slot.epoch());
                vars["last_block_epoch_slot"] = fmt::format("{}", last_block_slot.epoch_slot());
                vars["last_block_slot"] = fmt::format("{}", static_cast<uint64_t>(last_block_slot));
                vars["last_block_time"] = fmt::format("{}", last_block_slot.timestamp());
                vars["last_chunk_epoch"] = fmt::format("{}", last_chunk_first_slot.epoch());
                size_t pos = html.find("{{", 0);
                while (pos != html.npos) {
                    pos += 2;
                    size_t pos_end = html.find("}}", pos);
                    if (pos_end == html.npos)
                        break;
                    auto name = html.substr(pos, pos_end - pos);
                    html.replace(pos - 2, pos_end - pos + 4, vars[name]);
                    pos = html.find("{{", pos);
                }
                file::write((_cr.data_dir() / entry.path().filename()).string(), html);
            } else {
                auto dst_path = _cr.data_dir() / entry.path().filename().string();
                // Extra remove since copy_options::overwrite_existing was not working on windows
                std::filesystem::remove(dst_path);
                std::filesystem::copy_file(entry.path(), dst_path, std::filesystem::copy_options::overwrite_existing);
            }
        }
    }

    void publisher::_write_meta() const
    {
        uint64_t total_size = 0;
        uint64_t total_compressed_size = 0;
        json::array j_chain_epochs {};
        for (const auto &[epoch, epoch_meta]: _cr.epochs()) {
            j_chain_epochs.emplace_back(json::object {
                { "lastSlot", epoch_meta.last_slot() },
                { "lastBlockHash", fmt::format("{}", epoch_meta.last_block_hash()) },
                { "size", epoch_meta.size() }
            });
            total_size += epoch_meta.size();
            total_compressed_size += epoch_meta.compressed_size();
            json::array j_chunks {};
            for (const chunk_registry::chunk_info *chunk: epoch_meta.chunks)
                j_chunks.emplace_back(chunk->to_json());
            json::object j_epoch_meta {
                { "lastSlot", (size_t)epoch_meta.last_slot() },
                { "size", epoch_meta.size() },
                { "compressedSize", epoch_meta.compressed_size() },
                { "prevBlockHash", fmt::format("{}", epoch_meta.prev_block_hash()) },
                { "lastBlockHash", fmt::format("{}", epoch_meta.last_block_hash()) },
                { "chunks", std::move(j_chunks) }
            };
            json::save_pretty((_cr.data_dir() / fmt::format("epoch-{}-{}.json", epoch, epoch_meta.last_block_hash())).string(), j_epoch_meta);
        }
        json::save_pretty((_cr.data_dir() / "chain.json").string(), json::object { { "epochs", std::move(j_chain_epochs) } });
        json::save_pretty((_cr.data_dir() / "api.json").string(), json::object {
            { "version", 1 },
            { "metadataLifespanSec", std::chrono::duration<double>(metadata_lifespan).count() },
            { "volatileDataLifespanSec", std::chrono::duration<double>(volatile_data_lifespan).count() }
        });
        _write_index_html(total_size, total_compressed_size);
    }

    void publisher::_remove_old_meta() const
    {
        auto now = std::chrono::system_clock::now();
        auto too_old = now - metadata_lifespan;
        auto file_now = std::chrono::file_clock::now();
        for (auto &entry: std::filesystem::directory_iterator(_cr.data_dir())) {
            auto filename = entry.path().filename().string();
            // consider only the new epoch-<epoch-id>-<last-block-hash>
            if (entry.is_regular_file() && filename.starts_with("epoch-") && filename.ends_with(".json") && filename.size() >= 45) {
                auto entry_sys_time = std::chrono::time_point_cast<std::chrono::system_clock::duration>(entry.last_write_time() - file_now + now);
                if (entry_sys_time < too_old) {
                    logger::trace("found an obsolete metadata file {} - deleting it", entry.path().string());
                    std::filesystem::remove(entry.path());
                }
            }
        }
    }
}