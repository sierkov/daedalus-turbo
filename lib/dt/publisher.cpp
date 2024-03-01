/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <sstream>
#include <dt/cardano.hpp>
#include <dt/publisher.hpp>

namespace daedalus_turbo {
    publisher::publisher(scheduler &sched, chunk_registry &cr, const std::string &node_path, bool strict, size_t zstd_max_level)
        : _syncer { sched, cr, node_path, strict, zstd_max_level, std::chrono::seconds { 6 * 3600 } },
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
        struct epoch_info {
            size_t num_blocks = 0;
            uint64_t data_size = 0;
            uint64_t compressed_size = 0;
            cardano::slot first_slot {};
            cardano::slot last_slot {};
            cardano_hash_32 prev_block_hash {};
            cardano_hash_32 last_block_hash {};
            std::vector<std::reference_wrapper<const chunk_registry::chunk_info>> chunks {};
        };
        std::map<uint64_t, epoch_info> epochs {};
        uint64_t total_size = 0;
        uint64_t total_compressed_size = 0;
        for (const auto &[last_offset, dist_info]: _cr.chunks()) {
            uint64_t epoch = dist_info.first_slot.epoch();
            auto &epoch_data = epochs[epoch];
            epoch_data.num_blocks += dist_info.num_blocks;
            epoch_data.data_size += dist_info.data_size;
            epoch_data.compressed_size += dist_info.compressed_size;
            epoch_data.chunks.emplace_back(std::ref(dist_info));
            if (epoch_data.last_slot < dist_info.last_slot) {
                epoch_data.last_slot = dist_info.last_slot;
                epoch_data.last_block_hash = dist_info.last_block_hash;
            }
            if (epoch_data.first_slot == 0 || epoch_data.first_slot > dist_info.first_slot) {
                epoch_data.first_slot = dist_info.first_slot;
                epoch_data.prev_block_hash = dist_info.prev_block_hash;
            }
            total_size += dist_info.data_size;
            total_compressed_size += dist_info.compressed_size;
        }
        static constexpr size_t num_groups = 32;
        size_t max_group_size = (total_size + num_groups - 1) / num_groups; 
        std::ostringstream group_s {};
        group_s << "[\n";
        uint64_t group_size = 0;
        uint64_t group_compressed_size = 0;
        uint64_t group_blocks = 0;
        cardano_hash_32 group_prev_block_hash {};
        json::array group_epochs {};
        for (auto epoch_it = epochs.begin(); epoch_it != epochs.end();) {
            auto &[epoch, epoch_data] = *epoch_it;
            std::sort(epoch_data.chunks.begin(), epoch_data.chunks.end(),
                [](const chunk_registry::chunk_info &a, const chunk_registry::chunk_info &b) { return a.last_slot < b.last_slot; });
            json::array chunks {};
            for (const chunk_registry::chunk_info &chunk: epoch_data.chunks)
                chunks.emplace_back(chunk.to_json());
            json::object epoch_meta {
                { "lastSlot", (size_t)epoch_data.last_slot },
                { "size", epoch_data.data_size },
                { "compressedSize", epoch_data.compressed_size },
                { "prevBlockHash", fmt::format("{}", epoch_data.prev_block_hash.span()) },
                { "lastBlockHash", fmt::format("{}", epoch_data.last_block_hash.span()) },
                { "chunks", std::move(chunks) }
            };
            // temporary keep both the old and the name formats
            file::write((_cr.data_dir() / fmt::format("epoch-{}.json", epoch)).string(), json::serialize(epoch_meta));
            file::write((_cr.data_dir() / fmt::format("epoch-{}-{}.json", epoch, epoch_data.last_block_hash)).string(), json::serialize(epoch_meta));
            if (group_epochs.empty())
                group_prev_block_hash = epoch_data.prev_block_hash;
            group_epochs.emplace_back(json::object {
                { "id", epoch },
                { "size", epoch_data.data_size },
                { "lastBlockHash", fmt::format("{}", epoch_data.last_block_hash) }
            });
            group_size += epoch_data.data_size;
            group_compressed_size += epoch_data.compressed_size;
            group_blocks += epoch_data.num_blocks;
            epoch_it++;
            if (epoch_it == epochs.end() || group_size >= max_group_size) {
                group_s << "  " << json::serialize(json::object {
                    { "lastSlot", (size_t)epoch_data.last_slot },
                    { "numBlocks", group_blocks },
                    { "size", group_size },
                    { "compressedSize", group_compressed_size },
                    { "prevBlockHash", fmt::format("{}", group_prev_block_hash.span()) },
                    { "lastBlockHash", fmt::format("{}", epoch_data.last_block_hash.span()) },
                    { "epochs", std::move(group_epochs) }
                });
                if (epoch_it != epochs.end())
                    group_s << ',';
                group_s << '\n';
                group_size = 0;
                group_compressed_size = 0;
                group_blocks = 0;
                group_epochs.clear();
            }
        }
        group_s << "]\n";
        file::write((_cr.data_dir() / "chain.json").string(), group_s.str());
        _write_index_html(total_size, total_compressed_size);
    }

    void publisher::_remove_old_meta() const
    {
        static const std::chrono::seconds delete_delay { 3600 };
        auto now = std::chrono::system_clock::now();
        auto too_old = now - delete_delay;
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