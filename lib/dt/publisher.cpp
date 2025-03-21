/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano.hpp>
#include <dt/config.hpp>
#include <dt/publisher.hpp>
#include <dt/sync/local.hpp>
#include <dt/timer.hpp>

namespace daedalus_turbo {
    struct publisher::impl {
        impl(chunk_registry &cr, const std::string &node_dir, const buffer &sk, size_t zstd_max_level=22, file_remover &fr=file_remover::get())
            : _syncer { cr, zstd_max_level, volatile_data_lifespan }, _node_dir { node_dir },
              _sk { sk }, _cr { cr }, _file_remover { fr }, _turbo_hosts(configs_dir::get().at("turbo").at("hosts").as_array())
        {
        }

        size_t size() const
        {
            return _cr.num_chunks();
        }

        void publish()
        {
            timer tc { "publish cycle" };
            try {
                const auto peer = _syncer.find_peer(_node_dir);
                _syncer.sync(peer, {}, sync::validation_mode_t::none);
                _write_meta();
                _file_remover.mark_old_files(_cr.data_dir(), metadata_lifespan);
                logger::info("publisher cycle time: {} sec", tc.stop(false));
            } catch (std::exception &ex) {
                logger::info("dist: {}, size: {} max_slot: {} cycle time: {}",
                        _cr.chunks().size(), _cr.num_bytes(), _cr.max_slot(), tc.stop(false));
                logger::error("publisher run error: {}\n", ex.what());
            }
        }
    private:
        static constexpr std::chrono::seconds metadata_lifespan { 3600 };
        static constexpr std::chrono::seconds volatile_data_lifespan { 6 * 3600 };

        sync::local::syncer _syncer;
        const std::filesystem::path _node_dir;
        ed25519::skey _sk {};
        chunk_registry &_cr;
        file_remover &_file_remover;
        json::array _turbo_hosts;

        void _write_index_html(const uint64_t total_size, const uint64_t total_compressed_size) const
        {
            for (const auto &entry: std::filesystem::directory_iterator("./publisher/www/")) {
                if (!entry.is_regular_file())
                    continue;
                if (entry.path().extension() == ".html") {
                    std::string html { file::read(entry.path().string()).str() };
                    cardano::block_hash last_block_hash {};
                    auto last_block_slot = _cr.make_slot(0);
                    auto last_chunk_first_slot = _cr.make_slot(0);
                    auto last_chunk_it = _cr.chunks().rbegin();
                    if (last_chunk_it != _cr.chunks().rend()) {
                        last_block_hash = last_chunk_it->second.last_block_hash;
                        last_block_slot = _cr.make_slot(last_chunk_it->second.last_slot);
                        last_chunk_first_slot = _cr.make_slot(last_chunk_it->second.first_slot);
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

        void _write_peers() const
        {
            json::object j_peers { { "hosts", _turbo_hosts } };
            json::save_pretty_signed((_cr.data_dir() / "peers.json").string(), j_peers, _sk);
        }

        void _write_meta() const
        {
            uint64_t total_size = 0;
            uint64_t total_compressed_size = 0;
            json::array j_chain_epochs {};
            for (const auto &[epoch, epoch_meta]: _cr.epochs()) {
                j_chain_epochs.emplace_back(json::object {
                    { "lastSlot", epoch_meta.last_slot() },
                    { "lastBlockHash", fmt::format("{}", epoch_meta.last_block_hash()) },
                    { "size", epoch_meta.size() },
                    { "era", epoch_meta.era() }
                });
                total_size += epoch_meta.size();
                total_compressed_size += epoch_meta.compressed_size();
                json::array j_chunks {};
                for (const chunk_registry::chunk_info *chunk: epoch_meta.chunks())
                    j_chunks.emplace_back(chunk->to_json());
                json::object j_epoch_meta {
                    { "lastSlot", (size_t)epoch_meta.last_slot() },
                    { "size", epoch_meta.size() },
                    { "compressedSize", epoch_meta.compressed_size() },
                    { "prevBlockHash", fmt::format("{}", epoch_meta.prev_block_hash()) },
                    { "lastBlockHash", fmt::format("{}", epoch_meta.last_block_hash()) },
                    { "chunks", std::move(j_chunks) }
                };
                json::save_pretty_signed((_cr.data_dir() / fmt::format("epoch-{}-{}.json", epoch, epoch_meta.last_block_hash())).string(), j_epoch_meta, _sk);
            }
            json::object meta {
                { "api", json::object {
                    { "version", 3 },
                    { "metadataLifespanSec", std::chrono::duration<int64_t>(metadata_lifespan).count() },
                    { "volatileDataLifespanSec", std::chrono::duration<int64_t>(volatile_data_lifespan).count() }
                    }
                },
                { "epochs", std::move(j_chain_epochs) }
            };
            json::save_pretty_signed((_cr.data_dir() / "chain.json").string(), meta, _sk);
            _write_index_html(total_size, total_compressed_size);
            _write_peers();
        }
    };

    publisher::publisher(chunk_registry &cr, const std::string &node_path, const buffer &sk, size_t zstd_max_level, file_remover &fr)
        : _impl { std::make_unique<impl>(cr, node_path, sk, zstd_max_level, fr) }
    {
    }

    publisher::~publisher() =default;

    size_t publisher::size() const
    {
        return _impl->size();
    }

    void publisher::publish()
    {
        return _impl->publish();
    }
}