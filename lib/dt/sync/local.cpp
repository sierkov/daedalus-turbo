/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cbor/zero.hpp>
#include <dt/sync/local.hpp>

namespace daedalus_turbo::sync::local {
    static cardano::point chunk_tip(const std::string &path, const uint64_t offset, const cardano::config &cfg)
    {
        const auto data = file::read(path);
        const auto block_data = cbor::zero::parse_all(data);
        if (!block_data.empty()) [[likely]] {
            // reparse because the cardano parsing code supports only the older cbor parser now
            const auto last_tuple = cbor::parse(block_data.back().raw_span());
            const auto blk = cardano::make_block(last_tuple,
                offset + block_data.back().raw_span().data() - data.data(), cfg);
            return { blk->hash(), blk->slot(), blk->height(), blk->end_offset() };
        }
        throw error(fmt::format("empty chunk: {}", path));
    }

    static bool is_volatile_rel_path(const std::string &rel_path)
    {
        static const std::string_view match { "volatile" };
        return rel_path.size() > match.size() && rel_path.substr(0, match.size()) == match;
    }

    cardano::point chunk_update::last_point(const cardano::config &cfg) const
    {
        return chunk_tip(path, offset, cfg);
    }

    struct syncer::impl {
        struct sync_res {
            std::vector<std::string> updated {};
            std::vector<std::string> errors {};
            uint64_t last_slot = 0;
        };

        impl(syncer &parent, const size_t zstd_max_level, const std::chrono::seconds del_delay)
            : _parent { parent }, _delete_delay { del_delay },
                _zstd_level_immutable { std::min(static_cast<size_t>(22), zstd_max_level) },
                _zstd_level_volatile { std::min(static_cast<size_t>(3), zstd_max_level) }
        {
            _parent.local_chain().remover().remove_delay(del_delay);
            logger::debug("sync::local::syncer zstd (level-immutable: {} level-volatile: {})", _zstd_level_immutable, _zstd_level_volatile);
        }

        [[nodiscard]] std::shared_ptr<sync::peer_info> find_peer(const std::filesystem::path &node_dir) const
        {
            const auto immutable_dir = node_dir / "immutable";
            const auto volatile_dir = node_dir / "volatile";
            const auto converted_dir = node_dir / "volatile-dt";
            logger::info("analyzing available chunks");
            auto [source_end_offset, avail_chunks] = _find_avail_chunks(immutable_dir.string(), ".chunk");
            auto [volatile_size_in, avail_volatile] = _find_avail_chunks(volatile_dir.string(), ".dat");
            // move the last immutable chunk to volatile since they need to be parsed together
            if (!avail_volatile.empty()) {
                if (!avail_chunks.empty()) {
                    auto &last_immutable = avail_chunks.back();
                    source_end_offset -= last_immutable.data_size;
                    volatile_size_in += last_immutable.data_size;
                    avail_volatile.insert(avail_volatile.begin(), last_immutable);
                    avail_chunks.pop_back();
                }
                cardano::block_hash volatile_prev_hash = _parent.local_chain().config().byron_genesis_hash;
                if (!avail_chunks.empty()) {
                    const auto imm_tip = avail_chunks.back().last_point(_parent.local_chain().config());
                    volatile_prev_hash = imm_tip.hash;
                }
                source_end_offset += _convert_volatile(converted_dir, avail_chunks, source_end_offset, avail_volatile, volatile_size_in, volatile_prev_hash);
            }

            cardano::optional_point isect {};
            updated_chunk_list updated_chunks {};
            {
                uint64_t source_offset = 0;
                const chunk_update *last_matching_chunk = nullptr;
                for (auto &update: avail_chunks) {
                    update.offset = source_offset;
                    const auto chunk_ptr = _parent.local_chain().find_chunk_by_offset_no_throw(update.offset);
                    if (!updated_chunks.empty() || !chunk_ptr || chunk_ptr->offset != update.offset || chunk_ptr->data_size != update.data_size) {
                        if (chunk_ptr)
                            logger::warn("chunk {} is different source: (offset: {} size: {}) known: (offset: {} size: {})",
                                update.path, update.offset, update.data_size, chunk_ptr->offset, chunk_ptr->data_size);
                        updated_chunks.emplace_back(update);
                    } else if (updated_chunks.empty()) {
                        last_matching_chunk = &update;
                    }
                    source_offset += update.data_size;
                }
                if (last_matching_chunk)
                    isect = last_matching_chunk->last_point(_parent.local_chain().config());
            }

            cardano::optional_point tip {};
            if (!avail_chunks.empty())
                tip = avail_chunks.back().last_point(_parent.local_chain().config());
            // update source chunks to include only actually needed files
            return std::make_unique<peer_info>(node_dir, std::move(updated_chunks), source_end_offset, tip, isect);
        }

        void cancel_tasks(const uint64_t /*min_invalid_offset*/)
        {
        }

        void sync_attempt(peer_info &peer, const cardano::optional_slot max_slot)
        {
            timer t { "sync::local::sync" };
            std::vector<std::string> errors {};
            std::vector<std::string> updated {};
            _refresh_chunks(peer, updated, errors, max_slot);
            sync_res res { std::move(updated), std::move(errors), _parent.local_chain().max_slot() };
            std::ranges::sort(res.updated);
            std::ranges::sort(res.errors);

            logger::info("errors: {} updated: {} dist: {}, size: {} max_slot: {}",
                    res.errors.size(), res.updated.size(), _parent.local_chain().num_chunks(),
                    _parent.local_chain().num_bytes(), _parent.local_chain().max_slot());
            std::sort(res.updated.begin(), res.updated.end());
            for (const auto &rel_path: res.updated)
                logger::debug("publisher updated: {}", rel_path);
            std::sort(res.errors.begin(), res.errors.end());
            for (const auto &err: res.errors)
                logger::error("publisher error: {}", err);
        }
    private:
        struct analyze_res {
            std::string path {};
            std::string rel_path {};
            bool updated = false;
        };
        using block_hash_list = std::vector<cardano_hash_32>;
        using block_followers_map = std::map<cardano_hash_32, block_hash_list>;

        syncer &_parent;
        std::chrono::seconds _delete_delay;
        std::map<std::string, std::chrono::time_point<std::chrono::system_clock>> _deleted_chunks {};
        const size_t _zstd_level_immutable;
        const size_t _zstd_level_volatile;

        static std::time_t _to_time_t(const std::filesystem::file_time_type &tp)
        {
            using namespace std::chrono;
            auto sc_tp = time_point_cast<system_clock::duration>(tp - file_clock::now() + system_clock::now());
            return system_clock::to_time_t(sc_tp);
        }

        analyze_res _analyze_local_chunk(const std::filesystem::path &node_dir, const chunk_update &update)
        {
            timer t { fmt::format("process chunk path: {} offset: {} size: {}", update.path, update.offset, update.data_size), logger::level::trace };
            uint8_vector chunk {};
            file::read(update.path, chunk);
            if (chunk.size() != update.data_size)
                throw error(fmt::format("file changed: {} new size: {} recorded size: {}!", update.path, chunk.size(), update.data_size));
            const auto rel_path = std::filesystem::relative(std::filesystem::canonical(update.path), node_dir).string();
            const auto data_hash = blake2b<cardano::block_hash>(chunk);
            const auto dist_it = _parent.local_chain().find_data_hash_it(data_hash);
            // even if the data is the same, the offset change requires reparse/reindex
            if (dist_it != _parent.local_chain().chunks().end() && dist_it->second.offset == update.offset)
                return analyze_res { std::move(update.path), std::move(rel_path), false };
            std::string local_path;
            if (dist_it == _parent.local_chain().chunks().end()) {
                uint8_vector compressed {};
                zstd::compress(compressed, chunk, is_volatile_rel_path(rel_path) ? _zstd_level_volatile : _zstd_level_immutable);
                local_path = _parent.local_chain().full_path(storage::chunk_info::rel_path_from_hash(data_hash));
                file::write(local_path, compressed);
            } else {
                local_path = _parent.local_chain().full_path(dist_it->second.rel_path());
            }
            _parent.local_chain().add(update.offset, local_path);
            return analyze_res { std::move(update.path), std::move(rel_path), true };
        }

        void _refresh_chunks(peer_info &peer, std::vector<std::string> &updated, std::vector<std::string> &errors, const cardano::optional_slot &max_slot)
        {
            timer t { "check chunks for updates", logger::level::debug };
            if (!peer.updated_chunks().empty()) {
                const auto updated_start_offset = peer.updated_chunks().front().offset;
                if (updated_start_offset != _parent.local_chain().num_bytes())
                    throw error(fmt::format("internal error: updated chunk offset {} is greater than the compressed data size {}!",
                                updated_start_offset, _parent.local_chain().num_bytes()));
                logger::info("update_start_offset: {}", updated_start_offset);
                static const std::string task_name { "import-chunk" };
                timer t { "process updated chunks" };
                _parent.local_chain().sched().on_result(task_name, [&](auto &&res) {
                    if (res.type() == typeid(scheduled_task_error)) {
                        errors.emplace_back(std::any_cast<scheduled_task_error>(res).what());
                        return;
                    }
                    if (auto &&a_res = std::any_cast<std::optional<analyze_res>>(res); a_res && a_res->updated)
                        updated.emplace_back(a_res->rel_path);
                });
                const auto max_offset = _parent.local_chain().tx()->target_offset();
                for (const auto &update: peer.updated_chunks())
                    _parent.local_chain().sched().submit(task_name, 100 * static_cast<int>((max_offset - update.offset) / max_offset), [&] {
                        if (!max_slot || update.last_point(_parent.local_chain().config()).slot <= *max_slot)
                            return std::optional<analyze_res> { _analyze_local_chunk(peer.node_dir(), update) };
                        return std::optional<analyze_res> { };
                    });
                _parent.local_chain().sched().process(true);
            }
            logger::debug("after refresh: max source offset: {} chunk-registry size: {}", peer.num_bytes(), _parent.local_chain().num_bytes());
        }

        static std::pair<uint64_t, updated_chunk_list> _find_avail_chunks(const std::string &dir_path, const std::string &ext)
        {
            uint64_t total_size = 0;
            updated_chunk_list avail_chunks {};
            timer t { fmt::format("analyze files in {}", dir_path), logger::level::trace };
            for (const auto &entry: std::filesystem::directory_iterator(dir_path)) {
                if (!entry.is_regular_file() || entry.file_size() == 0 || entry.path().extension() != ext)
                    continue;
                auto path = std::filesystem::weakly_canonical(entry.path()).string();
                avail_chunks.emplace_back(path, _to_time_t(entry.last_write_time()), entry.file_size());
                total_size += entry.file_size();
            }
            std::sort(avail_chunks.begin(), avail_chunks.end());
            return std::make_pair(total_size, std::move(avail_chunks));
        }

        static block_hash_list _longest_chain(const cardano::block_hash &start_hash, const block_followers_map &followers)
        {
            map<cardano::block_hash, block_hash_list> lengths {};
            block_hash_list search_list {};
            search_list.emplace_back(start_hash);
            while (!search_list.empty()) {
                const auto &search_hash = search_list.back();
                auto [l_search_it, created] = lengths.try_emplace(search_hash);
                const auto f_it = followers.find(search_hash);
                if (created) {
                    if (f_it != followers.end()) {
                        for (const auto &next_hash: f_it->second) {
                            const auto l_next_it = lengths.find(next_hash);
                            if (l_next_it == lengths.end())
                                search_list.emplace_back(next_hash);
                        }
                    }
                } else {
                    if (f_it != followers.end()) {
                        for (const auto &next_hash: f_it->second) {
                            const auto l_next_it = lengths.find(next_hash);
                            if (l_next_it != lengths.end() && l_search_it->second.size() < 1 + l_next_it->second.size()) {
                                l_search_it->second.clear();
                                l_search_it->second.reserve(1 + l_next_it->second.size());
                                l_search_it->second.emplace_back(l_next_it->first);
                                for (const auto &hash: l_next_it->second)
                                    l_search_it->second.emplace_back(hash);
                            }
                        }
                    }
                    search_list.pop_back();
                }
            }
            return { std::move(lengths.at(start_hash)) };
        }

        uint64_t _convert_volatile(const std::filesystem::path &converted_dir, updated_chunk_list &avail_chunks,
            const uint64_t immutable_size, const updated_chunk_list &volatile_chunks, const uint64_t volatile_size_in,
            const cardano::block_hash &volatile_prev_hash) const
        {
            timer t { "convert volatile chunks", logger::level::trace };
            std::filesystem::create_directories(converted_dir);
            // read all volatile chunks and the final immutable into a single data buffer
            uint8_vector raw_data {};
            raw_data.resize(volatile_size_in);
            size_t offset = 0;
            for (const auto &info: volatile_chunks) {
                file::read_span(std::span { raw_data.data() + offset, info.data_size }, info.path, info.data_size);
                offset += info.data_size;
            }

            cbor_parser parser { raw_data };
            // cardano::block_base keeps a reference to block_tuple's cbor_value, so need to keep them
            std::vector<std::unique_ptr<cbor_value>> cbor {};
            std::map<cardano_hash_32, std::unique_ptr<cardano::block_base>> blocks {};
            // the first block the most recent immutable chunk
            const cardano::block_base *first_block = nullptr;
            while (!parser.eof()) {
                auto block_tuple_ptr = std::make_unique<cbor_value>();
                parser.read(*block_tuple_ptr);
                auto blk = cardano::make_block(*block_tuple_ptr, immutable_size + block_tuple_ptr->data - raw_data.data(), _parent.local_chain().config());
                if (!first_block)
                    first_block = blk.get();
                // volatile chunks can have data older than the data in the immutable ones, can simply skip those
                if (blk->slot() >= first_block->slot()) {
                    blocks.try_emplace(blk->hash(), std::move(blk));
                    cbor.emplace_back(std::move(block_tuple_ptr));
                }
            }

            block_followers_map followers {};
            for (const auto &[hash, blk]: blocks)  {
                auto [it, created] = followers.try_emplace(blk->prev_hash(), block_hash_list { hash });
                if (!created)
                    it->second.emplace_back(hash);
            }
            const auto longest = _longest_chain(volatile_prev_hash, followers);
            uint64_t output_size = 0;
            constexpr size_t batch_size = 100;
            size_t batch_idx = 0;
            for (size_t base = 0; base < longest.size(); ) {
                uint8_vector batch_data {};
                const auto batch_chunk_id = blocks.at(longest.at(base))->slot_object().chunk_id();
                for (size_t batch_end = std::min(base + batch_size, longest.size()); base < batch_end; ++base) {
                    const auto *blk = blocks.at(longest.at(base)).get();
                    // ensure blocks from only the same chunk are batched
                    if (blk->slot_object().chunk_id() != batch_chunk_id)
                        break;
                    batch_data << blk->raw_data();
                }
                const auto batch_hash = blake2b<cardano::block_hash>(batch_data);
                const auto path = std::filesystem::weakly_canonical(converted_dir / fmt::format("batch-{:04}-{}.dat", batch_idx, batch_hash));
                ++batch_idx;
                // write only if not exists to not change the last_write_time in the file system
                if (!std::filesystem::exists(path) || std::filesystem::file_size(path) != batch_data.size())
                    file::write(path.string(), batch_data);
                avail_chunks.emplace_back(path.string(), _to_time_t(std::filesystem::last_write_time(path)), batch_data.size());
                output_size += batch_data.size();
            }
            _parent.local_chain().remover().mark_old_files(converted_dir, _delete_delay);
            return output_size;
        }
    };

    syncer::syncer(chunk_registry &cr, const size_t zstd_max_level, const std::chrono::seconds del_delay)
        : sync::syncer { cr, peer_selection_simple::get() }, _impl { std::make_unique<impl>(*this, zstd_max_level, del_delay) }
    {
    }

    syncer::~syncer() =default;

    [[nodiscard]] std::shared_ptr<sync::peer_info> syncer::find_peer(const std::filesystem::path &node_dir) const
    {
        return _impl->find_peer(node_dir);
    }

    void syncer::cancel_tasks(const uint64_t min_invalid_offset)
    {
        _impl->cancel_tasks(min_invalid_offset);
    }

    void syncer::sync_attempt(sync::peer_info &peer, const cardano::optional_slot max_slot)
    {
        _impl->sync_attempt(dynamic_cast<peer_info &>(peer), max_slot);
    }
}