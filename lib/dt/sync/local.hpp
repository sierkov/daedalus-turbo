/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SYNC_LOCAL_HPP
#define DAEDALUS_TURBO_SYNC_LOCAL_HPP

#include <algorithm>
#include <dt/chunk-registry.hpp>
#include <dt/scheduler.hpp>
#include <dt/zstd.hpp>

namespace daedalus_turbo::sync::local {
    struct syncer {
        struct sync_res {
            std::vector<std::string> updated {};
            std::vector<std::string> deleted {};
            std::vector<std::string> errors {};
            cardano::slot last_slot {};
        };

        syncer(scheduler &sched, chunk_registry &cr, const std::string &node_path, bool strict=true, size_t zstd_max_level=3, std::chrono::seconds del_delay=std::chrono::seconds { 3600 })
            : _sched { sched }, _cr { cr }, _node_path { std::filesystem::canonical(node_path) },
                _immutable_path { _node_path / "immutable" }, _volatile_path { _node_path / "volatile" },
                _converted_path { _node_path / "volatile-dt" },
                _state_path { _cr.full_path("state-local.json") }, _delete_delay { del_delay },
                _zstd_level_immutable { std::min(static_cast<size_t>(22), zstd_max_level) },
                _zstd_level_volatile { std::min(static_cast<size_t>(3), zstd_max_level) },
                _strict { strict }
        {
            std::filesystem::create_directories(_converted_path);
            logger::trace("syncer zstd (level-immutable: {} level-volatile: {})", _zstd_level_immutable, _zstd_level_volatile);
            auto deletable_chunks = _cr.init_state(_strict);
            auto delete_time = std::chrono::system_clock::now() + _delete_delay;
            for (auto &&path: deletable_chunks) {
                logger::trace("unkown chunk found at startup {} - scheduling it for deletion", path);
                _deleted_chunks.try_emplace(std::move(path), delete_time);
            }
            _load_state();
        }

        size_t size() const
        {
            return _cr.num_chunks();
        }

        sync_res sync()
        {
            timer t { "sync::local::sync" };
            progress_guard pg { "parse", "merge", "validate" };
            _cr.clean_up();
            auto res = _refresh();
            _save_state();
            return res;
        }
    private:
        struct source_chunk_info {
            std::string rel_path {};
            std::time_t update_time {};
            uint64_t offset = 0;
            uint64_t data_size = 0;
            cardano_hash_32 data_hash {};

            bool is_volatile() const
            {
                thread_local std::string_view match { "volatile" };
                return rel_path.size() > match.size() && rel_path.substr(0, match.size()) == match;
            }

            static source_chunk_info from_json(const json::object &j)
            {
                source_chunk_info chunk {};
                chunk.rel_path = json::value_to<std::string_view>(j.at("relPath"));
                chunk.update_time = json::value_to<std::time_t>(j.at("updateTime"));
                chunk.offset = json::value_to<size_t>(j.at("offset"));
                chunk.data_size = json::value_to<size_t>(j.at("size"));
                chunk.data_hash = bytes_from_hex(json::value_to<std::string_view>(j.at("hash")));
                return chunk;
            }

            json::object to_json() const
            {
                return json::object {
                    { "relPath", rel_path },
                    { "size", data_size },
                    { "offset", offset },
                    { "hash", fmt::format("{}", data_hash.span()) },
                    { "updateTime", update_time }
                };
            }
        };

        struct chunk_update {
            std::string path {};
            std::time_t update_time {};
            uint64_t data_size = 0;
            uint64_t offset = 0;

            bool operator<(const chunk_update &b) const
            {
                return path < b.path;
            }
        };
        using avail_chunk_list = std::vector<chunk_update>;
        struct analyze_res {
            std::string path {};
            source_chunk_info source_info {};
            bool updated = false;
        };
        using block_hash_list = std::vector<cardano_hash_32>;
        using block_followers_map = std::map<cardano_hash_32, block_hash_list>;

        scheduler &_sched;
        chunk_registry &_cr;
        const std::filesystem::path _node_path;
        const std::filesystem::path _immutable_path;
        const std::filesystem::path _volatile_path;
        const std::filesystem::path _converted_path;
        const std::string _state_path;
        std::chrono::milliseconds _delete_delay;
        std::map<std::string, source_chunk_info> _source_chunks {};
        std::map<std::string, std::chrono::time_point<std::chrono::system_clock>> _deleted_chunks {};
        const size_t _zstd_level_immutable;
        const size_t _zstd_level_volatile;
        const bool _strict;

        static std::time_t _to_time_t(const std::filesystem::file_time_type &tp)
        {
            using namespace std::chrono;
            auto sc_tp = time_point_cast<system_clock::duration>(tp - file_clock::now() + system_clock::now());
            return system_clock::to_time_t(sc_tp);
        }

        void _load_state()
        {
            if (std::filesystem::exists(_state_path)) {
                auto json = file::read(_state_path);
                auto j_chunks = json::parse(json.span().string_view()).as_array();
                for (const auto &j_chunk: j_chunks) {
                    auto chunk = source_chunk_info::from_json(j_chunk.as_object());
                    auto full_path = std::filesystem::weakly_canonical(_node_path / chunk.rel_path).string();
                    if (!std::filesystem::exists(full_path)) {
                        logger::warn("{} is recorded in the state but missing - ignoring it and all the following chunks", full_path);
                        break;
                    }
                    if (chunk.offset >= _cr.num_bytes()) {
                        logger::warn("{}'s offset is greater than compressed db size: {} - ignoring it and all the following chunks",
                                        chunk.offset, _cr.num_bytes());
                        break;
                    }
                    _source_chunks.try_emplace(std::move(full_path), std::move(chunk));
                }
            }
        }

        void _save_state()
        {
            timer t { "sync::local::save_state", logger::level::debug };
            _cr.save_state();
            json::array j_chunks {};
            for (const auto &[full_path, chunk]: _source_chunks)
                j_chunks.emplace_back(chunk.to_json());
            json::save_pretty(_state_path, j_chunks);
        }

        std::vector<std::string> _delete_obsolete(const chunk_registry::file_set &deletable)
        {
            timer t { "delete obsolete", logger::level::debug };
            std::vector<std::string> deleted {};
            auto now = std::chrono::system_clock::now();
            auto new_delete_time = now + _delete_delay;
            for (const auto &path: deletable)
                _deleted_chunks.try_emplace(path, new_delete_time);
            for (auto it = _deleted_chunks.begin(); it != _deleted_chunks.end(); ) {
                if (now >= it->second) {
                    deleted.emplace_back(it->first);
                    std::filesystem::remove(it->first);
                    it = _deleted_chunks.erase(it);
                } else {
                    it++;
                }
            }
            auto too_old = now - _delete_delay;
            auto file_now = std::chrono::file_clock::now();
            for (auto &entry: std::filesystem::directory_iterator(_converted_path)) {
                if (entry.is_regular_file()) {
                    auto path = std::filesystem::weakly_canonical(entry.path()).string();
                    if (!_source_chunks.contains(path)) {
                        auto entry_sys_time = std::chrono::time_point_cast<std::chrono::system_clock::duration>(entry.last_write_time() - file_now + now);
                        if (entry_sys_time < too_old) {
                            logger::trace("found a converted volatile chunk {} not referenced by source_chunks - deleting it", path);
                            deleted.emplace_back(path);
                            std::filesystem::remove(path);
                        }
                    }
                }
            }
            return deleted;
        }

        analyze_res _analyze_local_chunk(chunk_update &&update)
        {
            timer t { fmt::format("process chunk path: {} offset: {} size: {}", update.path, update.offset, update.data_size), logger::level::trace };
            uint8_vector chunk {};
            file::read(update.path, chunk);
            if (chunk.size() != update.data_size)
                throw error("file changed: {} new size: {} recorded size: {}!", update.path, chunk.size(), update.data_size);
            source_chunk_info source_info {
                std::filesystem::relative(std::filesystem::canonical(update.path), _node_path).string(),
                update.update_time, update.offset, update.data_size
            };
            blake2b(source_info.data_hash, chunk);
            const auto dist_it = _cr.find(source_info.data_hash);
            // even if the data is the same, the offset change requires reparse/reindex
            if (dist_it != _cr.chunks().end() && dist_it->second.offset == source_info.offset)
                return analyze_res { std::move(update.path), std::move(source_info), false };
            std::string local_path;
            if (dist_it == _cr.chunks().end()) {
                uint8_vector compressed {};
                zstd::compress(compressed, chunk, source_info.is_volatile() ? _zstd_level_volatile : _zstd_level_immutable);
                local_path = _cr.full_path(storage::chunk_info::rel_path_from_hash(source_info.data_hash));
                file::write(local_path, compressed);
            } else {
                local_path = _cr.full_path(dist_it->second.rel_path());
            }
            _cr.add(source_info.offset, local_path, source_info.data_hash, source_info.rel_path, _strict);
            return analyze_res { std::move(update.path), std::move(source_info), true };
        }

        void _refresh_chunks(avail_chunk_list &avail_chunks,
            std::vector<std::string> &updated, chunk_registry::file_set &deletable, std::vector<std::string> &errors)
        {
            timer t { "check chunks for updates", logger::level::debug };
            uint64_t source_offset = 0;
            std::vector<chunk_update> updated_chunks {};
            // std::map guarantees ordered processing
            for (auto &&update: avail_chunks) {
                auto it = _source_chunks.find(update.path);
                bool size_matches = false, time_matches = false, offset_matches = false;
                bool exists = it != _source_chunks.end();
                if (exists) {
                    size_matches = it->second.data_size == update.data_size;
                    // add +1 second for conversion error between clocks from _to_time_t
                    time_matches = it->second.update_time + 1 >= update.update_time;
                    offset_matches = it->second.offset == source_offset;
                }
                if (!exists || !size_matches || !time_matches || !offset_matches) {
                    // truncate _source_chunks after this path since their offsets may be off and need to be rechecked
                    if (it != _source_chunks.end()) {
                        std::time_t update_time = it->second.update_time;
                        size_t prev_size = _source_chunks.size();
                        _source_chunks.erase(it, _source_chunks.end());
                        logger::warn("chunk {} is different (e: {} s: {} tp: {} tn: {} o: {}) in the source, updating it and {} following chunks",
                            update.path, exists, size_matches, update_time, update.update_time, offset_matches, prev_size - _source_chunks.size());
                    }
                    update.offset = source_offset;
                    updated_chunks.emplace_back(std::move(update));
                }
                source_offset += update.data_size;
            }
            if (!updated_chunks.empty()) {
                auto updated_start_offset = updated_chunks.front().offset;
                if (updated_start_offset < _cr.num_bytes()) {
                    // truncate del=false since some files after the truncation offset may have been just updated
                    for (auto &&del_path: _cr.truncate(updated_start_offset, false)) {
                        auto source_path = std::filesystem::weakly_canonical(_node_path / _cr.rel_path(del_path)).string();
                        // only to-be-deleted chunks unknown in the update source-chunk list to the deletable list
                        if (_source_chunks.find(source_path) == _source_chunks.end())
                            deletable.emplace(std::move(del_path));
                    }
                }
                if (updated_start_offset != _cr.num_bytes())
                    throw error("internal error: updated chunk offset {} is greater than the compressed data size {}!",
                        updated_start_offset, _cr.num_bytes());
                logger::info("update_start_offset: {}", updated_start_offset);
                static const std::string task_name { "import-chunk" };
                timer t { "process updated chunks" };
                _sched.on_result(task_name, [&](auto &&res) {
                    if (res.type() == typeid(scheduled_task_error)) {
                        errors.emplace_back(std::any_cast<scheduled_task_error>(res).what());
                        return;
                    }
                    auto &&a_res = std::any_cast<analyze_res>(res);
                    if (a_res.updated)
                        updated.emplace_back(a_res.source_info.rel_path);
                    auto [it, created] = _source_chunks.try_emplace(a_res.path, std::move(a_res.source_info));
                    if (!created)
                        it->second = std::move(a_res.source_info);
                });
                const auto max_offset = *_cr.target_offset();
                for (auto &&update: updated_chunks)
                    _sched.submit(task_name, 0 + 100 * (max_offset - update.offset) / max_offset, [&] {
                        return _analyze_local_chunk(std::move(update));
                    });
                _sched.process(true);
            }
            logger::debug("after refresh: max source offset: {} chunk-registry size: {}", source_offset, _cr.num_bytes());
        }

        std::pair<uint64_t, avail_chunk_list> _find_avail_chunks(const std::string &dir_path, const std::string &ext) const
        {
            uint64_t total_size = 0;
            avail_chunk_list avail_chunks {};
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

        static block_hash_list _longest_chain(const cardano_hash_32 &start_hash, const block_followers_map &followers)
        {
            block_hash_list segment {};
            segment.emplace_back(start_hash);
            auto it = followers.find(start_hash);
            if (it != followers.end()) {
                block_hash_list max_segment {};
                for (const auto &hash: it->second) {
                    auto seg = _longest_chain(hash, followers);
                    if (max_segment.size() < seg.size())
                        max_segment = seg;
                }
                for (const auto &hash: max_segment)
                    segment.emplace_back(hash);
            }
            return segment;
        }

        uint64_t _convert_volatile(avail_chunk_list &avail_chunks, const uint64_t immutable_size, const avail_chunk_list &volatile_chunks, const uint64_t volatile_size_in)
        {
            timer t { "convert volatile chunks", logger::level::trace };
            // read all volatile chunks and the final immutable into a single data buffer
            uint8_vector raw_data {};
            raw_data.resize(volatile_size_in);
            size_t offset = 0;
            for (const auto &info: volatile_chunks) {
                file::read_span<uint8_t>(std::span { raw_data.data() + offset, info.data_size }, info.path, info.data_size);
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
                auto blk = cardano::make_block(*block_tuple_ptr, immutable_size + block_tuple_ptr->data - raw_data.data());
                if (!first_block)
                    first_block = blk.get();
                // volatile chunks can have data older than the data in the immutable ones, can simply skip those
                if (blk->slot() >= first_block->slot()) {
                    blocks.try_emplace(blk->hash(), std::move(blk));
                    cbor.emplace_back(std::move(block_tuple_ptr));
                }
            }
            
            block_followers_map followers {};
            block_hash_list segments {};
            for (const auto &[hash, blk]: blocks)  {
                if (blocks.find(blk->prev_hash()) == blocks.end()) {
                    segments.emplace_back(hash);
                } else {
                    followers[blk->prev_hash()].emplace_back(hash);
                }
            }
            uint64_t output_size = 0;
            if (!segments.empty()) {
                block_hash_list longest_chain {};
                for (const auto &start_hash: segments) {
                    auto seg = _longest_chain(start_hash, followers);
                    if (longest_chain.size() < seg.size())
                        longest_chain = seg;
                }
                constexpr size_t batch_size = 100;
                size_t batch_idx = 0;
                for (size_t base = 0; base < longest_chain.size(); ) {
                    uint8_vector batch_data {};
                    size_t end = std::min(base + batch_size, longest_chain.size());
                    const auto *first_block = blocks.at(longest_chain.at(base)).get();
                    size_t off = base;
                    for (; off < end; ++off) {
                        const auto *blk = blocks.at(longest_chain.at(off)).get();
                        // ensure blocks from only one epoch in each chunk
                        if (blk->slot().epoch() != first_block->slot().epoch())
                            break;
                        batch_data << blk->raw_data();
                    }
                    base = off;
                    auto batch_hash = blake2b<cardano::block_hash>(batch_data);
                    auto path = std::filesystem::weakly_canonical(_converted_path / fmt::format("batch-{:04}-{}.dat", batch_idx, batch_hash));
                    ++batch_idx;
                    // write only if not exists to not change the last_write_time in the file system
                    if (!std::filesystem::exists(path) || std::filesystem::file_size(path) != batch_data.size())
                        file::write(path.string(), batch_data);
                    avail_chunks.emplace_back(path.string(), _to_time_t(std::filesystem::last_write_time(path)), batch_data.size());
                    output_size += batch_data.size();
                }
            }
            return output_size;
        }

        sync_res _refresh()
        {
            timer t { "sync::local::_refresh" };
            std::vector<std::string> errors {};
            std::vector<std::string> updated {};
            chunk_registry::file_set deletable {};
            logger::info("analyzing available chunks");
            auto [source_end_offset, avail_chunks] = _find_avail_chunks(_immutable_path.string(), ".chunk");
            auto [volatile_size_in, avail_volatile] = _find_avail_chunks(_volatile_path.string(), ".dat");
            // move the last immutable chunk to volatile since they need to be parsed together
            if (!avail_volatile.empty() && !avail_chunks.empty()) {
                auto &last_immutable = avail_chunks.back();
                source_end_offset -= last_immutable.data_size;
                volatile_size_in += last_immutable.data_size;
                avail_volatile.insert(avail_volatile.begin(), last_immutable);
                avail_chunks.pop_back();
                source_end_offset += _convert_volatile(avail_chunks, source_end_offset, avail_volatile, volatile_size_in);
            }
            // when the source has a shorter chain, must truncate the local one
            if (source_end_offset < _cr.num_bytes()) {
                for (auto &&del_path: _cr.truncate(source_end_offset, false))
                    deletable.emplace(std::move(del_path));
            }
            _cr.target_offset(source_end_offset);
            _refresh_chunks(avail_chunks, updated, deletable, errors);
            auto deleted = _delete_obsolete(deletable);
            return sync_res { std::move(updated), std::move(deleted), std::move(errors), _cr.max_slot() };
        }
    };
}

#endif // !DAEDALUS_TURBO_SYNC_LOCAL_HPP
