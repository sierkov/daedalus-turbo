/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
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
                _state_path { _cr.full_path("state-local.json") }, _delete_delay { del_delay },
                _zstd_level_immutable { std::min(static_cast<size_t>(22), zstd_max_level) },
                _zstd_level_volatile { std::min(static_cast<size_t>(3), zstd_max_level) },
                _strict { strict }
        {
            logger::debug("syncer zstd (level-immutable: {} level-volatile: {})", _zstd_level_immutable, _zstd_level_volatile);
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
                static std::string match { "volatile" };
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
        };

        struct analyze_res {
            std::string path {};
            source_chunk_info source_info {};
            chunk_registry::chunk_info dist_info {};
            bool updated = false;
        };

        scheduler &_sched;
        chunk_registry &_cr;
        const std::filesystem::path _node_path;
        const std::filesystem::path _immutable_path;
        const std::filesystem::path _volatile_path;
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
                    logger::trace("import chunk_info path: {} data_size: {} update_time: {}", chunk.rel_path, chunk.data_size, chunk.update_time);
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
            timer t { "local::syncer::save_state", logger::level::debug };
            _cr.save_state();
            std::ostringstream json_s {};
            json_s << "[\n";
            for (const auto &[full_path, chunk]: _source_chunks) {
                json_s << "  " << json::serialize(chunk.to_json());
                if (full_path != _source_chunks.rbegin()->first)
                    json_s << ',';
                json_s << '\n';
            }
            json_s << "]\n";
            file::write(_state_path, json_s.str());
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
            return deleted;
        }

        std::pair<bool, chunk_registry::chunk_info> _write_chunk(const source_chunk_info &info, const buffer &chunk) const
        {
            auto dist_it = _cr.find(info.data_hash);
            if (dist_it == _cr.chunks().end()) {
                uint8_vector compressed {};
                zstd::compress(compressed, chunk, info.is_volatile() ? _zstd_level_volatile : _zstd_level_immutable);
                auto dist_info = _cr.parse(info.offset, info.rel_path, chunk, compressed.size());
                file::write(_cr.full_path(dist_info.rel_path()), compressed);
                return std::make_pair(true, std::move(dist_info));
            } else if (dist_it->second.offset != info.offset) {
                // even though the data is the same, the change in the offset requires reindexing
                auto dist_info = _cr.parse(info.offset, info.rel_path, chunk, std::filesystem::file_size(_cr.full_path(dist_it->second.rel_path())));
                return std::make_pair(true, std::move(dist_info));
            } else {
                return std::make_pair(false, dist_it->second);
            }
        }

        void _refresh_sources(const std::filesystem::path &dir_path, const std::string &ext, const std::string &task_name,
            uint64_t &source_offset, std::vector<std::string> &updated, chunk_registry::file_set &deletable, std::vector<std::string> &errors)
        {
            timer t { fmt::format("check {} for updates start offset: {}", dir_path.string(), source_offset), logger::level::debug };
            std::vector<chunk_update> updated_chunks {};
            std::map<std::string, chunk_update> avail_chunks {};
            {
                timer t { fmt::format("analyze files {}", dir_path.string()), logger::level::debug };
                for (const auto &entry: std::filesystem::directory_iterator(dir_path)) {
                    if (entry.file_size() == 0 || entry.path().extension() != ext) continue;
                    auto path = std::filesystem::weakly_canonical(entry.path()).string();
                    avail_chunks.try_emplace(path, path, _to_time_t(entry.last_write_time()), entry.file_size());
                }
            }
            // std::map guarantees ordered processing
            for (auto &&[path, update]: avail_chunks) {
                auto it = _source_chunks.find(path);
                bool exists = it != _source_chunks.end();
                bool size_matches = false, time_matches = false, offset_matches = false;
                if (exists) {
                    size_matches = it->second.data_size == update.data_size;
                    // add +1 second for conversion error between clocks from _to_time_t
                    time_matches = it->second.update_time + 1 >= update.update_time;
                    offset_matches = it->second.offset == source_offset;
                }
                if (!exists || !size_matches || !time_matches || !offset_matches) {
                    // truncate _source_chunks after this path since their offsets may be off and need to be rechecked
                    if (it != _source_chunks.end()) {
                        size_t prev_size = _source_chunks.size();
                        std::time_t update_time = it->second.update_time;                        
                        while (it != _source_chunks.end())
                            it = _source_chunks.erase(it);
                        logger::warn("chunk {} is different (e: {} s: {} tp: {} tn: {} o: {}) in the source, updating it and {} following chunks",
                            path, exists, size_matches, update_time, update.update_time, offset_matches, prev_size - _source_chunks.size());
                    }
                    update.offset = source_offset;
                    updated_chunks.emplace_back(std::move(update));
                }
                source_offset += update.data_size;
            }
            std::vector<analyze_res> analyzed_chunks {};
            uint64_t updated_min_offset = _cr.num_bytes();
            {
                timer t { fmt::format("process updated chunks from {}", dir_path.string()) };
                _sched.on_result(task_name, [&](const auto &res) {
                    if (res.type() == typeid(scheduled_task_error)) {
                        errors.emplace_back(std::any_cast<scheduled_task_error>(res).what());
                        return;
                    }
                    const auto &results = std::any_cast<std::vector<analyze_res>>(res);
                    for (const auto &a_res: results) {
                        auto [it, created] = _source_chunks.try_emplace(a_res.path, a_res.source_info);
                        if (!created)
                            it->second = a_res.source_info;
                        if (a_res.updated && updated_min_offset > a_res.dist_info.offset)
                            updated_min_offset = a_res.dist_info.offset;
                        analyzed_chunks.emplace_back(a_res);
                    }
                });
                size_t task_size = 0;
                std::vector<chunk_update> task {};
                bool small_tasks = updated_chunks.size() / 4 <= _sched.num_workers();
                for (auto it = updated_chunks.begin(); it != updated_chunks.end(); it++) {
                    task_size += it->data_size;
                    task.emplace_back(std::move(*it));
                    if (small_tasks || task_size >= 256'000'000 || std::next(it) == updated_chunks.end()) {
                        _sched.submit(task_name, task_size >> 20, [this, task] {
                            std::vector<analyze_res> results {};
                            for (const auto &update: task) {
                                timer t { fmt::format("process chunk path: {} offset: {} size: {}", update.path, update.offset, update.data_size), logger::level::trace };
                                uint8_vector chunk {};
                                file::read(update.path, chunk);
                                if (chunk.size() != update.data_size)
                                    throw error("file changed new size: {} recorded size: {}!", chunk.size(), update.data_size);
                                source_chunk_info source_info {
                                    std::filesystem::relative(std::filesystem::canonical(update.path), _node_path).string(),
                                    update.update_time, update.offset, update.data_size
                                };
                                blake2b(source_info.data_hash, chunk);
                                auto write_info = _write_chunk(source_info, chunk);
                                results.emplace_back(update.path, std::move(source_info), std::move(write_info.second), write_info.first);
                            }
                            return results;
                        });
                        task.clear();
                        task_size = 0;
                    }
                }
                _sched.process(true);
            }
            if (updated_min_offset != _cr.num_bytes()) {
                // truncate del=false since some files after the truncation offset may have been just updated
                for (auto &&del_path: _cr.truncate(updated_min_offset, false)) {
                    auto source_path = std::filesystem::weakly_canonical(_node_path / _cr.rel_path(del_path)).string();
                    // only to-be-deleted chunks unknown in the update source-chunk list to the deletable list
                    if (_source_chunks.find(source_path) == _source_chunks.end())
                        deletable.emplace(std::move(del_path));
                }
            }
            std::sort(analyzed_chunks.begin(), analyzed_chunks.end(), [](const auto &a, const auto &b) { return a.dist_info.orig_rel_path < b.dist_info.orig_rel_path; });
            for (auto &&chunk: analyzed_chunks) {
                if (chunk.updated)
                    updated.emplace_back(chunk.dist_info.orig_rel_path);
                if (chunk.updated || chunk.dist_info.offset >= updated_min_offset)
                    _cr.add(std::move(chunk.dist_info), _strict);
            }
            logger::debug("after refresh: max source offset: {} chunk-registry size: {}", source_offset, _cr.num_bytes());
        }

        sync_res _refresh()
        {
            std::vector<std::string> errors {};
            std::vector<std::string> updated {};
            chunk_registry::file_set deletable {};
            uint64_t source_offset = 0;
            _refresh_sources(_immutable_path, ".chunk", "copy-immutable", source_offset, updated, deletable, errors);
            _refresh_sources(_volatile_path, ".dat", "copy-volatile", source_offset, updated, deletable, errors);
            // when the source has a shorter chain must truncate
            if (source_offset != _cr.num_bytes()) {
                for (auto &&del_path: _cr.truncate(source_offset, false))
                    deletable.emplace(std::move(del_path));
            }
            auto deleted = _delete_obsolete(deletable);
            return sync_res { std::move(updated), std::move(deleted), std::move(errors), _cr.max_slot() };
        }
    };
}

#endif // !DAEDALUS_TURBO_SYNC_LOCAL_HPP