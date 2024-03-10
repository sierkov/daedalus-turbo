/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CHUNK_REGISTRY_HPP
#define DAEDALUS_TURBO_CHUNK_REGISTRY_HPP

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <dt/atomic.hpp>
#include <dt/cardano.hpp>
#include <dt/storage/chunk_info.hpp>
#include <dt/file.hpp>
#include <dt/json.hpp>
#include <dt/progress.hpp>
#include <dt/scheduler.hpp>
#include <dt/timer.hpp>

namespace daedalus_turbo {
    struct chunk_registry {
        // Shall be a multiple of an SSD's sector size and larger than Cardano's largest block (including Byron boundary ones too!)
        using chunk_info = storage::chunk_info;
        using chunk_map = std::map<uint64_t, chunk_info>;
        using chunk_list = std::vector<chunk_info>;

        struct epoch_info {
            std::vector<const chunk_info *> chunks {};

            const cardano::block_hash &prev_block_hash() const
            {
                if (chunks.empty())
                    throw error("first_block_hash called on an epoch with no chunks!");
                return chunks.front()->prev_block_hash;
            }

            const cardano::block_hash &last_block_hash() const
            {
                if (chunks.empty())
                    throw error("first_block_hash called on an epoch with no chunks!");
                return chunks.back()->last_block_hash;
            }

            cardano::slot last_slot() const
            {
                if (chunks.empty())
                    throw error("first_block_hash called on an epoch with no chunks!");
                return chunks.back()->last_slot;
            }

            uint64_t start_offset() const
            {
                if (chunks.empty())
                    throw error("first_block_hash called on an epoch with no chunks!");
                return chunks.front()->offset;
            }

            uint64_t end_offset() const
            {
                if (chunks.empty())
                    throw error("first_block_hash called on an epoch with no chunks!");
                return chunks.back()->end_offset();
            }

            uint64_t size() const
            {
                return end_offset() - start_offset();
            }

            uint64_t compressed_size() const
            {
                uint64_t sz = 0;
                for (const auto *chunk: chunks)
                    sz += chunk->compressed_size;
                return sz;
            }
        };
        using epoch_map = std::map<size_t, epoch_info>;
        using file_set = std::set<std::string>;
        using block_processor = std::function<void(const cardano::block_base &)>;

        static std::filesystem::path init_db_dir(const std::string &db_dir)
        {
            std::filesystem::create_directories(db_dir);
            return std::filesystem::canonical(db_dir);
        }

        chunk_registry(scheduler &sched, const std::string &data_dir)
            : _sched { sched }, _data_dir { data_dir },
                _db_dir { init_db_dir((_data_dir / "compressed").string()) },
                _state_path { (_db_dir / "state.json").string() }
        {
        }

        virtual ~chunk_registry() =default;

        // data accessors

        std::string rel_path(const std::filesystem::path &full_path) const
        {
            auto canon_path = std::filesystem::weakly_canonical(full_path);
            auto [diffBegin, diffEnd] = std::mismatch(_db_dir.begin(), _db_dir.end(), canon_path.begin());
            if (diffBegin != _db_dir.end())
                throw error("the supplied path '{}' is not inside the host directory '{}'", canon_path.string(), _db_dir.string());
            return std::filesystem::relative(canon_path, _db_dir).string();
        }

        std::string full_path(const std::filesystem::path &rel_path) const
        {
            auto canon_path = std::filesystem::weakly_canonical(_db_dir / rel_path);
            auto [diffBegin, diffEnd] = std::mismatch(_db_dir.begin(), _db_dir.end(), canon_path.begin());
            if (diffBegin != _db_dir.end())
                throw error("the supplied path '{}' does not resolve into the host directory '{}'", canon_path.string(), _db_dir.string());
            auto save_dir = canon_path.parent_path();
            if (!std::filesystem::exists(save_dir))
                std::filesystem::create_directories(save_dir);
            return canon_path.string();
        }

        const chunk_map &chunks() const
        {
            return _chunks;
        }

        const epoch_map &epochs() const
        {
            return _epochs;
        }

        // can be called concurrently with parse/add activities
        epoch_info epoch(uint64_t epoch) const
        {
            std::scoped_lock lk { _update_mutex };
            return _epochs.at(epoch);
        }

        std::optional<chunk_info> last_chunk() const
        {
            if (!_chunks.empty())
                return _chunks.rbegin()->second;
            return {};
        }

        cardano::slot max_slot() const
        {
            if (!_chunks.empty())
                return _chunks.rbegin()->second.last_slot;
            return 0;
        }

        size_t num_bytes() const
        {
            return _end_offset;
        }

        size_t num_chunks() const
        {
            return _chunks.size();
        }

        std::optional<uint64_t> target_offset() const
        {
            return _target_offset;
        }

        const std::filesystem::path &data_dir() const
        {
            return _data_dir;
        }

        const chunk_info &find(uint64_t offset) const
        {
            return _find_it(offset)->second;
        }

        chunk_map::const_iterator find(const buffer &data_hash) const
        {
            return std::find_if(_chunks.begin(), _chunks.end(),
                [&](const auto &el) { return el.second.data_hash == data_hash; });
        }

        void read(uint64_t offset, cbor_value &value)
        {
            if (offset >= _end_offset)
                throw error("the requested offset {} is larger than the maximum one: {}", offset, _end_offset);
            const auto &chunk = find(offset);
            if (offset >= chunk.offset + chunk.data_size)
                throw error("the requested chunk segment is too small to parse it");
            file::read(full_path(chunk.rel_path()), _read_buffer);
            size_t read_offset = offset - chunk.offset;
            size_t read_size = _read_buffer.size() - read_offset;
            cbor_parser parser(buffer { _read_buffer.data() + read_offset, read_size });
            parser.read(value);
        }

        template<typename T>
        bool parse_parallel(
            const std::function<void(T &res, const std::string &chunk_path, cardano::block_base &blk)> &act,
            const std::function<void(std::string &&chunk_path, T &&res)> &agg,
            bool progress=true)
        {
            using parse_res = std::pair<std::string, T>;
            progress_guard pg { "parse" };
            size_t num_parsed = 0;
            _sched.on_result("parse-chunk", [&](auto &&res) {
                if (res.type() == typeid(scheduled_task_error))
                    return;
                auto &&[chunk_path, chunk_res] = std::any_cast<parse_res>(res);
                agg(std::move(chunk_path), std::move(chunk_res));
                progress::get().update("parse", ++num_parsed, num_chunks());
            });
            for (const auto &[chunk_offset, chunk_info]: _chunks) {
                _sched.submit("parse-chunk", 100, [this, chunk_offset, chunk_info, &act]() {
                    T res {};
                    auto data = file::read(full_path(chunk_info.rel_path()));
                    buffer buf { data };
                    cbor_parser block_parser { buf };
                    cbor_value block_tuple;
                    auto canon_path = full_path(chunk_info.rel_path());
                    while (!block_parser.eof()) {
                        block_parser.read(block_tuple);
                        auto blk = cardano::make_block(block_tuple, chunk_offset + block_tuple.data - buf.data());
                        act(res, canon_path, *blk);
                    }
                    return parse_res { std::move(canon_path), std::move(res) };
                });
            }
            return _sched.process_ok(progress);
        }

        // state modifying methods

        file_set init_state(bool strict=true)
        {
            timer t { "chunk-registry init state", logger::level::trace };
            auto [truncate_offset, deletable_chunks] = _load_state(strict);
            // give subclasses the time to update their data structures if some chunks weren't loaded / didn't match the state
            for (auto &&path: truncate(truncate_offset, false))
                deletable_chunks.emplace(std::move(path));
            logger::debug("chunk-registry data size: {} num chunks: {} num deletable chunks: {}", num_bytes(), num_chunks(), deletable_chunks.size());
            return deletable_chunks;
        }

        virtual void save_state()
        {
            timer t { "chunk_registry::save_state" };
            if (!_unmerged_chunks.empty()) {
                if (!_chunks.empty())
                    logger::trace("last merged chunk: {}", json::serialize(_chunks.rbegin()->second.to_json()));
                for (const auto &[last_byte_offset, uchunk]: _unmerged_chunks)
                    logger::trace("unmerged chunk with last byte offset {}: {}", last_byte_offset, json::serialize(uchunk.to_json()));
                logger::warn("{} unmerged chunks - ignoring them", _unmerged_chunks.size());
                _unmerged_chunks.clear();
            }
            _notify_of_updates(true);
            // let for the newly scheduled operations in _on_epoch_merge calls to finish
            _sched.process(true);
            json::array j_chunks {};
            for (const auto &[max_offset, chunk]: _chunks)
                j_chunks.emplace_back(chunk.to_json());
            json::save_pretty(_state_path, json::object { { "chunks", j_chunks } });
            _parse_start_offset = _end_offset;
            _parsed = 0;
        }

        virtual file_set truncate(size_t max_end_offset, bool del=true)
        {
            file_set deleted_chunks {};
            if (max_end_offset >= _end_offset)
                return deleted_chunks;
            timer t { fmt::format("truncate chunk registry to size {}", max_end_offset) };
            auto chunk_it = _find_it(max_end_offset);
            if (chunk_it->second.offset < max_end_offset)
                max_end_offset = chunk_it->second.offset;
            for (auto epoch_it = _epochs.find(chunk_it->second.epoch()); epoch_it != _epochs.end(); ) {
                if (chunk_it->second.offset <= epoch_it->second.start_offset()) {
                    epoch_it = _epochs.erase(epoch_it);
                } else {
                    std::vector<const chunk_info *> ok_chunks {};
                    for (const auto &chunk_ptr: epoch_it->second.chunks) {
                        if (chunk_ptr->offset < max_end_offset) {
                            ok_chunks.emplace_back(chunk_ptr);
                        }
                    }
                    epoch_it->second.chunks = std::move(ok_chunks);
                    ++epoch_it;
                }
            }
            if (!_epochs.empty()) {
                _notify_next_epoch = _epochs.rbegin()->first;
                _notify_end_offset = _epochs.rbegin()->second.end_offset();
            } else {
                _notify_next_epoch = 0;
                _notify_end_offset = 0;
            }
            while (chunk_it != _chunks.end()) {
                auto canon_path = full_path(chunk_it->second.rel_path());
                deleted_chunks.emplace(canon_path);
                if (del) std::filesystem::remove(canon_path);
                chunk_it = _chunks.erase(chunk_it);
            }
            if (!_chunks.empty()) {
                _end_offset = _chunks.rbegin()->second.end_offset();
            } else {
                _end_offset = 0;
            }
            _parse_start_offset = _end_offset;
            _parsed = 0;
            if (!deleted_chunks.empty())
                logger::info("truncated chunk registry to the end offset: {}", _end_offset);
            return deleted_chunks;
        }

        void import(const chunk_registry &src_cr, const bool strict=true)
        {
            uint8_vector raw_data {}, compressed_data {};
            target_offset(src_cr.num_bytes());
            for (const auto &[last_byte_offset, src_chunk]: src_cr.chunks()) {
                file::read_raw(src_cr.full_path(src_chunk.rel_path()), compressed_data);
                zstd::decompress(raw_data, compressed_data);
                auto data_hash = blake2b<cardano::block_hash>(raw_data);
                auto local_path = full_path(chunk_info::rel_path_from_hash(data_hash));
                file::write(local_path, compressed_data);
                add(src_chunk.offset, local_path, data_hash, src_chunk.orig_rel_path, strict);
            }
            save_state();
        }

        std::string add(const uint64_t offset, const std::string &local_path, const cardano::block_hash &data_hash, const std::string &orig_rel_path, const bool strict=true)
        {
            auto compressed = file::read_raw(local_path);
            uint8_vector data {};
            zstd::decompress(data, compressed);
            static auto noop = [](const auto &){};
            auto parsed_chunk = _parse(offset, orig_rel_path, data, compressed.size(), noop);
            if (parsed_chunk.data_hash != data_hash)
                throw error("data hash does not match for the chunk: {}", local_path);
            auto final_path = full_path(parsed_chunk.rel_path());
            if (final_path != local_path)
                std::filesystem::rename(local_path, final_path);
            _add(std::move(parsed_chunk), strict);
            return final_path;
        }

        virtual void clean_up()
        {
        }

        void target_offset(uint64_t offset)
        {
            _target_offset.emplace(offset);
        }
    protected:
        scheduler &_sched;
        const std::filesystem::path _data_dir;
        const std::filesystem::path _db_dir;
        std::optional<uint64_t> _target_offset {};
        uint64_t _end_offset = 0;
        mutable std::atomic_uint64_t _parsed = 0;
        uint64_t _parse_start_offset = 0;

        virtual std::pair<uint64_t, file_set> _load_state(bool strict=true)
        {
            timer t { "chunk-registry load state from " + _state_path, logger::level::debug };
            _chunks.clear();
            _epochs.clear();
            _end_offset = 0;
            file_set known_chunks {}, deletable_chunks {};
            if (std::filesystem::exists(_state_path)) {
                auto j = json::load(_state_path).as_object();
                uint64_t start_offset = 0;
                for (const auto &j: j.at("chunks").as_array()) {
                    auto chunk = chunk_info::from_json(j.as_object());
                    auto path = full_path(chunk.rel_path());
                    std::error_code ec {};
                    uint64_t file_size = std::filesystem::file_size(path, ec);
                    if (ec) {
                        logger::info("load_state: file access error for {}: {} - ignoring it and the following chunks!",
                            chunk.rel_path(), ec.message());
                        break;
                    }
                    if (file_size != chunk.compressed_size) {
                        logger::info("load_state: file size mismatch for {}: recorded: {} vs actual: {}: ignoring it and the following chunks!",
                            chunk.rel_path(), chunk.compressed_size, file_size);
                        break;
                    }
                    chunk.offset = start_offset;
                    start_offset += chunk.data_size;
                    _add(std::move(chunk), strict, false);
                    known_chunks.emplace(std::move(path));
                }
            }
            _notify_next_epoch = _epochs.empty() ? 0 : _epochs.rbegin()->first;
            _notify_end_offset = _end_offset;
            _parse_start_offset = _end_offset;
            logger::info("chunk_registry has data up to offset {}", _end_offset);
            for (const auto &entry: std::filesystem::recursive_directory_iterator { _db_dir }) {
                auto path = full_path(entry.path().string());
                if (entry.is_regular_file() && entry.path().extension() == ".zstd" && !known_chunks.contains(path))
                    deletable_chunks.emplace(std::move(path));
            }
            return std::make_pair(_end_offset, deletable_chunks);
        }

        virtual void _on_epoch_merge(uint64_t epoch, const epoch_info &info)
        {
            logger::trace("on_epoch_merge epoch: {} start_offset: {} end_offset: {}", epoch, info.start_offset(), info.end_offset());
        }

       virtual chunk_info _parse(uint64_t offset, const std::string &rel_path,
           const buffer &raw_data, size_t compressed_size, const block_processor &blk_proc) const
       {
            timer t { fmt::format("parsing chunk {} to add it to the registry", rel_path), logger::level::trace };
            chunk_info chunk { rel_path, raw_data.size(), compressed_size };
            chunk.offset = offset;
            blake2b(chunk.data_hash, raw_data);
            uint64_t prev_slot = 0;
            cbor_parser parser { raw_data };
            cbor_value block_tuple {};
            while (!parser.eof()) {
                parser.read(block_tuple);
                auto blk_ptr = cardano::make_block(block_tuple, chunk.offset + block_tuple.data - raw_data.data());
                auto &blk = *blk_ptr;
                try {
                    if (blk.slot() < prev_slot)
                        throw error("chunk {} at {}: a block's slot {} is less than the slot of the prev block {}!", rel_path, offset, blk.slot(), prev_slot);
                    prev_slot = blk.slot();
                    if (chunk.num_blocks == 0) {
                        chunk.prev_block_hash = blk.prev_hash();
                        chunk.first_slot = blk.slot();
                    }
                    chunk.num_blocks++;
                    chunk.last_block_hash = blk.hash();
                    chunk.last_slot = blk.slot();
                    blk_proc(blk);
                } catch (std::exception &ex) {
                    throw error("failed parsing block at slot {}/{} and offset {}: {}", blk.slot().epoch(), blk.slot(), blk.offset(), ex.what());
                }
            }
            auto new_parsed = atomic_add(_parsed, static_cast<uint64_t>(raw_data.size()));
            if (_target_offset)
                progress::get().update("parse", new_parsed, *_target_offset - _parse_start_offset);
            return chunk;
       }
    private:
        const std::string _state_path;
        alignas(mutex::padding) mutable std::mutex _update_mutex {};
        chunk_map _chunks {};
        chunk_map _unmerged_chunks {};
        epoch_map _epochs {};
        uint64_t _notify_end_offset = 0;
        uint64_t _notify_next_epoch = 0;
        const std::string _ext = ".zstd";
        static thread_local uint8_vector _read_buffer;

        void _add(chunk_info &&chunk, const bool strict=true, const bool notify=true)
        {
            if (_target_offset && *_target_offset < chunk.offset + chunk.data_size)
                throw error("chunk's data exceeds the target offset: {}", _target_offset);
            if (chunk.data_size == 0 || chunk.num_blocks == 0)
                throw error("empty chunks are not allowed: {}!", chunk.orig_rel_path);
            if (chunk.first_slot.epoch() != chunk.last_slot.epoch())
                throw error("chunks containing blocks from only one epoch are allowed: {}", chunk.orig_rel_path);
            std::scoped_lock lk { _update_mutex };
            auto [um_it, um_created] = _unmerged_chunks.try_emplace(chunk.offset + chunk.data_size - 1, std::move(chunk));
            // chunk variable should not be used after this point due to std::move(chunk) right above
            if (!um_created)
                throw error("internal error: duplicate chunk offset: {} size: {} from: {}", um_it->second.offset, um_it->second.data_size, um_it->second.orig_rel_path);
            while (!_unmerged_chunks.empty() && _unmerged_chunks.begin()->second.offset == _end_offset) {
                const auto &tested_chunk = _unmerged_chunks.begin()->second;
                if (strict) {
                    if (!_chunks.empty()) {
                        const auto &last = _chunks.rbegin()->second;
                        if (tested_chunk.first_slot < last.last_slot)
                            throw error("{} the new chunk's first slot {} is less than the last slot in the registry {}",
                                tested_chunk.orig_rel_path, tested_chunk.first_slot, last.last_slot);
                        if (last.last_block_hash != tested_chunk.prev_block_hash)
                            throw error("{} prev_block_hash {} does not match the prev chunk's ({}) last_block_hash of the last block {}",
                                tested_chunk.orig_rel_path, tested_chunk.prev_block_hash, last.orig_rel_path, last.last_block_hash);
                    } else {
                        static auto genesis_hash = cardano::block_hash::from_hex("5F20DF933584822601F9E3F8C024EB5EB252FE8CEFB24D1317DC3D432E940EBB");
                        if (tested_chunk.prev_block_hash != genesis_hash)
                            throw error("{}'s prev_block_hash {} does not match the genesis hash {}",
                                tested_chunk.orig_rel_path, tested_chunk.prev_block_hash, genesis_hash);
                    }
                }
                auto [it, created, node] = _chunks.insert(_unmerged_chunks.extract(_unmerged_chunks.begin()));
                const auto &inserted_chunk = it->second;
                if (!created)
                    throw error("internal error: duplicate chunk offset: {} size: {}", inserted_chunk.offset, inserted_chunk.data_size);
                _end_offset += inserted_chunk.data_size;
                _epochs[inserted_chunk.epoch()].chunks.emplace_back(&inserted_chunk);
            }
            if (notify)
                _notify_of_updates();
        }

        void _notify_of_updates(bool force=false)
        {
            while (_end_offset > _notify_end_offset && (_chunks.rbegin()->second.epoch() > _notify_next_epoch || force)) {
                auto notify_epoch = _chunks.rbegin()->second.epoch() > _notify_next_epoch ? _notify_next_epoch : _chunks.rbegin()->second.epoch();
                // in unit-tests chunks may have non-continuous ecpohs
                if (_epochs.contains(notify_epoch)) {
                    auto &info = _epochs.at(notify_epoch);
                    if (info.chunks.empty())
                        throw error("epoch {} does not have any chunks!", notify_epoch);
                    if (force) {
                        epoch_info info_part {};
                        for (const auto &chunk: info.chunks) {
                            if (chunk->offset >= _notify_end_offset)
                                info_part.chunks.emplace_back(chunk);
                        }
                        _on_epoch_merge(notify_epoch, info_part);
                    } else {
                        _on_epoch_merge(notify_epoch, info);
                    }
                    _notify_end_offset = info.end_offset();
                }
                _notify_next_epoch = notify_epoch + 1;
            }
        }

        chunk_map::const_iterator _find_it(uint64_t offset) const
        {
            const auto it = _chunks.lower_bound(offset);
            if (it == _chunks.end())
                throw error("no chunk matches offset: {}!", offset);
            return it;
        }
    };
}

#endif // !DAEDALUS_TURBO_CHUNK_REGISTRY_HPP
