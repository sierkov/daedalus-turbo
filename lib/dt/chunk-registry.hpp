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
#include <dt/file.hpp>
#include <dt/json.hpp>
#include <dt/progress.hpp>
#include <dt/scheduler.hpp>
#include <dt/timer.hpp>

namespace daedalus_turbo {
    struct chunk_registry {
        // Shall be a multiple of an SSD's sector size and larger than Cardano's largest block (including Byron boundary ones too!)
        static constexpr size_t max_read_size = 1 << 18;

        struct chunk_info {
            std::string orig_rel_path {};
            size_t data_size = 0;
            size_t compressed_size = 0;
            size_t num_blocks = 0;
            cardano::slot first_slot {};
            cardano::slot last_slot {};
            cardano_hash_32 data_hash {};
            cardano_hash_32 prev_block_hash {};
            cardano_hash_32 last_block_hash {};
            uint64_t offset = 0;

            std::string rel_path() const
            {
                return fmt::format("{}/{}.zstd", is_volatile() ? "volatile" : "immutable", data_hash.span());
            }

            uint64_t end_offset() const
            {
                return offset + data_size;
            }

            bool is_volatile() const
            {
                static std::string match { "volatile" };
                return orig_rel_path.size() > match.size() && orig_rel_path.substr(0, match.size()) == match;
            }

            uint64_t epoch() const
            {
                return first_slot.epoch();
            }

            static chunk_info from_json(const json::object &j)
            {
                chunk_info chunk {};
                chunk.orig_rel_path = json::value_to<std::string_view>(j.at("relPath"));
                if (j.contains("offset"))
                    chunk.offset = json::value_to<size_t>(j.at("offset"));
                chunk.data_size = json::value_to<size_t>(j.at("size"));
                chunk.compressed_size = json::value_to<size_t>(j.at("compressedSize"));
                chunk.num_blocks = json::value_to<size_t>(j.at("numBlocks"));
                chunk.first_slot = json::value_to<uint64_t>(j.at("firstSlot"));
                chunk.last_slot = json::value_to<uint64_t>(j.at("lastSlot"));
                chunk.data_hash = bytes_from_hex(json::value_to<std::string_view>(j.at("hash")));
                chunk.prev_block_hash = bytes_from_hex(json::value_to<std::string_view>(j.at("prevBlockHash")));
                chunk.last_block_hash = bytes_from_hex(json::value_to<std::string_view>(j.at("lastBlockHash")));
                return chunk;
            }

            json::object to_json() const
            {
                return json::object {
                    { "relPath", orig_rel_path },
                    { "size", data_size },
                    { "compressedSize", compressed_size },
                    { "numBlocks", num_blocks },
                    { "firstSlot", (size_t)first_slot },
                    { "lastSlot", (size_t)last_slot },
                    { "hash", fmt::format("{}", data_hash.span()) },
                    { "prevBlockHash", fmt::format("{}", prev_block_hash.span()) },
                    { "lastBlockHash", fmt::format("{}", last_block_hash.span()) }
                };
            }
        };

        using chunk_map = std::map<uint64_t, chunk_info>;
        using chunk_list = std::vector<chunk_info>;

        struct epoch_info {
            size_t num_blocks = 0;
            cardano::slot first_slot {};
            cardano::slot last_slot {};
            cardano_hash_32 prev_block_hash {};
            cardano_hash_32 last_block_hash {};
            std::vector<const chunk_info *> chunk_ids {};
            uint64_t start_offset = 0;
            uint64_t end_offset = 0;
        };
        using epoch_map = std::map<size_t, epoch_info>;
        using file_set = std::set<std::string>;
        template<typename T>
        using parse_res = std::map<std::string, std::vector<T>>;
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

        virtual ~chunk_registry()
        {
        }

        virtual void add(chunk_info &&chunk, bool strict=true, bool notify=true)
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
                throw error("internal error: duplicate chunk offset: {} size: {}", um_it->second.offset, um_it->second.data_size);
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
                auto &epoch_data = _epochs[inserted_chunk.epoch()];
                _add_chunk_to_epoch(epoch_data, inserted_chunk);
            }
            if (notify && strict)
                _notify_of_updates();
        }

        virtual void clean_up()
        {
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

        const std::optional<chunk_info> last_chunk() const
        {
            std::optional<chunk_info> chunk {};
            if (!_chunks.empty())
                chunk.emplace(_chunks.rbegin()->second);
            return chunk;
        }

        const std::string rel_path(const std::filesystem::path &full_path) const
        {
            auto canon_path = std::filesystem::weakly_canonical(full_path);
            const auto canon_str = canon_path.string();
            auto canon_simple_path = std::filesystem::weakly_canonical(_db_dir / "a");
            auto canon_simple_str = canon_simple_path.string();
            canon_simple_str = canon_simple_str.substr(0, canon_simple_str.size() - 1);
            if (canon_str.size() <= canon_simple_str.size()
                    || canon_str.substr(0, canon_simple_str.size()) != canon_simple_str)
                throw error("the supplied path '{}' is not inside the host directory '{}'", canon_str, canon_simple_str);
            return canon_str.substr(canon_simple_str.size());
        }

        const std::string full_path(const std::filesystem::path &rel_path) const
        {
            auto canon_path = std::filesystem::weakly_canonical(_db_dir  / rel_path);
            if (canon_path.string().size() < _db_dir.string().size()
                    || canon_path.string().substr(0, _db_dir.string().size()) != _db_dir.string())
                throw error("a relative path '{}' produced a full path '{}' which is not inside the host direactory '{}'", rel_path.string(), canon_path.string(), _db_dir.string());
            auto save_dir = canon_path.parent_path();
            if (!std::filesystem::exists(save_dir))
                std::filesystem::create_directories(save_dir);
            return canon_path.string();
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
                if (chunk_it->second.offset <= epoch_it->second.start_offset) {
                    epoch_it = _epochs.erase(epoch_it);
                } else {
                    std::vector<const chunk_info *> ok_chunks {};
                    for (const auto &chunk_ptr: epoch_it->second.chunk_ids) {
                        if (chunk_ptr->offset < max_end_offset) {
                            ok_chunks.emplace_back(chunk_ptr);
                        } else {
                            epoch_it->second.num_blocks -= chunk_ptr->num_blocks;
                        }
                    }
                    epoch_it->second.end_offset = max_end_offset;
                    epoch_it->second.last_block_hash = ok_chunks.back()->last_block_hash;
                    epoch_it->second.last_slot = ok_chunks.back()->last_slot;
                    epoch_it->second.chunk_ids = std::move(ok_chunks);
                    epoch_it++;
                }
            }
            if (!_epochs.empty()) {
                _notify_next_epoch = _epochs.rbegin()->first;
                _notify_end_offset = _epochs.rbegin()->second.end_offset;
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
                const auto &last_chunk = _chunks.rbegin()->second;
                _end_offset = last_chunk.offset + last_chunk.data_size;
            } else {
                _end_offset = 0;
            }
            _parse_start_offset = _end_offset;
            _parsed = 0;
            if (!deleted_chunks.empty())
                logger::info("truncated chunk registry to the end offset: {}", _end_offset);
            return deleted_chunks;
        }

        cardano::slot max_slot() const
        {
            if (_chunks.size() == 0)
                return 0;
            return _chunks.rbegin()->second.last_slot;
        }

        size_t num_bytes() const
        {
            return _end_offset;
        }

        size_t num_chunks() const
        {
            return _chunks.size();
        }

        const chunk_info &find(uint64_t offset) const
        {
            auto it = _find_it(offset);
            return it->second;
        }

        const chunk_map::const_iterator find(const buffer &data_hash) const
        {
            return std::find_if(_chunks.begin(), _chunks.end(),
                [&](const auto &el) { return el.second.data_hash == data_hash; });
        }

        void read(uint64_t offset, cbor_value &value, const size_t read_size=max_read_size)
        {
            read(offset, value, _read_buffer, read_size);
        }

        void read(uint64_t offset, cbor_value &value, uint8_vector &read_buffer, size_t read_size=max_read_size)
        {
            if (offset >= _end_offset)
                throw error("the requested offset {} is larger than the maximum one: {}", offset, _end_offset);
            const auto &chunk = find(offset);
            if (offset >= chunk.offset + chunk.data_size)
                throw error("the requested chunk segment is too small to parse it");
            file::read(full_path(chunk.rel_path()), read_buffer);
            size_t read_offset = offset - chunk.offset;
            if (read_offset + read_size > read_buffer.size())
                read_size = read_buffer.size() - read_offset;
            cbor_parser parser(buffer { read_buffer.data() + read_offset, read_size });
            parser.read(value);
        }

        template<typename T>
        parse_res<T> parallel_parse(const std::function<T(const std::string &chunk_path, cardano::block_base &blk)> &act, bool progress=false)
        {
            parse_res<T> results {};
            _sched.on_result("parse-chunk", [&](const auto &res) {
                if (res.type() == typeid(scheduled_task_error))
                    return;
                const auto &[chunk_path, chunk_res] = std::any_cast<typename parse_res<T>::value_type>(res);
                auto &chunk_res_all = results[chunk_path];
                for (const auto &r: chunk_res) chunk_res_all.emplace_back(r);
            });
            for (const auto &[chunk_offset, chunk_info]: _chunks) {
                _sched.submit("parse-chunk", 100, [this, chunk_offset, chunk_info, &act]() {
                    std::vector<T> res {};
                    auto data = file::read(full_path(chunk_info.rel_path()));
                    buffer buf { data };
                    cbor_parser block_parser { buf };
                    cbor_value block_tuple;
                    auto canon_path = full_path(chunk_info.rel_path());
                    while (!block_parser.eof()) {
                        block_parser.read(block_tuple);
                        auto blk = cardano::make_block(block_tuple, chunk_offset + block_tuple.data - buf.data());
                        res.emplace_back(act(canon_path, *blk));
                    }
                    return typename parse_res<T>::value_type { canon_path, std::move(res) };
                });
            }
            _sched.process(progress);
            return results;
        }

        virtual chunk_info parse(uint64_t offset, const std::string &rel_path, const buffer &raw_data, size_t compressed_size) const
        {
            timer t { fmt::format("parsing chunk {} to add it to the registry", rel_path), logger::level::trace };
            static auto noop = [](const auto &){};
            auto chunk = _parse_normal(offset, rel_path, raw_data, compressed_size, noop);
            auto new_parsed = atomic_add(_parsed, static_cast<uint64_t>(raw_data.size()));
            if (_target_offset) {
                progress::get().update("parse", new_parsed, *_target_offset - _parse_start_offset);
            }
            return chunk;
        }

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
            std::ostringstream json_s {};
            json_s << "{\n"
                << "  \"chunks\": [\n";
            for (const auto &[max_offset, chunk]: _chunks) {
                json_s << "      " << json::serialize(chunk.to_json());
                if (chunk.offset + chunk.data_size < _end_offset)
                    json_s << ',';
                json_s << '\n';
            }
            json_s << "  ]\n"
                << "}\n";
            file::write(_state_path, json_s.str());
            _parse_start_offset = _end_offset;
            _parsed = 0;
        }

        void target_offset(uint64_t offset)
        {
            _target_offset.emplace(offset);
        }

        const std::optional<uint64_t> target_offset() const
        {
            return _target_offset;
        }

        const std::filesystem::path &data_dir() const
        {
            return _data_dir;
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
                    add(std::move(chunk), strict, false);
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
            logger::trace("on_epoch_merge epoch: {} start_offset: {} end_offset: {}", epoch, info.start_offset, info.end_offset);
        }

        void _parse_immutable_chunk(const chunk_info &chunk, const buffer &raw_data, const block_processor &blk_proc) const
        {
            cbor_parser parser { raw_data };
            cbor_value block_tuple {};
            while (!parser.eof()) {
                parser.read(block_tuple);
                auto blk = cardano::make_block(block_tuple, chunk.offset + block_tuple.data - raw_data.data());
                try {
                    blk_proc(*blk);
                } catch (std::exception &ex) {
                    throw error("failed parsing block at slot {}/{} and offset {}: {}", blk->slot().epoch(), blk->slot(), blk->offset(), ex.what());
                }
            }
        }

        void _parse_chunk(const chunk_info &chunk, const buffer &raw_data, const block_processor &blk_proc) const
        {
            _parse_immutable_chunk(chunk, raw_data, blk_proc);
        }

       virtual chunk_info _parse_normal(uint64_t offset, const std::string &rel_path,
            const buffer &raw_data, size_t compressed_size, const block_processor &extra_proc) const
        {
            chunk_info chunk { rel_path, raw_data.size(), compressed_size };
            chunk.offset = offset;
            blake2b(chunk.data_hash, raw_data);
            uint64_t prev_slot = 0;
            _parse_chunk(chunk, raw_data, [&](const auto &blk) {
                if (blk.era() > 0) {
                    if (blk.slot() > 0 && blk.slot() <= prev_slot)
                        throw error("chunk {} at {}: a block's slot {} is less than the slot of the prev block {}!", rel_path, offset, blk.slot(), prev_slot);
                    else
                        prev_slot = blk.slot();
                }
                if (chunk.num_blocks == 0) {
                    chunk.prev_block_hash = blk.prev_hash();
                    chunk.first_slot = blk.slot();
                }
                chunk.num_blocks++;
                chunk.last_block_hash = blk.hash();
                chunk.last_slot = blk.slot();
                extra_proc(blk);
            });
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

        void _add_chunk_to_epoch(epoch_info &epoch_data, const chunk_info &inserted_chunk)
        {
            epoch_data.num_blocks += inserted_chunk.num_blocks;
            if (epoch_data.chunk_ids.empty()) {
                epoch_data.first_slot = inserted_chunk.first_slot;
                epoch_data.prev_block_hash = inserted_chunk.prev_block_hash;
                epoch_data.start_offset = inserted_chunk.offset;
            }
            epoch_data.last_slot = inserted_chunk.last_slot;
            epoch_data.last_block_hash = inserted_chunk.last_block_hash;
            epoch_data.end_offset = inserted_chunk.offset + inserted_chunk.data_size;
            epoch_data.chunk_ids.emplace_back(&inserted_chunk);
        }

        void _notify_of_updates(bool force=false)
        {
            while (_end_offset > _notify_end_offset && (_chunks.rbegin()->second.epoch() > _notify_next_epoch || force)) {
                auto notify_epoch = _chunks.rbegin()->second.epoch() > _notify_next_epoch ? _notify_next_epoch : _chunks.rbegin()->second.epoch();
                // in unit-tests chunks may have non-continuous ecpohs
                if (_epochs.contains(notify_epoch)) {
                    auto &info = _epochs.at(notify_epoch);
                    if (info.chunk_ids.empty())
                        throw error("epoch {} does not have any chunks!", notify_epoch);
                    if (force) {
                        epoch_info info_part {};
                        for (const auto &chunk: info.chunk_ids) {
                            if (chunk->offset >= _notify_end_offset)
                                _add_chunk_to_epoch(info_part, *chunk);
                        }
                        _on_epoch_merge(notify_epoch, info_part);
                    } else {
                        _on_epoch_merge(notify_epoch, info);
                    }
                    _notify_end_offset = info.end_offset;
                }
                _notify_next_epoch = notify_epoch + 1;
            }
        }

        chunk_map::const_iterator _find_it(uint64_t offset) const
        {
            auto it = _chunks.lower_bound(offset);
            if (it == _chunks.end())
                throw error("no chunk matches offset: {}!", offset);
            return it;
        }
    };
}

#endif // !DAEDALUS_TURBO_CHUNK_REGISTRY_HPP