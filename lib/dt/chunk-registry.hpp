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
#include <dt/file-remover.hpp>
#include <dt/json.hpp>
#include <dt/progress.hpp>
#include <dt/scheduler.hpp>
#include <dt/storage/chunk_info.hpp>
#include <dt/timer.hpp>

namespace daedalus_turbo {
    struct chunk_registry {
        // Shall be a multiple of an SSD's sector size and larger than Cardano's largest block (including Byron boundary ones too!)
        using chunk_info = storage::chunk_info;
        using chunk_map = std::map<uint64_t, chunk_info>;
        using chunk_list = std::vector<chunk_info>;

        struct active_transaction {
            uint64_t start_offset = 0;
            uint64_t target_offset = 0;
            bool prepared = false;
        };

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

        explicit chunk_registry(const std::string &data_dir, bool strict=true, scheduler &sched=scheduler::get(), file_remover &fr=file_remover::get())
            : _data_dir { data_dir }, _db_dir { init_db_dir((_data_dir / "compressed").string()) },
                _sched { sched }, _file_remover { fr }, _strict { strict },
                _state_path { (_db_dir / "state.json").string() },
                _state_pre_path { (_db_dir / "state-pre.json").string() }
        {
            timer t { "chunk-registry construct" };
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
                    _add(std::move(chunk), false);
                    known_chunks.emplace(std::move(path));
                }
            }
            for (const auto &entry: std::filesystem::recursive_directory_iterator { _db_dir }) {
                auto path = full_path(entry.path().string());
                if (entry.is_regular_file() && entry.path().extension() == ".zstd" && !known_chunks.contains(path))
                    _file_remover.mark(path);
            }
            logger::info("chunk_registry has data up to offset {}", num_bytes());
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
            std::filesystem::create_directories(canon_path.parent_path());
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
            mutex::scoped_lock lk { _update_mutex };
            return _epochs.at(epoch);
        }

        std::optional<chunk_info> last_chunk() const
        {
            if (!_chunks.empty()) [[likely]]
                return _chunks.rbegin()->second;
            return {};
        }

        cardano::slot max_slot() const
        {
            if (!_chunks.empty()) [[likely]]
                return _chunks.rbegin()->second.last_slot;
            return 0;
        }

        uint64_t num_bytes() const
        {
            if (!_chunks.empty()) [[likely]]
                return _chunks.rbegin()->second.end_offset();
            return 0;
        }

        size_t num_chunks() const
        {
            return _chunks.size();
        }

        scheduler &sched() const
        {
            return _sched;
        }

        file_remover &remover() const
        {
            return _file_remover;
        }

        std::optional<active_transaction> tx() const
        {
            return _transaction;
        }

        const std::filesystem::path &data_dir() const
        {
            return _data_dir;
        }

        const chunk_info &find(uint64_t offset) const
        {
            return _find_it(offset)->second;
        }

        chunk_map::const_iterator find_it(uint64_t offset) const
        {
            return _find_it(offset);
        }

        chunk_map::const_iterator find(const buffer &data_hash) const
        {
            return std::find_if(_chunks.begin(), _chunks.end(),
                [&](const auto &el) { return el.second.data_hash == data_hash; });
        }

        size_t count_blocks(const cardano::slot &first_slot, const cardano::slot &last_slot)
        {
            // cannot allow updates because that will invalidate the iterators
            mutex::scoped_lock lk { _update_mutex };
            auto it = std::lower_bound(_chunks.begin(), _chunks.end(), first_slot, [&](const auto &el, const auto &val) {
                return el.second.last_slot < val;
            });
            if (it == _chunks.end())
                throw error("requested slot {} is beyond max known slot", first_slot);
            if (it->second.first_slot > first_slot)
                throw error("no chunk has block with slot {}", first_slot);
            size_t num_data_blocks = 0;
            for (; it != _chunks.end() && it->second.first_slot <= last_slot; ++it) {
                const auto chunk_path = full_path(it->second.rel_path());
                const auto chunk_data = file::read(chunk_path);
                cbor_parser parser { chunk_data };
                cbor_value block_tuple {};
                while (!parser.eof()) {
                    parser.read(block_tuple);
                    const auto blk = cardano::make_block(block_tuple, it->second.offset + block_tuple.data - chunk_data.data());
                    if (blk->slot() > last_slot)
                        break;
                    if (blk->slot() >= first_slot && blk->era() > 0)
                        ++num_data_blocks;
                }
            }
            return num_data_blocks;
        }

        size_t count_blocks_in_window(const cardano::slot &first_slot, const uint64_t window_size=cardano::density_default_window)
        {
            return count_blocks(first_slot, first_slot + window_size);
        }

        void read(uint64_t offset, cbor_value &value)
        {
            if (offset >= num_bytes())
                throw error("the requested offset {} is larger than the maximum one: {}", offset, num_bytes());
            const auto &chunk = find(offset);
            if (offset >= chunk.offset + chunk.data_size)
                throw error("the requested chunk segment is too small to parse it");
            file::read(full_path(chunk.rel_path()), _read_buffer);
            size_t read_offset = offset - chunk.offset;
            size_t read_size = _read_buffer.size() - read_offset;
            cbor_parser parser(buffer { _read_buffer.data() + read_offset, read_size });
            parser.read(value);
        }

        // assumes no concurent modifications to chunk_refistry data
        template<typename T>
        bool parse_parallel(
            const std::function<void(T &res, const std::string &chunk_path, cardano::block_base &blk)> &act,
            const std::function<void(std::string &&chunk_path, T &&res)> &agg,
            const bool progress=true)
        {
            using parse_res = std::pair<std::string, T>;
            progress_guard pg { "parse" };
            std::atomic_size_t num_tasks = 0;
            std::atomic_size_t num_parsed = 0;
            _sched.on_result("parse-chunk", [&](auto &&res) {
                if (res.type() == typeid(scheduled_task_error))
                    return;
                auto &&[chunk_path, chunk_res] = std::any_cast<parse_res>(res);
                agg(std::move(chunk_path), std::move(chunk_res));
                progress::get().update("parse", ++num_parsed, num_tasks.load());
            });
            for (const auto &[chunk_offset, chunk_info]: _chunks) {
                ++num_tasks;
                _sched.submit("parse-chunk", 100, [this, chunk_offset, chunk_info, &act]() {
                    T res {};
                    auto canon_path = full_path(chunk_info.rel_path());
                    const auto data = file::read(canon_path);
                    cbor_parser block_parser { data };
                    cbor_value block_tuple {};
                    while (!block_parser.eof()) {
                        block_parser.read(block_tuple);
                        const auto blk = cardano::make_block(block_tuple, chunk_offset + block_tuple.data - data.data());
                        act(res, canon_path, *blk);
                    }
                    return parse_res { std::move(canon_path), std::move(res) };
                });
            }
            return _sched.process_ok(progress);
        }

        // state modifying methods

        void import(const chunk_registry &src_cr)
        {
            uint8_vector raw_data {}, compressed_data {};
            start_tx(num_bytes(), src_cr.num_bytes());
            for (const auto &[last_byte_offset, src_chunk]: src_cr.chunks()) {
                file::read_raw(src_cr.full_path(src_chunk.rel_path()), compressed_data);
                zstd::decompress(raw_data, compressed_data);
                auto data_hash = blake2b<cardano::block_hash>(raw_data);
                auto local_path = full_path(chunk_info::rel_path_from_hash(data_hash));
                file::write(local_path, compressed_data);
                add(src_chunk.offset, local_path, data_hash, src_chunk.orig_rel_path);
            }
            prepare_tx();
            commit_tx();
        }

        std::string add(const uint64_t offset, const std::string &local_path, const cardano::block_hash &data_hash, const std::string &orig_rel_path)
        {
            if (!_transaction)
                throw error("add can be executed only inside of a transaction!");
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
            _add(std::move(parsed_chunk));
            return final_path;
        }

        uint64_t valid_end_offset()
        {
            return _valid_end_offset_impl();
        }

        void start_tx(const uint64_t start_offset, const uint64_t target_offset, const bool truncate=true)
        {
            timer t { "chunk_registry::start_tx", logger::level::debug };
            if (_transaction)
                throw error("nested transactions are not allowed!");
            if (start_offset > num_bytes())
                throw error("start offset cannot be greater than the maximum offset!");
            if (start_offset > valid_end_offset())
                throw error("start_offset: {} is greater than valid_end_offset: {}!", start_offset, valid_end_offset());
            _transaction = active_transaction { start_offset, target_offset };
            if (truncate)
                _do_truncate(start_offset);
            _start_tx_impl();
        }

        void prepare_tx()
        {
            timer t { "chunk_registry::preapre_tx", logger::level::debug };
            if (!_transaction)
                throw error("prepare_tx can be executed only inside of a transaction!");
            _prepare_tx_impl();
            _do_truncate(valid_end_offset());
            _transaction->prepared = true;
        }

        void rollback_tx()
        {
            if (!_transaction)
                throw error("rollback_tx can be executed only inside of a transaction!");
            _rollback_tx_impl();
            _transaction.reset();
        }

        void commit_tx()
        {
            timer t { "chunk_registry::commit_tx", logger::level::debug };
            if (!_transaction)
                throw error("commit_tx can be executed only inside of a transaction!");
            if (!_transaction->prepared)
                throw error("commit_tx can only be executed after a successful prepare_tx!");
            _commit_tx_impl();
            _transaction.reset();
        }
    protected:
        const std::filesystem::path _data_dir;
        const std::filesystem::path _db_dir;
        scheduler &_sched;
        file_remover &_file_remover;
        const bool _strict = true;
        std::optional<active_transaction> _transaction {};

        virtual void _truncate_impl(uint64_t max_end_offset)
        {
            if (num_bytes() <= max_end_offset)
                return;
            timer t { fmt::format("chunk_registry::_truncate to size {}", max_end_offset) };
            auto chunk_it = _find_it(max_end_offset);
            if (chunk_it->second.offset != max_end_offset)
                throw error("cannot truncate to offsets not on the boundary between chunks!");
            auto epoch_it = _epochs.find(chunk_it->second.epoch());
            // filter chunks of the truncated epoch, must be ordered by their offsets
            for (size_t ci = 0; ci < epoch_it->second.chunks.size(); ++ci) {
                if (epoch_it->second.chunks[ci]->offset >= max_end_offset) {
                    epoch_it->second.chunks.resize(ci);
                    break;
                }
            }
            if (!epoch_it->second.chunks.empty())
                ++epoch_it;
            if (epoch_it != _epochs.end())
                _epochs.erase(epoch_it, _epochs.end());
            while (chunk_it != _chunks.end()) {
                _truncated_chunks.emplace_back(chunk_it->second);
                chunk_it = _chunks.erase(chunk_it);
            }
        }

        virtual void _start_tx_impl()
        {
            _parsed = 0;
            _parsed_base = num_bytes() - _transaction->start_offset;
            _notify_end_offset = num_bytes();
            _notify_next_epoch = _epochs.empty() ? 0 : _epochs.rbegin()->first;
        }

        virtual uint64_t _valid_end_offset_impl()
        {
            // chunks are updates only when they become mergeable
            return num_bytes();
        }

        virtual void _prepare_tx_impl()
        {
            timer t { "chunk_registry::_prepare_tx" };
            if (!_unmerged_chunks.empty()) {
                if (!_chunks.empty())
                    logger::trace("last merged chunk: {}", json::serialize(_chunks.rbegin()->second.to_json()));
                for (const auto &[last_byte_offset, uchunk]: _unmerged_chunks)
                    logger::trace("unmerged chunk with last byte offset {}: {}", last_byte_offset, json::serialize(uchunk.to_json()));
                logger::warn("{} unmerged chunks - ignoring them", _unmerged_chunks.size());
                _unmerged_chunks.clear();
            }
            {
                mutex::unique_lock update_lk { _update_mutex };
                _notify_of_updates(update_lk, true);
            }
            // let the operations potentially scheduled in _on_epoch_merge calls to finish
            _sched.process(true);
            _save_json_chunks(_state_pre_path);
        }

        virtual void _rollback_tx_impl()
        {
            throw error("rollback_tx not implemented!");
        }

        virtual void _commit_tx_impl()
        {
            if (!std::filesystem::exists(_state_pre_path))
                throw error("the prepared chunk_registry state file is missing: {}!", _state_pre_path);
            std::filesystem::rename(_state_pre_path, _state_path);
            for (const auto &chunk: _truncated_chunks)
                _file_remover.mark(full_path(chunk.rel_path()));
            for (const auto &[last_byte_offset, chunk]: _chunks)
                _file_remover.unmark(full_path(chunk.rel_path()));
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
            // allow up to 5 seconds of time difference as Daedalus does currently
            auto max_slot = cardano::slot::from_time(std::chrono::system_clock::now() + std::chrono::seconds { 5 });
            cbor_parser parser { raw_data };
            cbor_value block_tuple {};
            while (!parser.eof()) {
                parser.read(block_tuple);
                auto blk_ptr = cardano::make_block(block_tuple, chunk.offset + block_tuple.data - raw_data.data());
                auto &blk = *blk_ptr;
                try {
                    auto slot = blk.slot();
                    if (slot >= max_slot)
                        throw error("a block with time slot from the future: {}!", slot);
                    if (slot < prev_slot)
                        throw error("chunk {} at {}: a block's slot {} is less than the slot of the prev block {}!", rel_path, offset, slot, prev_slot);
                    prev_slot = slot;
                    if (chunk.num_blocks == 0) {
                        chunk.prev_block_hash = blk.prev_hash();
                        chunk.first_slot = slot;
                    }
                    ++chunk.num_blocks;
                    chunk.last_block_hash = blk.hash();
                    chunk.last_slot = slot;
                    blk_proc(blk);
                } catch (std::exception &ex) {
                    throw error("failed parsing block at slot {}/{} and offset {}: {}", blk.slot().epoch(), blk.slot(), blk.offset(), ex.what());
                }
            }
            auto new_parsed = atomic_add(_parsed, static_cast<uint64_t>(raw_data.size()));
            progress::get().update("parse", _parsed_base + new_parsed, _transaction->target_offset - _transaction->start_offset);
            return chunk;
       }
    private:
        const std::string _state_path;
        const std::string _state_pre_path;
        alignas(mutex::padding) mutable mutex::unique_lock::mutex_type _update_mutex {};
        chunk_map _chunks {};
        chunk_map _unmerged_chunks {};
        epoch_map _epochs {};
        // Active transaction data
        uint64_t _parsed_base = 0;
        mutable std::atomic_uint64_t _parsed = 0;
        uint64_t _notify_end_offset = 0;
        uint64_t _notify_next_epoch = 0;
        std::vector<chunk_info> _truncated_chunks {};

        static thread_local uint8_vector _read_buffer;

        void _save_json_chunks(const std::string &path)
        {
            // the caller is responsible to hold a lock protecting access to the _chunks!
            json::array j_chunks {};
            for (const auto &[max_offset, chunk]: _chunks)
                j_chunks.emplace_back(chunk.to_json());
            json::save_pretty(path, json::object { { "chunks", j_chunks } });
        }

        void _do_truncate(size_t max_end_offset)
        {
            if (!_transaction)
                throw error("truncate can be executed only inside of a transaction!");
            if (num_bytes() > max_end_offset)
                _truncate_impl(max_end_offset);
        }

        void _add(chunk_info &&chunk, const bool normal=true)
        {
            if (normal && _transaction->target_offset < chunk.offset + chunk.data_size)
                throw error("chunk's data exceeds the target offset: {}", _transaction->target_offset);
            if (chunk.data_size == 0 || chunk.num_blocks == 0)
                throw error("empty chunks are not allowed: {}!", chunk.orig_rel_path);
            if (chunk.first_slot.epoch() != chunk.last_slot.epoch())
                throw error("chunks containing blocks from only one epoch are allowed: {}", chunk.orig_rel_path);
            mutex::unique_lock update_lk { _update_mutex };
            auto [um_it, um_created] = _unmerged_chunks.try_emplace(chunk.offset + chunk.data_size - 1, std::move(chunk));
            // chunk variable should not be used after this point due to std::move(chunk) right above
            if (!um_created)
                throw error("internal error: duplicate chunk offset: {} size: {} from: {}", um_it->second.offset, um_it->second.data_size, um_it->second.orig_rel_path);
            while (!_unmerged_chunks.empty() && _unmerged_chunks.begin()->second.offset == num_bytes()) {
                const auto &tested_chunk = _unmerged_chunks.begin()->second;
                if (_strict) {
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
                _epochs[inserted_chunk.epoch()].chunks.emplace_back(&inserted_chunk);
            }
            if (normal)
                _notify_of_updates(update_lk);
        }

        void _notify_of_updates(mutex::unique_lock &update_lk, bool force=false)
        {
            if (!update_lk)
                throw error("update_mutex must be locked when _notify_of_updates is called!");
            const auto max_epoch = max_slot().epoch();
            const auto end_offset = num_bytes();
            if (!force && _transaction->target_offset == end_offset)
                force = true;
            while (end_offset > _notify_end_offset && (_notify_next_epoch < max_epoch || (force && _notify_next_epoch == max_epoch))) {
                // in unit-tests chunks may have non-continuous ecpohs
                if (_epochs.contains(_notify_next_epoch)) {
                    const auto &epoch_info = _epochs.at(_notify_next_epoch);
                    if (epoch_info.chunks.empty())
                        throw error("epoch {} does not have any chunks!", _notify_next_epoch);
                    auto epoch_info_copy = epoch_info;
                    epoch_info_copy.chunks.clear();
                    for (const auto *chunk: epoch_info.chunks) {
                        if (chunk->offset >= _notify_end_offset)
                            epoch_info_copy.chunks.emplace_back(chunk);
                    }
                    if (!epoch_info_copy.chunks.empty()) {
                        // experimental support for on-the-go checkpoints
                        _save_json_chunks(_state_path);
                        _on_epoch_merge(_notify_next_epoch, epoch_info_copy);
                    }
                    _notify_end_offset = epoch_info.end_offset();
                }
                ++_notify_next_epoch;
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