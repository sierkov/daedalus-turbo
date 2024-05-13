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
#include <dt/zpp.hpp>

namespace daedalus_turbo {
    typedef uint64_t chunk_offset_t;

    struct chunk_registry {
        // Shall be a multiple of an SSD's sector size and larger than Cardano's largest block (including Byron boundary ones too!)
        using chunk_info = storage::chunk_info;
        using chunk_map = std::map<uint64_t, chunk_info>;
        using chunk_list = std::vector<chunk_info>;
        using chunk_reverse_iterator = chunk_map::const_reverse_iterator;

        struct active_transaction {
            uint64_t start_offset = 0;
            uint64_t target_offset = 0;
            bool prepared = false;
        };

        struct epoch_info {
            using chunk_list = std::vector<const chunk_info *>;

            epoch_info(chunk_list &&chunks): _chunks { std::move(chunks) }
            {
                if (_chunks.empty())
                    throw error("chunk list cannot be empty!");
            }

            const chunk_list &chunks() const
            {
                return _chunks;
            }

            const cardano::block_hash &prev_block_hash() const
            {
                return _chunks.front()->prev_block_hash;
            }

            [[nodiscard]] const cardano::block_hash &last_block_hash() const
            {
                return _chunks.back()->last_block_hash;
            }

            [[nodiscard]] cardano::slot last_slot() const
            {
                return _chunks.back()->last_slot;
            }

            [[nodiscard]] uint64_t start_offset() const
            {
                return _chunks.front()->offset;
            }

            [[nodiscard]] uint64_t end_offset() const
            {
                return _chunks.back()->end_offset();
            }

            [[nodiscard]] uint64_t size() const
            {
                return end_offset() - start_offset();
            }

            [[nodiscard]] uint64_t compressed_size() const
            {
                uint64_t sz = 0;
                for (const auto *chunk: _chunks)
                    sz += chunk->compressed_size;
                return sz;
            }
        private:
            chunk_list _chunks;
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
                _state_path { (_db_dir / "state.bin").string() },
                _state_path_pre { (_db_dir / "state-pre.bin").string() }
        {
            timer t { "chunk-registry construct" };
            file_set known_chunks {}, deletable_chunks {};
            chunk_map chunks {};
            if (std::filesystem::exists(_state_path))
                zpp::load(chunks, _state_path);
            for (auto &&[last_byte_offset, chunk]: chunks) {
                const auto path = full_path(chunk.rel_path());
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
                _add(std::move(chunk), false);
                known_chunks.emplace(std::move(path));
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

        epoch_map epochs() const
        {
            mutex::scoped_lock lk { _update_mutex };
            epoch_map eps {};
            std::optional<uint64_t> last_epoch {};
            epoch_info::chunk_list chunks {};
            for (const auto &[last_byte_offset, chunk]: _chunks) {
                if (!last_epoch || *last_epoch != chunk.epoch()) {
                    if (last_epoch && !chunks.empty())
                        eps.try_emplace(*last_epoch, std::move(chunks));
                    last_epoch = chunk.epoch();
                    chunks.clear();
                }
                chunks.emplace_back(&chunk);
            }
            if (last_epoch && !chunks.empty())
                eps.try_emplace(*last_epoch, std::move(chunks));
            return eps;
        }

        bool has_epoch(uint64_t epoch) const
        {
            mutex::unique_lock lk { _update_mutex };
            return _has_epoch(epoch, lk);
        }

        epoch_info epoch(uint64_t epoch) const
        {
            epoch_info::chunk_list chunks {};
            auto chunk_it = std::lower_bound(_chunks.begin(), _chunks.end(), epoch,
                [](const auto &el, const auto &epoch) { return el.second.epoch() < epoch; });
            for (; chunk_it != _chunks.end() && chunk_it->second.epoch() == epoch; ++chunk_it) {
                chunks.emplace_back(&chunk_it->second);
            }
            return { std::move(chunks) };
        }

        std::optional<chunk_info> last_chunk() const
        {
            if (!_chunks.empty()) [[likely]]
                return _chunks.rbegin()->second;
            return {};
        }

        std::optional<storage::block_info> last_block() const
        {
            if (!_chunks.empty()) [[likely]] {
                return _chunks.rbegin()->second.blocks.back();
            }
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

        uint64_t num_compressed_bytes() const
        {
            if (!_chunks.empty()) [[likely]]
                return std::accumulate(_chunks.begin(), _chunks.end(), 0ULL,
                    [](auto sum, const auto &chunk) { return sum + chunk.second.compressed_size; });
            return 0;
        }

        size_t num_chunks() const
        {
            return _chunks.size();
        }

        size_t num_blocks() const
        {
            return std::accumulate(_chunks.begin(), _chunks.end(), static_cast<size_t>(0),
                [](auto sum, const auto &val) { return sum + val.second.blocks.size(); });
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

        const storage::block_info &find_block(uint64_t tx_offset) const
        {
            const auto chunk_it = _find_chunk_by_offset(tx_offset);
            if (chunk_it == _chunks.end())
                throw error("unknown offset: {}!", tx_offset);
            const auto block_it = _find_block_by_offset(chunk_it, tx_offset);
            if (block_it == chunk_it->second.blocks.end())
                throw error("unknown offset: {}!", tx_offset);
            if (!(tx_offset >= block_it->offset && tx_offset < block_it->offset + block_it->size))
                throw error("internal error: block metadata does not match the transaction!");
            return *block_it;
        }

        const storage::block_info &find_block(const cardano::slot &slot) const
        {
            const auto chunk_it = _find_chunk_by_slot(slot);
            if (chunk_it == _chunks.end())
                throw error("internal error: no block registered at a slot: {}!", slot);
            const auto block_it = _find_block_by_slot(chunk_it, slot);
            if (block_it == chunk_it->second.blocks.end())
                throw error("internal error: no block registered at a slot: {}!", slot);
            if (block_it->slot != slot)
                throw error("internal error: no block registered at a slot: {}!", slot);
            return *block_it;
        }

        const storage::block_info &find_block(const cardano::slot &slot, const cardano::block_hash &hash) const
        {
            auto chunk_it = _find_chunk_by_slot(slot);
            if (chunk_it == _chunks.end())
                throw error("internal error: no block registered at a slot: {}!", slot);
            auto block_it = _find_block_by_slot(chunk_it, slot);
            if (block_it == chunk_it->second.blocks.end())
                throw error("internal error: no block registered at a slot: {}!", slot);
            if (block_it->slot != slot)
                throw error("internal error: no block registered at a slot: {}!", slot);
            while (block_it->hash != hash && block_it->slot == slot) {
                if (++block_it == chunk_it->second.blocks.end()) {
                    if (++chunk_it == _chunks.end())
                        throw error("internal error: no block registered at a slot {} with hash {}!", slot, hash);
                    block_it = chunk_it->second.blocks.begin();
                }
            }
            if (block_it->slot != slot || block_it->hash != hash)
                throw error("internal error: no block registered at a slot {} with hash {}!", slot, hash);
            return *block_it;
        }

        uint64_t find_epoch(const uint64_t offset) const
        {
            mutex::scoped_lock lk { _update_mutex };
            return find_offset(offset).epoch();
        }

        const chunk_info &find_offset(uint64_t offset) const
        {
            return _find_chunk_by_offset(offset)->second;
        }

        const chunk_info &find_last_block_hash(const buffer &last_block_hash) const
        {
            const auto it = std::find_if(_chunks.begin(), _chunks.end(),
                                         [&](const auto &el) { return el.second.last_block_hash == last_block_hash; });
            if (it == _chunks.end())
                throw error("there is no chunk with its last block hash {}", last_block_hash);
            return it->second;
        }

        chunk_map::const_iterator find_slot_it(const cardano::slot &slot) const
        {
            const auto chunk_it = _find_chunk_by_slot(slot);
            if (chunk_it == _chunks.end())
                throw error("there is no chunk with a block at slot {}", slot);
            return chunk_it;
        }

        chunk_map::const_iterator find_offset_it(uint64_t offset) const
        {
            return _find_chunk_by_offset(offset);
        }

        chunk_map::const_iterator find_data_hash_it(const buffer &data_hash) const
        {
            return std::find_if(_chunks.begin(), _chunks.end(),
                [&](const auto &el) { return el.second.data_hash == data_hash; });
        }

        size_t count_blocks(const std::optional<cardano::point> &start_point, const cardano::slot &last_slot)
        {
            // cannot allow updates because that will invalidate the iterators
            mutex::scoped_lock lk { _update_mutex };
            size_t num_data_blocks = 0;
            auto chunk_it = start_point ? _find_chunk_by_slot(start_point->slot) : _chunks.begin();
            bool seen_start_hash = false;
            for (; chunk_it != _chunks.end() && chunk_it->second.first_slot <= last_slot; ++chunk_it) {
                for (const auto &block: chunk_it->second.blocks) {
                    if (block.slot > last_slot)
                        break;
                    if (start_point) {
                        if (block.slot < start_point->slot)
                            continue;
                        // There is a miniscule probability that multiple blocks are generated in the same slot.
                        // In this case, we must start counting only after seeing the right block hash
                        if (block.slot == start_point->slot) {
                            if (!seen_start_hash && block.hash != start_point->hash)
                                continue;
                            seen_start_hash = true;
                        }
                    }
                    if (block.era > 0)
                        ++num_data_blocks;
                }
            }
            return num_data_blocks;
        }

        size_t count_blocks_in_window(const std::optional<cardano::point> &start_point={}, const uint64_t window_size=cardano::density_default_window)
        {
            return count_blocks(start_point, start_point ? start_point->slot + window_size : window_size);
        }

        void read(uint64_t offset, cbor_value &value)
        {
            if (offset >= num_bytes())
                throw error("the requested offset {} is larger than the maximum one: {}", offset, num_bytes());
            const auto &chunk = find_offset(offset);
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
            const auto compressed = file::read_raw(local_path);
            uint8_vector data {};
            zstd::decompress(data, compressed);
            static auto noop = [](const auto &){};
            auto parsed_chunk = _parse(offset, orig_rel_path, data, compressed.size(), noop);
            if (parsed_chunk.data_hash != data_hash)
                throw error("data hash does not match for the chunk: {}", local_path);
            const auto final_path = full_path(parsed_chunk.rel_path());
            if (final_path != local_path)
                std::filesystem::rename(local_path, final_path);
            _add(std::move(parsed_chunk));
            return final_path;
        }

        uint64_t valid_end_offset()
        {
            return _valid_end_offset_impl();
        }

        uint64_t max_end_offset()
        {
            return _max_end_offset_impl();
        }

        std::exception_ptr transact(const uint64_t start_offset, const uint64_t target_offset, const std::function<void()> &action)
        {
            auto ex_ptr = logger::run_log_errors([&] {
                start_tx(start_offset, target_offset);
                action();
                prepare_tx();
                commit_tx();
            });
            if (ex_ptr) {
                logger::run_log_errors([&] {
                    rollback_tx();
                });
            }
            return ex_ptr;
        }

        std::exception_ptr transact(const uint64_t start_offset, const std::function<void()> &action)
        {
            return transact(start_offset, std::numeric_limits<uint64_t>::max(), action);
        }

        void truncate(const uint64_t max_end_offset)
        {
            transact(max_end_offset, max_end_offset, [] {});
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
            // must happen before a potential truncate below
            if (!_truncated_chunks.empty()) {
                logger::warn("truncated chunks weren't empty at the beginning of a tx - recovering from an error?");
                _truncated_chunks.clear();
            }
            if (truncate)
                _do_truncate(start_offset);
            _start_tx_impl();
        }

        void prepare_tx()
        {
            timer t { "chunk_registry::prepare_tx", logger::level::debug };
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
            if (num_bytes() > max_end_offset) {
                timer t { fmt::format("chunk_registry::_truncate to size {}", max_end_offset), logger::level::info };
                auto chunk_it = _find_chunk_by_offset(max_end_offset);
                if (chunk_it->second.offset < max_end_offset) {
                    auto block_it = _find_block_by_offset(chunk_it, max_end_offset);
                    if (block_it == chunk_it->second.blocks.end())
                        throw error("internal error: no block covers offset {}", max_end_offset);
                    // truncate chunk data and update its metadata
                    auto &chunk = chunk_it->second;
                    _truncated_chunks.emplace_back(chunk);
                    chunk.blocks.resize(block_it - chunk_it->second.blocks.begin());
                    chunk.num_blocks = chunk.blocks.size();
                    chunk.data_size = chunk.blocks.back().end_offset() - chunk.offset;
                    const auto old_path = full_path(chunk.rel_path());
                    auto chunk_data = file::read(old_path);
                    chunk_data.resize(chunk.data_size);
                    blake2b(chunk.data_hash, chunk_data);
                    const auto compressed = zstd::compress(chunk_data);
                    file::write(full_path(chunk.rel_path()), compressed);
                    chunk.compressed_size = compressed.size();
                    chunk.last_slot = chunk.blocks.back().slot;
                    chunk.last_block_hash = chunk.blocks.back().hash;
                    ++chunk_it;
                }
                while (chunk_it != _chunks.end()) {
                    _truncated_chunks.emplace_back(chunk_it->second);
                    chunk_it = _chunks.erase(chunk_it);
                }
            }
        }

        virtual void _start_tx_impl()
        {
            _parsed = 0;
            _parsed_base = num_bytes() - _transaction->start_offset;
            _notify_end_offset = num_bytes();
            _notify_next_epoch = _chunks.empty() ? 0 : _chunks.rbegin()->second.epoch();
            if (!_unmerged_chunks.empty()) {
                logger::warn("unmerged chunks weren't empty at the beginning of a tx - recovering from an error?");
                _unmerged_chunks.clear();
            }
        }

        virtual uint64_t _valid_end_offset_impl()
        {
            // chunks are updates only when they become mergeable
            return num_bytes();
        }

        virtual uint64_t _max_end_offset_impl()
        {
            // chunks are updates only when they become mergeable
            return num_bytes();
        }

        virtual void _prepare_tx_impl()
        {
            timer t { "chunk_registry::_prepare_tx" };
            if (!_unmerged_chunks.empty()) {
                logger::warn("{} unmerged chunks - ignoring them", _unmerged_chunks.size());
                if (!_chunks.empty())
                    logger::trace("last merged chunk: {}", json::serialize(_chunks.rbegin()->second.to_json()));
                for (const auto &[last_byte_offset, uchunk]: _unmerged_chunks)
                    logger::trace("unmerged chunk with last byte offset {}: {}", last_byte_offset, json::serialize(uchunk.to_json()));
                _unmerged_chunks.clear();
            }
            {
                mutex::unique_lock update_lk { _update_mutex };
                _notify_of_updates(update_lk, true);
            }
            // let the operations potentially scheduled in _on_epoch_merge calls to finish
            _sched.process(true);
            _save_state(_state_path_pre);
        }

        virtual void _rollback_tx_impl()
        {
            for (auto chunk_it = find_offset_it(_transaction->start_offset); chunk_it != _chunks.end(); ) {
                _file_remover.mark(full_path(chunk_it->second.rel_path()));
                chunk_it = _chunks.erase(chunk_it);
            }
            for (auto &&chunk: _truncated_chunks) {
                const auto chunk_path = full_path(chunk.rel_path());
                _file_remover.unmark(chunk_path);
                const auto [it, created] = _chunks.try_emplace(chunk.offset + chunk.data_size - 1, std::move(chunk));
                if (!created)
                    throw error("rollback failed: couldn't reinsert chunk {}", chunk_path);
            }
            _truncated_chunks.clear();
            _unmerged_chunks.clear();
        }

        virtual void _commit_tx_impl()
        {
            if (!std::filesystem::exists(_state_path_pre))
                throw error("the prepared chunk_registry state file is missing: {}!", _state_path_pre);
            std::filesystem::rename(_state_path_pre, _state_path);
            for (const auto &chunk: _truncated_chunks)
                _file_remover.mark(full_path(chunk.rel_path()));
            _truncated_chunks.clear();
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
                const auto blk_ptr = cardano::make_block(block_tuple, chunk.offset + block_tuple.data - raw_data.data());
                const auto &blk = *blk_ptr;
                try {
                    const auto slot = blk.slot();
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
                    static constexpr auto max_era = std::numeric_limits<uint8_t>::max();
                    if (blk.era() > max_era)
                        throw error("block at slot {} has era {} that is outside of the supported max limit of {}", slot, blk.era(), max_era);
                    static constexpr auto max_size = std::numeric_limits<uint32_t>::max();
                    if (blk.size() > max_size)
                        throw error("block at slot {} has size {} that is outside of the supported max limit of {}", slot, blk.size(), max_size);
                    chunk.blocks.emplace_back(slot, blk.offset(), chunk.last_block_hash, static_cast<uint32_t>(blk.size()), static_cast<uint8_t>(blk.era()));
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
        const std::string _state_path_pre;
        alignas(mutex::padding) mutable mutex::unique_lock::mutex_type _update_mutex {};
        chunk_map _chunks {};
        // Active transaction data
        chunk_map _unmerged_chunks {};
        uint64_t _parsed_base = 0;
        mutable std::atomic_uint64_t _parsed = 0;
        uint64_t _notify_end_offset = 0;
        uint64_t _notify_next_epoch = 0;
        std::vector<chunk_info> _truncated_chunks {};

        static thread_local uint8_vector _read_buffer;

        void _save_state(const std::string &path)
        {
            // the caller is responsible to hold a lock protecting access to the _chunks!
            zpp::save(path, _chunks);
        }

        void _do_truncate(const size_t target_offset)
        {
            if (!_transaction)
                throw error("truncate can be executed only inside of a transaction!");
            if (max_end_offset() > target_offset)
                _truncate_impl(target_offset);
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
                auto &&inserted_chunk = it->second;
                if (!created)
                    throw error("internal error: duplicate chunk offset: {} size: {}", inserted_chunk.offset, inserted_chunk.data_size);
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
                // in unit-tests chunks may have non-continuous epochs
                if (_has_epoch(_notify_next_epoch, update_lk)) {
                    const auto einfo = epoch(_notify_next_epoch);
                    epoch_info::chunk_list filtered_chunks {};
                    for (const auto *chunk: einfo.chunks()) {
                        if (chunk->offset >= _notify_end_offset)
                            filtered_chunks.emplace_back(chunk);
                    }
                    _notify_end_offset = einfo.end_offset();
                    if (!filtered_chunks.empty())
                        _on_epoch_merge(_notify_next_epoch, { std::move(filtered_chunks) });
                }
                ++_notify_next_epoch;
            }
        }

        chunk_map::iterator _find_chunk_by_offset(const uint64_t offset)
        {
            const auto it = _chunks.lower_bound(offset);
            if (it == _chunks.end())
                throw error("no chunk matches offset: {}!", offset);
            return it;
        }

        chunk_map::const_iterator _find_chunk_by_offset(const uint64_t offset) const
        {
            const auto it = _chunks.lower_bound(offset);
            if (it == _chunks.end())
                throw error("no chunk matches offset: {}!", offset);
            return it;
        }

        storage::block_list::const_iterator _find_block_by_offset(const chunk_map::const_iterator chunk_it, const uint64_t offset) const
        {
            if (chunk_it == _chunks.end())
                throw error("internal error: a non-empty chunk_iterator is expected!");
            const auto &blocks = chunk_it->second.blocks;
            const auto block_it = std::lower_bound(blocks.begin(), blocks.end(), offset,
                [](const auto &b, const auto offset) { return b.end_offset() - 1 < offset; });
            return block_it;
        }

        // can return the closest succeeding chunk if no chunk includes the block
        chunk_map::const_iterator _find_chunk_by_slot(const cardano::slot &slot) const
        {
            const auto chunk_it = std::lower_bound(_chunks.begin(), _chunks.end(), slot,
                [](const auto &c, const auto &slot) { return c.second.last_slot < slot; });
            return chunk_it;
        }

        // can return the closest succeeding block if there is no block at that slot
        storage::block_list::const_iterator _find_block_by_slot(const chunk_map::const_iterator chunk_it, const cardano::slot &slot) const
        {
            if (chunk_it == _chunks.end())
                throw error("internal error: a non-empty chunk_iterator is expected!");
            const auto &blocks = chunk_it->second.blocks;
            const auto block_it = std::lower_bound(blocks.begin(), blocks.end(), slot,
                [](const auto &b, const auto &slot) { return b.slot < slot; });
            return block_it;
        }

        bool _has_epoch(const uint64_t epoch, mutex::unique_lock &update_lk) const
        {
            if (!update_lk)
                throw error("internal error: update lock must be held at the call to _has_epoch");
            const auto chunk_it = std::lower_bound(_chunks.begin(), _chunks.end(), epoch, [](const auto &el, const auto &epoch) { return el.second.epoch() < epoch; });
            return chunk_it != _chunks.end() && chunk_it->second.epoch() == epoch;
        }
    };
}

#endif // !DAEDALUS_TURBO_CHUNK_REGISTRY_HPP