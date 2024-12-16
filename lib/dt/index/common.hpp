/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_COMMON_HPP
#define DAEDALUS_TURBO_INDEX_COMMON_HPP

#include <dt/cardano/common.hpp>
#include <dt/container.hpp>
#include <dt/index/io.hpp>
#include <dt/index/merge.hpp>
#include <dt/mutex.hpp>
#include <dt/zpp.hpp>

namespace daedalus_turbo::index {
    struct chunk_indexer_base {
        virtual ~chunk_indexer_base() =default;

        void index(const cardano::block_base &blk)
        {
            uint64_t last_byte_offset = blk.offset();
            if (blk.size() > 0)
                last_byte_offset += blk.size() - 1;
            if (last_byte_offset > _max_offset)
                _max_offset = last_byte_offset;
            _index(blk);
        }

        virtual void index_tx(const cardano::tx &)
        {
        }

        virtual void index_invalid_tx(const cardano::tx &)
        {
        }

        uint64_t max_offset() const
        {
            return _max_offset;
        }

    protected:
        virtual void _index(const cardano::block_base &)
        {
        }

    private:
        uint64_t _max_offset = 0;
    };

    template<typename T>
    struct chunk_indexer_one_part: chunk_indexer_base {
        chunk_indexer_one_part(const std::string &idx_path, size_t)
            : _idx { idx_path, 1 }
        {}

        ~chunk_indexer_one_part() override
        {
            _idx.set_meta("max_offset", buffer::from(max_offset()));
        }
    protected:
        sorting_writer<T> _idx;
    };

    template<typename T>
    struct chunk_indexer_multi_part: chunk_indexer_base {
        chunk_indexer_multi_part(const std::string &idx_path, size_t num_threads)
            : _idx { idx_path, num_threads }, _part_range { 1 + ((256 - 1) / num_threads) }
        {}

        ~chunk_indexer_multi_part() override
        {
            _idx.set_meta("max_offset", buffer::from(max_offset()));
        }
    protected:
        sorting_writer<T> _idx;
        const size_t _part_range;
    };

    struct epoch_observer {
        virtual void mark_epoch(const cardano::slot_range &slots, uint64_t chunk_id) =0;
    };

    template<typename T>
    struct chunk_indexer_one_epoch_base: chunk_indexer_base {
        using data_type = T;

        chunk_indexer_one_epoch_base(epoch_observer &observer, const uint64_t chunk_id, const std::string &idx_path)
            : _epoch_observer { observer }, _chunk_id { chunk_id }, _idx_base_path { idx_path }
        {
        }

        ~chunk_indexer_one_epoch_base() override
        {
            if (_slots) {
                _epoch_observer.mark_epoch(*_slots, _chunk_id);
                zpp::save_zstd(fmt::format("{}.bin", _idx_base_path), _data);
            }
        }
    protected:
        epoch_observer &_epoch_observer;
        uint64_t _chunk_id;
        std::string _idx_base_path;
        data_type _data {};
        std::optional<cardano::slot_range> _slots {};

        virtual void _index_epoch(const cardano::block_base &/*blk*/, data_type &/*idx*/)
        {
        }

        void _index(const cardano::block_base &blk) override
        {
            try {
                if (_slots)
                    _slots->update(blk.slot());
                else {
                    _slots.emplace(blk.slot());
                }
                _index_epoch(blk, _data);
            } catch (std::exception &ex) {
                logger::warn("one_epoch index {} indexing error: {}", _idx_base_path, ex.what());
            }
        }
    };

    template<typename T>
    struct chunk_indexer_one_epoch: chunk_indexer_one_epoch_base<vector<T>> {
        chunk_indexer_one_epoch(epoch_observer &observer, const uint64_t chunk_id, const std::string &idx_path)
            : chunk_indexer_one_epoch_base<vector<T>> { observer, chunk_id, idx_path }
        {
        }

        ~chunk_indexer_one_epoch() override
        {
            if (!chunk_indexer_one_epoch_base<vector<T>>::_data.empty())
                std::sort(chunk_indexer_one_epoch_base<vector<T>>::_data.begin(), chunk_indexer_one_epoch_base<vector<T>>::_data.end());
        }
    };

    using chunk_id_list = std::set<uint64_t>;

    struct indexer_base {
        static std::string chunk_dir(const std::string &idx_dir, const std::string &idx_name)
        {
            return fmt::format("{}/{}", idx_dir, idx_name);
        }

        static std::string reader_path(const std::string &idx_dir, const std::string &idx_name,
            const std::string &slice_id="", const std::string &chunk_id="")
        {
            const std::string_view sep1 { slice_id.empty() ? "" : "-" };
            const std::string_view sep2 { chunk_id.empty() ? "" : "-" };
            return fmt::format("{}/{}/index{}{}{}{}.data", idx_dir, idx_name, sep1, slice_id, sep2, chunk_id);
        }

        static std::string chunk_path(const std::string &idx_dir, const std::string &idx_name, const std::string &slice_id, uint64_t chunk_id)
        {
            return reader_path(idx_dir, idx_name, slice_id, fmt::format("{}", chunk_id));
        }

        indexer_base(const std::string &idx_dir, const std::string &idx_name, scheduler &sched=scheduler::get())
            : _sched { sched }, _idx_dir { idx_dir }, _idx_name { idx_name }
        {
            std::filesystem::create_directories(chunk_dir());
        }

        virtual ~indexer_base() =default;

        const std::string &name() const
        {
            return _idx_name;
        }

        const std::string &base_dir() const
        {
            return _idx_dir;
        }

        const std::string chunk_dir() const
        {
            return chunk_dir(_idx_dir, _idx_name);
        }

        bool exists(const std::string &slice_id) const
        {
            return std::filesystem::exists(reader_path(_idx_dir, _idx_name, slice_id));
        }

        virtual void finalize(const std::string &/*slice_id*/, const chunk_id_list &/*chunks*/)
        {
        }

        virtual void merge(const std::string &/*task_group*/, size_t /*task_prio*/, const std::vector<std::string> &/*chunks*/,
                const std::string &/*final_path*/, const std::function<void()> &/*on_complete*/)
        {
            throw error("merge not implemented");
        }

        virtual void clean_up() const
        {
            for (const auto &entry: std::filesystem::directory_iterator(chunk_dir())) {
                if (!entry.is_regular_file())
                    continue;
                if (entry.path().extension() != ".data") {
                    logger::trace("removing a temporary file: {}", entry.path().string());
                    std::filesystem::remove(entry.path());
                } else if (!entry.path().filename().string().starts_with("index-slice-")) {
                    logger::trace("removing an unmerged index chunk: {}", entry.path().string());
                    std::filesystem::remove(entry.path());
                }
            }
        }

        virtual std::string reader_path(const std::string &slice_id="") const
        {
            return reader_path(_idx_dir, _idx_name, slice_id);
        }

        virtual void remove(const std::string &slice_id="")
        {
            std::filesystem::remove(reader_path(slice_id));
        }

        virtual std::string chunk_path(const std::string &slice_id, uint64_t chunk_id) const
        {
            return chunk_path(_idx_dir, _idx_name, slice_id, chunk_id);
        }

        virtual bool mergeable() const
        {
            return false;
        }

        virtual void reset()
        {
        }

        virtual uint64_t disk_size(const std::string &slice_id) const =0;
        virtual std::unique_ptr<chunk_indexer_base> make_chunk_indexer(const std::string &slice_id, uint64_t chunk_id) =0;
        virtual void schedule_truncate(const std::string &slice_id, const std::string &new_slice_id, uint64_t new_end_offset) =0;
    protected:
        scheduler &_sched;
        std::string _idx_dir;
        std::string _idx_name;
    };

    extern const size_t two_step_merge_num_files;

    template<typename ChunkIndexer>
    struct indexer_chunked: indexer_base {
        using indexer_base::indexer_base;

        uint64_t disk_size(const std::string &slice_id="") const override
        {
            return writer<int>::disk_size(reader_path(slice_id));
        }
    };

    template<typename T, typename ChunkIndexer>
    struct indexer_merging: indexer_chunked<ChunkIndexer> {
        using indexer_chunked<ChunkIndexer>::indexer_chunked;

        reader<T> make_reader(const std::string &slice_id="") const
        {
            return { indexer_base::reader_path(slice_id) };
        }

        void merge(const std::string &task_group, size_t task_prio, const std::vector<std::string> &chunks, const std::string &final_path,
                   const std::function<void()> &on_complete) override
        {
            merge_one_step<T>(indexer_chunked<ChunkIndexer>::_sched, task_group, task_prio, chunks, final_path, on_complete);
        }

        bool mergeable() const override
        {
            return true;
        }
    };

    template<typename T, typename ChunkIndexer>
    struct indexer_no_offset: indexer_merging<T, ChunkIndexer> {
        using indexer_merging<T, ChunkIndexer>::indexer_merging;

        std::unique_ptr<chunk_indexer_base> make_chunk_indexer(const std::string &slice_id, uint64_t chunk_id) override
        {
            return std::make_unique<ChunkIndexer>(indexer_merging<T, ChunkIndexer>::chunk_path(slice_id, chunk_id), default_parts);
        }
    };

    using chunk_list = vector<uint64_t>;
    using epoch_chunks = map<cardano::slot_range, chunk_list>;

    template<typename ChunkIndexer>
    struct indexer_one_epoch: indexer_chunked<ChunkIndexer>, epoch_observer {
        using indexer_chunked<ChunkIndexer>::indexer_chunked;

        bool mergeable() const override
        {
            return false;
        }

        void mark_epoch(const cardano::slot_range &slots, const uint64_t chunk_id) override
        {
            mutex::scoped_lock lk { _updated_epochs_mutex };
            auto [it, created] = _updated_epochs.try_emplace(slots);
            it->second.emplace_back(chunk_id);
        }

        void finalize(const std::string &/*slice_id*/, const chunk_id_list &/*chunk_ids*/) override
        {
            // do nothing, processing if any must be done by the owner of the instance
            _updated_epochs.clear();
        }

        std::unique_ptr<chunk_indexer_base> make_chunk_indexer(const std::string &slice_id, uint64_t chunk_id) override
        {
            return std::make_unique<ChunkIndexer>(*this, chunk_id,
                indexer_chunked<ChunkIndexer>::chunk_path(slice_id, chunk_id));
        }

        void schedule_truncate(const std::string &, const std::string &, uint64_t) override
        {
            // update-only index, do nothing
        }

        void reset() override
        {
            mutex::scoped_lock lk { _updated_epochs_mutex };
            _updated_epochs.clear();
        }

        chunk_list chunks(const cardano::slot_range &epoch_slots) const
        {
            mutex::scoped_lock lk { _updated_epochs_mutex };
            chunk_list chunks {};
            for (auto it = _updated_epochs.lower_bound(epoch_slots); it != _updated_epochs.end(); ++it) {
                if (it->first.min() > epoch_slots.max())
                    break;
                if (it->first.min() >= epoch_slots.min()) {
                    if (it->first.max() <= epoch_slots.max()) {
                        for (const auto chunk_id: it->second)
                            chunks.emplace_back(chunk_id);
                    } else {
                        throw error(fmt::format("the chunk with slot range {} does not fit into the epoch slot range {}", it->first, epoch_slots));
                    }
                }
            }
            return chunks;
        }
    private:
        alignas(mutex::padding) mutable mutex::unique_lock::mutex_type _updated_epochs_mutex {};
        index::epoch_chunks _updated_epochs {};
    };

    template<typename T>
    concept HasOffsetField = requires(T a) {
        { a.offset + 1 };
    };

    template<HasOffsetField T, typename ChunkIndexer>
    struct indexer_offset: indexer_no_offset<T, ChunkIndexer> {
        using indexer_no_offset<T, ChunkIndexer>::indexer_no_offset;

        void schedule_truncate(const std::string &slice_id, const std::string &new_slice_id, uint64_t new_end_offset) override
        {
            const auto src_path = indexer_no_offset<T, ChunkIndexer>::reader_path(slice_id);
            const auto new_path = indexer_no_offset<T, ChunkIndexer>::reader_path(new_slice_id);
            const std::string task_name = fmt::format("truncate:{}", src_path);
            logger::debug("truncate {} to {} bytes", src_path, new_end_offset);
            if (!std::filesystem::exists(src_path))
                return;
            if (new_end_offset > 0) {
                auto reader = std::make_shared<index::reader_mt<T>>(src_path);
                const auto index_max_offset = reader->get_meta("max_offset").template to<uint64_t>();
                const bool truncation_needed = index_max_offset >= new_end_offset;
                logger::trace("truncate {} - current max offset: {} truncation needed: {}", src_path, index_max_offset, truncation_needed);
                if (!truncation_needed)
                    return;
                size_t num_parts = reader->num_parts();
                auto writer = std::make_shared<index::writer<T>>(src_path + "-new", num_parts);
                auto new_max_offset = std::make_shared<uint64_t>(0);
                indexer_no_offset<T, ChunkIndexer>::_sched.on_completion(task_name, num_parts, [reader, writer, src_path, new_path, new_max_offset] {
                    reader->close();
                    writer->set_meta("max_offset", buffer::from(*new_max_offset));
                    writer->commit();
                    writer->rename(new_path);
                });
                indexer_no_offset<T, ChunkIndexer>::_sched.on_result(task_name, [new_max_offset, task_name](const auto &res) {
                    if (res.type() == typeid(scheduled_task_error)) {
                        logger::error("task {} {}", task_name, std::any_cast<scheduled_task_error>(res).what());
                        return;
                    }
                    auto task_max_offset = std::any_cast<uint64_t>(res);
                    if (task_max_offset > *new_max_offset)
                        *new_max_offset = task_max_offset;
                });
                for (size_t pi = 0; pi < num_parts; ++pi) {
                    indexer_no_offset<T, ChunkIndexer>::_sched.submit(task_name, reader->size() >> 20, [reader, writer, pi, new_end_offset]() {
                        auto thread_data = reader->init_thread(pi);
                        uint64_t max_offset = 0;
                        T item {};
                        while (reader->read_part(pi, item, thread_data)) {
                            if (item.offset < new_end_offset) {
                                if (item.offset > max_offset)
                                    max_offset = item.offset;
                                writer->emplace_part(pi, item);
                            }
                        }
                        return max_offset + sizeof(item);
                    });
                }
            } else {
                // just delete index if new_end_offset == 0
                std::filesystem::remove(src_path);
            }
        }
    };
}

#endif //!DAEDALUS_TURBO_INDEX_COMMON_HPP