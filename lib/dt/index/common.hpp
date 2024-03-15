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

namespace daedalus_turbo::index {
    struct chunk_indexer_base {
        virtual ~chunk_indexer_base() {}

        void index(const cardano::block_base &blk)
        {
            uint64_t last_byte_offset = blk.offset();
            if (blk.size() > 0)
                last_byte_offset += blk.size() - 1;
            if (last_byte_offset > _max_offset)
                _max_offset = last_byte_offset;
            _index(blk);
        }

        uint64_t max_offset() const
        {
            return _max_offset;
        }

    protected:
        virtual void _index(const cardano::block_base &blk) =0;

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
        virtual void mark_epoch(uint64_t epoch, uint64_t chunk_id) =0;
    };

    template<typename T>
    struct chunk_indexer_one_epoch: chunk_indexer_base {
        chunk_indexer_one_epoch(epoch_observer &observer, uint64_t chunk_id, const std::string &idx_path)
            : _epoch_observer { observer }, _chunk_id { chunk_id }, _idx_base_path { idx_path }
        {}

        ~chunk_indexer_one_epoch() override
        {
            if (!_data.empty()) {
                _epoch_observer.mark_epoch(*_epoch, _chunk_id);
                std::sort(_data.begin(), _data.end());
                file::write_zpp(fmt::format("{}-{}.bin", _idx_base_path, *_epoch), _data);
            }
        }
    protected:
        using data_list = vector<T>;

        epoch_observer &_epoch_observer;
        uint64_t _chunk_id;
        std::string _idx_base_path;
        data_list _data {};
        std::optional<uint64_t> _epoch {};

        virtual void _index_epoch(const cardano::block_base &blk, data_list &idx) =0;

        void _index(const cardano::block_base &blk) override
        {
            try {
                auto blk_epoch = blk.slot().epoch();
                if (_epoch) [[likely]] {
                    if (*_epoch != blk_epoch)
                        throw error("all blocks must contains the same epoch: {} but got {}", *_epoch, blk_epoch);
                } else {
                    _epoch = blk_epoch;
                }
                _index_epoch(blk, _data);
            } catch (std::exception &ex) {
                logger::warn("one_epoch index {} indexing error: {}", _idx_base_path, ex.what());
            }
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

        virtual void merge(const std::string &/*task_group*/, size_t /*task_prio*/, const std::vector<std::string> &/*chunks*/, const std::string &/*final_path*/)
        {
            throw error("merge not implemented");
        }

        virtual size_t merge_task_count(const std::vector<std::string> &/*chunks*/) const
        {
            throw error("merge_task_count not implemented");
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
        virtual void schedule_truncate(const std::string &slice_id, uint64_t new_end_offset, const std::function<void()> &on_done) =0;
    protected:
        scheduler &_sched;
        std::string _idx_dir;
        std::string _idx_name;
    };

    extern const size_t two_step_merge_num_files;

    template<typename T, typename ChunkIndexer>
    struct indexer_merging: indexer_base {
        using indexer_base::indexer_base;

        uint64_t disk_size(const std::string &slice_id="") const override
        {
            return writer<T>::disk_size(reader_path(slice_id));
        }

        index::reader<T> make_reader(const std::string slice_id="") const
        {
            return index::reader<T> { reader_path(slice_id) };
        }

        void merge(const std::string &task_group, size_t task_prio, const std::vector<std::string> &chunks, const std::string &final_path) override
        {
            merge_one_step<T>(_sched, task_group, task_prio, chunks, final_path);
        }

        size_t merge_task_count(const std::vector<std::string> &chunks) const override
        {
            return merge_estimate_task_count<T>(chunks);
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
    using epoch_chunks = map<uint64_t, chunk_list>;

    template<typename T, std::derived_from<chunk_indexer_one_epoch<T>> ChunkIndexer>
    struct indexer_one_epoch: indexer_merging<T, ChunkIndexer>, epoch_observer {
        indexer_one_epoch(const std::string &idx_dir, const std::string &idx_name, scheduler &sched=scheduler::get())
            : indexer_merging<T, ChunkIndexer> { idx_dir, idx_name, sched }
        {
        }

        using indexer_merging<T, ChunkIndexer>::indexer_merging;

        bool mergeable() const override
        {
            return false;
        }

        void mark_epoch(uint64_t epoch, uint64_t chunk_id) override
        {
            std::scoped_lock lk { _updated_epochs_mutex };
            auto [it, created] = _updated_epochs.try_emplace(epoch);
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
                indexer_merging<T, ChunkIndexer>::chunk_path(slice_id, chunk_id));
        }

        void schedule_truncate(const std::string &, uint64_t, const std::function<void()> &) override
        {
            // update-only index, do nothing
        }

        void reset() override
        {
            _updated_epochs.clear();
        }

        const epoch_chunks &updated_epochs() const
        {
            return _updated_epochs;
        }
    private:
        alignas(mutex::padding) std::mutex _updated_epochs_mutex {};
        epoch_chunks _updated_epochs {};
    };

    template<typename T>
    concept HasOffsetField = requires(T a) {
        { a.offset + 1 };
    };

    template<HasOffsetField T, typename ChunkIndexer>
    struct indexer_offset: indexer_no_offset<T, ChunkIndexer> {
        using indexer_no_offset<T, ChunkIndexer>::indexer_no_offset;

        void schedule_truncate(const std::string &slice_id, uint64_t new_end_offset, const std::function<void()> &on_done) override
        {
            auto src_path = indexer_no_offset<T, ChunkIndexer>::reader_path(slice_id);
            const std::string task_name = fmt::format("truncate-{}", src_path);
            logger::debug("truncate {} to {} bytes", src_path, new_end_offset);
            if (!std::filesystem::exists(src_path))
                return;
            if (new_end_offset > 0) {
                auto reader = std::make_shared<index::reader_mt<T>>(src_path);
                auto index_max_offset = reader->get_meta("max_offset").template to<uint64_t>();
                bool truncation_needed = index_max_offset >= new_end_offset;
                logger::trace("truncate {} - current max offset: {} truncation needed: {}", src_path, index_max_offset, truncation_needed);
                if (!truncation_needed)
                    return;
                size_t num_parts = reader->num_parts();
                auto writer = std::make_shared<index::writer<T>>(src_path + "-new", num_parts);
                auto scheduled = std::make_shared<std::atomic_bool>(false);
                auto new_max_offset = std::make_shared<uint64_t>(0);
                indexer_no_offset<T, ChunkIndexer>::_sched.on_result(task_name, [this, on_done, new_max_offset, src_path, reader, writer, scheduled, task_name](const auto &res) mutable {
                    if (res.type() == typeid(scheduled_task_error)) {
                        logger::error("task {} {}", task_name, std::any_cast<scheduled_task_error>(res).what());
                        return;
                    }
                    auto task_max_offset = std::any_cast<uint64_t>(res);
                    if (task_max_offset > *new_max_offset)
                        *new_max_offset = task_max_offset;
                    if (!*scheduled || indexer_no_offset<T, ChunkIndexer>::_sched.task_count(task_name) > 0)
                        return;
                    reader->close();
                    writer->set_meta("max_offset", buffer::from(*new_max_offset));
                    writer->commit();
                    writer->rename(src_path);
                    on_done();
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
                *scheduled = true;
            } else {
                // just delete index if new_end_offset == 0
                std::filesystem::remove(src_path);
            }
        }
    };
}

#endif //!DAEDALUS_TURBO_INDEX_COMMON_HPP