/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_COMMON_HPP
#define DAEDALUS_TURBO_INDEX_COMMON_HPP

#include <dt/index/io.hpp>
#include <dt/index/merge.hpp>

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
    struct chunk_indexer_one_part: public chunk_indexer_base {
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
    struct chunk_indexer_multi_part: public chunk_indexer_base {
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
    struct chunk_indexer_multi_epoch: public chunk_indexer_base {
        chunk_indexer_multi_epoch(epoch_observer &observer, uint64_t chunk_id, const std::string &idx_path, size_t)
            : _epoch_observer { observer }, _chunk_id { chunk_id }, _idx_base_path { idx_path }
        {}

        ~chunk_indexer_multi_epoch() override
        {
            for (auto &[epoch, data]: _idxs) {
                std::sort(data.begin(), data.end());
                file::write_vector(fmt::format("{}-{}.bin", _idx_base_path, epoch), data);
            }
        }
    protected:
        epoch_observer &_epoch_observer;
        uint64_t _chunk_id;
        std::string _idx_base_path;
        std::map<uint64_t, std::vector<T>> _idxs {};

        virtual void _index_epoch(const cardano::block_base &blk, std::vector<T> &idx) =0;

        std::vector<T> &_epoch_data(uint64_t epoch)
        {
            auto [it, created] = _idxs.try_emplace(epoch);
            if (created)
                _epoch_observer.mark_epoch(epoch, _chunk_id);
            return it->second;
        }

        void _index(const cardano::block_base &blk) override
        {
            try {
                auto &data = _epoch_data(blk.slot().epoch());
                _index_epoch(blk, data);
            } catch (std::exception &ex) {
                logger::warn("multi_epoch index {} indexing error: {}", _idx_base_path, ex.what());
            }
        }
    };

    using chunk_id_list = std::set<uint64_t>;

    struct indexer_base {
        static std::string reader_path(const std::string &idx_dir, const std::string &idx_name, const std::string &slice_id="")
        {
            const std::string_view sep { slice_id.empty() ? "" : "-" };
            return fmt::format("{}/{}/index{}{}", idx_dir, idx_name, sep, slice_id);
        }

        static std::string chunk_path(const std::string &idx_dir, const std::string &idx_name, const std::string &slice_id, uint64_t chunk_id)
        {
            return fmt::format("{}-{}", reader_path(idx_dir, idx_name, slice_id), chunk_id);
        }

        indexer_base(scheduler &sched, const std::string &idx_dir, const std::string &idx_name)
            : _sched { sched }, _idx_dir { idx_dir }, _idx_name { idx_name }
        {
            std::filesystem::path rp { reader_path() };
            if (!std::filesystem::exists(rp.parent_path()))
                std::filesystem::create_directories(rp.parent_path());
        }

        virtual ~indexer_base()
        {}

        const std::string &name() const
        {
            return _idx_name;
        }

        const std::string &base_dir() const
        {
            return _idx_dir;
        }

        bool exists(const std::string &slice_id) const
        {
            return index::writer<int>::exists(reader_path(_idx_dir, _idx_name, slice_id));
        }

        virtual void finalize(const std::string &/*slice_id*/, const chunk_id_list &/*chunks*/)
        {
        }

        virtual void merge(const std::string &/*task_group*/, size_t /*task_prio*/, const std::vector<std::string> &/*chunks*/, const std::string &/*final_path*/)
        {
            throw error("not implemented");
        }

        virtual void clean_up() const
        {
            for (const auto &entry: std::filesystem::directory_iterator { fmt::format("{}/{}", _idx_dir, _idx_name) }) {
                if (!entry.is_regular_file())
                    continue;
                if (entry.path().extension() != ".data") {
                    logger::debug("removing a temporary file: {}", entry.path().string());
                    std::filesystem::remove(entry.path());
                } else if (entry.path().filename().string().starts_with("index-update-")) {
                    logger::debug("removing an unmerged index chunk: {}", entry.path().string());
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
            index::writer<int>::remove(reader_path(slice_id));
        }

        virtual std::string chunk_path(const std::string &slice_id, uint64_t chunk_id) const
        {
            return chunk_path(_idx_dir, _idx_name, slice_id, chunk_id);
        }

        virtual bool mergeable() const
        {
            return false;
        }

        virtual uint64_t disk_size(const std::string &slice_id) const =0;
        virtual std::unique_ptr<chunk_indexer_base> make_chunk_indexer(const std::string &slice_id, uint64_t chunk_id) =0;
        virtual void truncate(const std::string &slice_id, uint64_t new_end_offset) =0;
    protected:
        scheduler &_sched;
        std::string _idx_dir;
        std::string _idx_name;
    };

    extern const size_t two_step_merge_num_files;

    template<typename T, typename ChunkIndexer>
    struct indexer_merging: public indexer_base {
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

        bool mergeable() const override
        {
            return true;
        }
    };

    template<typename T, typename ChunkIndexer>
    struct indexer_no_offset: public indexer_merging<T, ChunkIndexer> {
        using indexer_merging<T, ChunkIndexer>::indexer_merging;

        std::unique_ptr<chunk_indexer_base> make_chunk_indexer(const std::string &slice_id, uint64_t chunk_id) override
        {
            return std::make_unique<ChunkIndexer>(indexer_merging<T, ChunkIndexer>::chunk_path(slice_id, chunk_id),
                indexer_merging<T, ChunkIndexer>::_sched.num_workers());
        }
    };

    using chunk_list = std::vector<uint64_t>;
    using epoch_chunks = std::map<uint64_t, chunk_list>;

    template<typename T, std::derived_from<chunk_indexer_multi_epoch<T>> ChunkIndexer>
    struct indexer_multi_epoch: public indexer_merging<T, ChunkIndexer>, public epoch_observer {
        using indexer_merging<T, ChunkIndexer>::indexer_merging;

        bool mergeable() const override
        {
            return false;
        }

        void mark_epoch(uint64_t epoch, uint64_t chunk_id) override
        {
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
                indexer_merging<T, ChunkIndexer>::chunk_path(slice_id, chunk_id),
                indexer_merging<T, ChunkIndexer>::_sched.num_workers());
        }

        void truncate(const std::string &, uint64_t) override
        {
            // update-only index, do nothing
        }

        const epoch_chunks &updated_epochs() const
        {
            return _updated_epochs;
        }
    private:
        epoch_chunks _updated_epochs {};
    };

    template<typename T>
    concept HasOffsetField = requires(T a) {
        { a.offset + 1 };
    };

    template<HasOffsetField T, typename ChunkIndexer>
    struct indexer_offset: public indexer_no_offset<T, ChunkIndexer> {
        using indexer_no_offset<T, ChunkIndexer>::indexer_no_offset;

        void truncate(const std::string &slice_id, uint64_t new_end_offset) override
        {
            const std::string task_name { "truncate-" + indexer_no_offset<T, ChunkIndexer>::_idx_name + "-" + slice_id };
            auto src_path = indexer_no_offset<T, ChunkIndexer>::reader_path(slice_id);
            logger::debug("truncate {} to {} bytes", src_path, new_end_offset);
            if (!index::writer<T>::exists(src_path))
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
                indexer_no_offset<T, ChunkIndexer>::_sched.on_result(task_name, [this, new_max_offset, src_path, reader, writer, scheduled, task_name](const auto &res) mutable {
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
                index::writer<T>::remove(src_path);
            }
        }
    };
}

#endif //!DAEDALUS_TURBO_INDEX_COMMON_HPP