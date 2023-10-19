/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_COMMON_HPP
#define DAEDALUS_TURBO_INDEX_COMMON_HPP

#include <atomic>
#include <memory>
#include <mutex>
#include <set>
#include <vector>
#include <dt/cardano/common.hpp>
#include <dt/file.hpp>
#include <dt/scheduler.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::index {
    template<typename T>
    struct chunk_info {
        uint64_t file_offset = 0;
        size_t packed_size = 0;
        T max_item {};
    };

    // Each partition can be written only from a single thread to minimize cross-thread synchronization
    template<typename T>
    struct writer {
        static constexpr size_t default_chunk_size = 0x1000;
        static constexpr size_t max_parts = 256;

        static uint64_t disk_size(const std::string &path)
        {
            if (!exists(path))
                return 0;
            return std::filesystem::file_size(path + ".data");
        }

        static bool exists(const std::string &path)
        {
            return std::filesystem::exists(path + ".data");
        }

        static void rename(const std::string &old_name, const std::string &new_name)
        {
            std::filesystem::rename(old_name + ".data", new_name + ".data");
        }

        static void remove(const std::string &path)
        {
            auto full_path = path + ".data";
            if (std::filesystem::exists(full_path))
                std::filesystem::remove(full_path);
        }

        writer() =delete;
        writer(const writer<T> &) =delete;

        writer(const std::string &path, size_t num_partitions = 1, size_t chunk_size=default_chunk_size)
            : _parts(num_partitions), _bufs(num_partitions), _cnts(num_partitions),
                _path { path }, _data_path { path + ".data" },
                _num_parts { num_partitions }, _chunk_size { chunk_size },
                _os { _data_path }
        {
            if (_num_parts > max_parts)
                throw error("num_partitions: {} is greater than the preconfigured maximum: {}!", _num_parts, max_parts);
            for (auto &buf: _bufs)
                buf.resize(chunk_size);
        }

        writer(writer<T> &&w)
            : _parts { std::move(w._parts) }, _bufs { std::move(w._bufs) }, _cnts { std::move(w._cnts) },
                _path { std::move(w._path) }, _data_path { std::move(w._data_path) },
                _num_parts { w._num_parts }, _chunk_size { w._chunk_size },
                _commited { (bool)w._commited },_os { std::move(w._os) }, _free_off { (size_t)w._free_off }
        {
        }

        ~writer()
        {
            if (!_commited) _commit();
        }

        void commit()
        {
            if (_commited) throw error("writer::commit {} has already been commited!", _path);
            _commit();
        }

        template<typename ...A>
        const T &emplace_part(size_t part_id, A &&...args)
        {
            if (_commited) throw error("writer::emplace_part {} has already been commited!", _path);
            auto &cnt = _cnts.at(part_id);
            auto &buf = _bufs.at(part_id);
            T &item = buf.at(cnt % _chunk_size);
            new (&item) T { std::forward<A>(args)... };
            cnt++;
            if (cnt % _chunk_size == 0)
                _flush_part(part_id);
            return item;
        }

        template<typename ...A>
        const T &emplace(A &&...args)
        {
            return emplace_part(0, std::forward<A>(args)...);
        }

        const std::string &path() const
        {
            return _path;
        }

        void rename(const std::string &new_path) const
        {
            rename(_path, new_path);
        }

        void set_meta(const std::string &name, const buffer &data)
        {
            if (name.size() > 255)
                throw error("name of metadata item is too long: {}!", name.size());
            if (data.size() > 255)
                throw error("size of the metadata item is too big: {}!", data.size());
            _meta[name] = data;
        }

    protected:
        std::vector<std::vector<chunk_info<T>>> _parts;
        std::vector<std::vector<T>> _bufs;
        std::vector<size_t> _cnts;
        std::map<std::string, uint8_vector> _meta {};
        std::string _path, _data_path;
        size_t _num_parts, _chunk_size;

        std::atomic_bool _commited = false;
        alignas(mutex::padding) std::mutex _write_mutex {};
        file::write_stream _os;
        size_t _free_off = 0;

        void _commit()
        {
            _commited = true;
            for (size_t i = 0; i < _num_parts; ++i)
                _flush_part(i);
            uint64_t meta_off = _os.tellp();
            _os.write(&_num_parts, sizeof(_num_parts));
            _os.write(&_chunk_size, sizeof(_chunk_size));
            uint64_t meta_size = _meta.size();
            _os.write(&meta_size, sizeof(meta_size));
            for (const auto &[name, data]: _meta) {
                uint8_t name_size = name.size();
                _os.write(&name_size, sizeof(name_size));
                _os.write(name.data(), name_size);
                uint8_t data_size = data.size();
                _os.write(&data_size, sizeof(data_size));
                _os.write(data.data(), data_size);
            }
            _os.write(_cnts.data(), sizeof(_cnts[0]) * _cnts.size());
            for (const auto &chunk_list: _parts) {
                if (!chunk_list.empty())
                    _os.write(chunk_list.data(), sizeof(chunk_list[0]) * chunk_list.size());
            }
            _os.write(&meta_off, sizeof(meta_off));
            _os.close();
        }

        void _flush_part(size_t part_id)
        {
            auto &cnt = _cnts.at(part_id);
            auto &part = _parts.at(part_id);
            size_t cnt_flushed = part.size() * _chunk_size;
            if (cnt > cnt_flushed) {
                size_t cnt_todo = cnt - cnt_flushed;
                if (!_commited && cnt_todo != _chunk_size)
                    throw error("internal_error: only the final chunk may have a size less than chunk_size constant!");
                auto &buf = _bufs.at(part_id);
                if (part.size() > 0 && buf.at(cnt_todo - 1) < part.back().max_item)
                    throw error("{} partition-{} chunks {} and {} are not ordered!", _path, part_id, part.size() - 1, part.size());
                std::span<uint8_t> data { reinterpret_cast<uint8_t *>(buf.data()), cnt_todo * sizeof(T) };
                thread_local uint8_vector comp_data {};
                zstd::compress(comp_data, data, 3);

                std::scoped_lock lock { _write_mutex };
                size_t fact_off = _os.tellp();
                if (fact_off != _free_off)
                    throw error("internal error with {}: expected file position {} but got {}", _path, (size_t)_free_off, fact_off);
                part.emplace_back(_free_off, comp_data.size(), buf.at(cnt_todo - 1));
                _free_off += comp_data.size();
                _os.write(comp_data.data(), comp_data.size());
            }
        }
    };

    template<class T>
    struct sorting_writer {
        sorting_writer(const std::string &path, size_t num_partitions = 1)
            : _bufs(num_partitions), _writer { path, num_partitions }
        {
            for (auto &buf: _bufs)
                buf.reserve(1024);
        }

        ~sorting_writer()
        {
            if (!_commited) _commit();
        }

        template<typename ...A>
        const T &emplace_part(size_t part_idx, A &&...args)
        {
            if (_commited) throw error("sorting-writer::emplace_part {} has already been commited!", _writer.path());
            auto &buf = _bufs.at(part_idx);
            auto &item = buf.emplace_back(std::forward<A>(args)...);
            return item;
        }

        template<typename ...A>
        const T &emplace(A &&...args)
        {
            return emplace_part(0, std::forward<A>(args)...);
        }

        void set_meta(const std::string &name, const buffer &data)
        {
            _writer.set_meta(name, data);
        }

    private:
        std::vector<std::vector<T>> _bufs;
        writer<T> _writer;
        bool _commited = false;

        void _commit()
        {
            _commited = true;
            for (size_t pi = 0; pi < _bufs.size(); pi++) {
                auto &buf = _bufs.at(pi);
                std::sort(buf.begin(), buf.end());
                for (auto &&item: buf)
                    _writer.emplace_part(pi, item);
            }
            _writer.commit();
        }
    };

    template<class T>
    struct reader_mt {
        using find_result = std::tuple<size_t, T>;
        static constexpr size_t max_parts = writer<T>::max_parts;

        struct thread_data {
            std::vector<size_t> offsets {};
            std::vector<size_t> cache_chunk_idxs {};
            std::vector<std::vector<T>> caches {};
            uint8_vector read_buf {};
            size_t num_reads = 0;
            size_t next_part_idx = 0;
            size_t single_part_idx = max_parts;
        };

        reader_mt(const std::string &path)
            :_path { path }, _data_path { path + ".data" }, _is { _data_path }
        {
            auto data_size = std::filesystem::file_size(_data_path);
            if (data_size < sizeof(uint64_t))
                throw error("{} is too small - no metadata can be found", _data_path);
            _is.seek(data_size - sizeof(uint64_t));
            uint64_t meta_off;
            _is.read(&meta_off, sizeof(meta_off));
            _is.seek(meta_off);
            _is.read(&_num_parts, sizeof(_num_parts));
            if (_num_parts == 0)
                throw error("num_partitions is {} for {}!", _num_parts, _path);
            if (_num_parts > max_parts)
                throw error("num_partitions: {} is greater than the preconfigured maximum: {}!", _num_parts, max_parts);
            _is.read(&_chunk_size, sizeof(_chunk_size));
            uint64_t meta_cnt;
            _is.read(&meta_cnt, sizeof(meta_cnt));
            while (meta_cnt > 0) {
                uint8_t name_size;
                _is.read(&name_size, sizeof(name_size));
                std::string name {};
                name.resize(name_size);
                _is.read(name.data(), name_size);
                uint8_t data_size;
                _is.read(&data_size, sizeof(data_size));
                uint8_vector data {};
                data.resize(data_size);
                _is.read(data.data(), data_size);
                _meta[name] = std::move(data);
                meta_cnt--;
            }
            _cnts.resize(_num_parts);
            _is.read(_cnts.data(), sizeof(_cnts[0]) * _num_parts);
            _chunk_lists.resize(_num_parts);
            _max_items.resize(_num_parts);
            for (size_t p = 0; p < _num_parts; ++p) {
                size_t chunk_cnt = _cnts.at(p);
                size_t list_size = (chunk_cnt + _chunk_size - 1) / _chunk_size;
                auto &chunk_list = _chunk_lists.at(p);
                chunk_list.resize(list_size);
                _is.read(chunk_list.data(), sizeof(chunk_list[0]) * list_size);
                for (size_t ci = 1; ci < chunk_list.size(); ci++) {
                    if (chunk_list.at(ci).max_item < chunk_list.at(ci - 1).max_item)
                        throw error("index {}: partition-{} chunks {} and {} are not ordered!", _path, p, ci - 1, ci);
                }
                if (chunk_list.size() > 0) _max_items.at(p) = chunk_list.back().max_item;
                else if (p > 0) _max_items.at(p) = _max_items.at(p - 1);
            }
            for (size_t pi = 1; pi < _num_parts; ++pi) {
                if (_max_items.at(pi) < _max_items.at(pi - 1))
                    throw error("index {}: partitions {} and {} are not ordered!", _path, pi - 1, pi);
            }
        }

        thread_data init_thread(size_t part_idx=max_parts) const
        {
            thread_data t {};
            if (part_idx == max_parts) {
                t.offsets.resize(_num_parts);
                t.cache_chunk_idxs.resize(_num_parts);
                t.caches.resize(_num_parts);
            } else {
                t.single_part_idx = part_idx;
                t.offsets.resize(1);
                t.cache_chunk_idxs.resize(1);
                t.caches.resize(1);
            }
            return t;
        }

        bool eof_part(size_t part_idx, thread_data &t) const
        {
            size_t t_part_idx = _thread_part_idx(part_idx, t);
            const auto &cnt = _cnts.at(part_idx);
            const auto &off = t.offsets.at(t_part_idx);
            return off >= cnt;
        }

        bool eof(thread_data &t) const
        {
            for (size_t p = 0; p < _num_parts; ++p) {
                if (eof_part(p, t)) return true;
            }
            return false;
        }

        find_result find(const T &search_item, thread_data &t) const
        {
            size_t match_size = 0;
            T match_item {};
            bool multi_match = false;
            auto comp = [](const T &a, const T &b) { return a.index_less(b); };
            auto part_it = std::lower_bound(_max_items.begin(), _max_items.end(), search_item, comp);
            if (part_it != _max_items.end()) {
                size_t part_idx = part_it - _max_items.begin();
                size_t t_part_idx = _thread_part_idx(part_idx, t);
                auto &chunk_list = _chunk_lists.at(part_idx);
                auto &cache_chunk_idx = t.cache_chunk_idxs.at(t_part_idx);
                auto chunk_it = std::lower_bound(chunk_list.begin(), chunk_list.end(), search_item,
                                                    [](const chunk_info<T> &el, const T &val) { return el.max_item.index_less(val); });
                auto chunk_it_end = std::upper_bound(chunk_list.begin(), chunk_list.end(), search_item,
                                                    [](const T &val, const chunk_info<T> &el) { return val.index_less(el.max_item); });
                if (chunk_it != chunk_list.end()) {
                    size_t new_cache_chunk_idx = chunk_it - chunk_list.begin();
                    auto &cache = t.caches.at(t_part_idx);
                    if (new_cache_chunk_idx != cache_chunk_idx || cache.size() == 0)
                        _load_cache(part_idx, new_cache_chunk_idx, t);
                    auto [it, it_end] = std::equal_range(cache.begin(), cache.end(), search_item, comp);
                    if (it != it_end && *it == search_item) {
                        match_item = *it;
                        match_size = it_end - it;
                        if (it_end == cache.end()) multi_match = true;
                        // set the position for a potential call to next()
                        t.offsets.at(t_part_idx) = cache_chunk_idx * _chunk_size + (it - cache.begin()) + 1;
                    }
                }
                if (match_size > 0) {
                    if (multi_match) {
                        match_size += (chunk_it_end - chunk_it - 1) * _chunk_size;
                        if (chunk_it_end != chunk_list.end()) {
                            size_t new_cache_chunk_idx = chunk_it_end - chunk_list.begin();
                            auto &cache = t.caches.at(t_part_idx);
                            if (new_cache_chunk_idx != cache_chunk_idx || cache.size() == 0)
                                _load_cache(part_idx, new_cache_chunk_idx, t);
                            auto it = std::upper_bound(cache.begin(), cache.end(), search_item, comp);
                            match_size += it - cache.begin();
                        }
                    }
                    t.next_part_idx = part_idx;
                }
            }
            return find_result { match_size, match_item };
        }

        const buffer get_meta(const std::string &name) const
        {
            auto it = _meta.find(name);
            if (it == _meta.end())
                throw error("unknown metadata item: {}!", name);
            return it->second.span();
        }

        size_t num_parts() const
        {
            return _num_parts;
        }

        size_t offset_part(size_t part_idx, thread_data &t) const
        {
            size_t t_part_idx = _thread_part_idx(part_idx, t);
            return t.offsets.at(t_part_idx);
        }

        const std::string &path() const
        {
            return _path;
        }

        void seek_part(size_t part_idx, size_t new_offset, thread_data &t) const
        {
            size_t t_part_idx = _thread_part_idx(part_idx, t);
            const auto &cnt = _cnts.at(part_idx);
            auto &offset = t.offsets.at(t_part_idx);
            if (new_offset >= cnt)
                throw error("offset is larger than the number of available elements: {} >= {}", new_offset, cnt);
            offset = new_offset;
        }

        void seek(size_t new_offset, thread_data &t) const
        {
            seek_part(0, new_offset, t);
        }

        size_t size_part(size_t part_idx) const
        {
            return _cnts.at(part_idx);
        }

        size_t size() const
        {
            size_t tot_size = 0;
            for (size_t p = 0; p < _num_parts; ++p)
                tot_size += size_part(p);
            return tot_size;
        }

        bool read_part(size_t part_idx, T& item, thread_data &t) const
        {
            size_t t_part_idx = _thread_part_idx(part_idx, t);
            size_t &off = t.offsets.at(t_part_idx);
            size_t cnt = _cnts.at(part_idx);
            if (off >= cnt) return false;
            size_t new_cache_chunk_idx = off / _chunk_size;
            auto &cache_chunk_idx = t.cache_chunk_idxs.at(t_part_idx);
            auto &cache = t.caches.at(t_part_idx);
            if (new_cache_chunk_idx != cache_chunk_idx || cache.size() == 0)
                _load_cache(part_idx, new_cache_chunk_idx, t);
            item = cache.at(off - new_cache_chunk_idx * _chunk_size);
            off++;
            return true;
        }

        bool read(T &item, thread_data &t) const
        {
            for (; t.next_part_idx < _num_parts; t.next_part_idx++) {
                if (read_part(t.next_part_idx, item, t)) return true;
            }
            return false;
        }

        void close()
        {
            std::scoped_lock lock { _read_mutex };
            _is.close();
        }

    private:
        std::string _path, _data_path;
        size_t _num_parts = 0;
        size_t _chunk_size = 0;
        std::map<std::string, uint8_vector> _meta {};
        std::vector<std::vector<chunk_info<T>>> _chunk_lists {};
        std::vector<size_t> _cnts {};
        std::vector<T> _max_items {};
        alignas(mutex::padding) mutable std::mutex _read_mutex {};
        mutable file::read_stream _is;

        size_t _thread_part_idx(size_t part_idx, thread_data &t) const
        {
            if (t.single_part_idx != max_parts) {
                if (part_idx != t.single_part_idx)
                    throw error("reader configured for a single partition {} but got request for data from partition {}!", t.single_part_idx, part_idx);
                part_idx = 0;
            }
            return part_idx;
        }

        void _load_cache(size_t part_idx, size_t new_chunk_idx, thread_data &t) const
        {
            size_t t_part_idx = _thread_part_idx(part_idx, t);
            auto &cache_chunk_idx = t.cache_chunk_idxs.at(t_part_idx);
            cache_chunk_idx = new_chunk_idx;
            auto &cache = t.caches.at(t_part_idx);
            const auto &cnt = _cnts.at(part_idx);
            const auto &chunk_list = _chunk_lists.at(part_idx);
            const auto &chunk = chunk_list.at(new_chunk_idx);
            size_t cache_offset = new_chunk_idx * _chunk_size;
            if (cache_offset + _chunk_size <= cnt) cache.resize(_chunk_size);
            else cache.resize(cnt - cache_offset);
            t.read_buf.resize(chunk.packed_size);

            {
                std::scoped_lock lock { _read_mutex };
                _is.seek(chunk.file_offset);
                _is.read(t.read_buf.data(), t.read_buf.size());
            }
            
            std::span<uint8_t> cache_buf { reinterpret_cast<uint8_t *>(cache.data()), sizeof(T) * cache.size() };
            zstd::decompress(cache_buf, t.read_buf);
            t.num_reads++;
        }
    };

    template<class T>
    struct reader {
        reader(const std::string &path): _reader { path }, _data { _reader.init_thread() }
        {
        }

        bool eof_part(size_t part_idx)
        {
            return _reader.eof_part(part_idx, _data);
        }

        bool eof()
        {
            return _reader.eof(_data);
        }

        reader_mt<T>::find_result find(const T &search_item)
        {
            return _reader.find(search_item, _data);
        }

        const buffer get_meta(const std::string &name) const
        {
            return _reader.get_meta(name);
        }

        size_t num_parts()
        {
            return _reader.num_parts();
        }

        bool read_part(size_t part_id, T& item)
        {
            return _reader.read_part(part_id, item, _data);
        }

        bool read(T &item)
        {
            return _reader.read(item, _data);
        }

        size_t size_part(size_t part_idx)
        {
            return _reader.size_part(part_idx);
        }

        size_t size()
        {
            return _reader.size();
        }

        reader_mt<T> &mt()
        {
            return _reader;
        }

    private:
        reader_mt<T> _reader;
        reader_mt<T>::thread_data _data;
    };

    template<class T>
    struct reader_multi_mt {
        struct thread_data {
            std::vector<std::unique_ptr<typename reader_mt<T>::thread_data>> data {};
            std::vector<size_t> matches {};
            size_t next_match_count = 0;
            size_t num_reads = 0;
        };

        reader_multi_mt(const std::span<const std::string> &paths): _readers {}
        {
            if (paths.size() == 0)
                throw error("at least one path is required!");
            _readers.reserve(paths.size());
            for (const auto &p: paths)
                _readers.emplace_back(std::make_unique<reader_mt<T>>(p));
        }

        thread_data init_thread() const
        {
            thread_data t {};
            t.data.reserve(_readers.size());
            for (const auto &reader: _readers) {
                t.data.emplace_back(std::make_unique<typename reader_mt<T>::thread_data>(reader->init_thread()));
            }
            t.matches.resize(_readers.size());
            return t;
        }

        reader_mt<T>::find_result find(const T &search_item, thread_data &t) const
        {
            t.next_match_count = 0;
            t.num_reads = 0;
            T first_item {};
            for (size_t ri = 0; ri < _readers.size(); ++ri) {
                auto &reader = _readers.at(ri);
                auto &data = *(t.data.at(ri));
                auto [ match_count, match_item ] = reader->find(search_item, data);
                if (match_count) {
                    if (t.next_match_count == 0) {
                        first_item = match_item;
                        t.matches.at(ri) = match_count - 1;
                    } else {
                        reader->seek_part(data.next_part_idx, reader->offset_part(data.next_part_idx, data) - 1, data);
                        t.matches.at(ri) = match_count;
                    }
                    t.next_match_count += t.matches.at(ri);
                } else {
                    t.matches.at(ri) = 0;
                }
                t.num_reads += data.num_reads;
            }
            return typename reader_mt<T>::find_result { t.next_match_count + 1, first_item };
        }

        bool read(T &item, thread_data &t) const
        {
            for (size_t ri = 0; ri < _readers.size(); ++ri) {
                if (t.next_match_count > 0) {
                    auto &match_cnt = t.matches.at(ri);
                    if (match_cnt == 0)
                        continue;
                    match_cnt--;
                    t.next_match_count--;
                }
                auto &reader = _readers.at(ri);
                auto &data = *(t.data.at(ri));
                if (reader->read(item, data))
                    return true;
            }
            return false;
        }

        size_t size() const
        {
            size_t tot_size = 0;
            for (const auto &reader: _readers)
                tot_size += reader->size();
            return tot_size; 
        }

    private:
        std::vector<std::unique_ptr<reader_mt<T>>> _readers;
    };

    template<class T>
    struct reader_multi {
        reader_multi(const std::span<const std::string> &paths)
            : _reader { paths }, _data { _reader.init_thread() }
        {
        }

        reader_mt<T>::find_result find(const T &search_item)
        {
            return _reader.find(search_item, _data);
        }

        bool read(T &item)
        {
            return _reader.read(item, _data);
        }

        size_t size() const
        {
            return _reader.size();
        }

    private:
        reader_multi_mt<T> _reader;
        reader_multi_mt<T>::thread_data _data;
    };

    struct chunk_indexer_base {
        virtual ~chunk_indexer_base() {}

        void index(const cardano::block_base &blk)
        {
            if (blk.offset() > _max_offset)
                _max_offset = blk.offset();
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

    using chunk_id_list = std::set<uint64_t>;

    struct indexer_base {
        indexer_base(scheduler &sched, const std::string &idx_dir, const std::string &idx_name)
            : _sched { sched }, _idx_dir { idx_dir }, _idx_name { idx_name }
        {
            std::filesystem::path rp { reader_path() };
            if (!std::filesystem::exists(rp.parent_path()))
                std::filesystem::create_directories(rp.parent_path());
        }

        const std::string &name() const
        {
            return _idx_name;
        }

        static std::string reader_path(const std::string &idx_dir, const std::string &idx_name, const std::string &slice_id="")
        {
            const std::string_view sep { slice_id.empty() ? "" : "-" };
            return fmt::format("{}/{}/index{}{}", idx_dir, idx_name, sep, slice_id);
        }

        virtual ~indexer_base()
        {}

        virtual std::string reader_path(const std::string &slice_id="") const
        {
            return reader_path(_idx_dir, _idx_name, slice_id);
        }

        virtual void remove(const std::string &slice_id="")
        {
            index::writer<int>::remove(reader_path(slice_id));
        }

        virtual uint64_t disk_size(const std::string &slice_id) const =0;
        virtual void finalize(const std::string &slice_id, const chunk_id_list &chunks) =0;
        virtual std::unique_ptr<chunk_indexer_base> make_chunk_indexer(const std::string &slice_id, uint64_t chunk_id) =0;
        virtual void truncate(const std::string &slice_id, uint64_t new_end_offset) =0;
        virtual void combine(const std::string &out_slice_id, const std::string &del_slice_id) =0;

    protected:
        scheduler &_sched;
        std::string _idx_dir;
        std::string _idx_name;

        std::string _chunk_path(const std::string &slice_id, uint64_t chunk_id) const
        {
            return fmt::format("{}-{}", reader_path(slice_id), chunk_id);
        }
    };

    extern const size_t two_step_merge_num_files;

    template<typename T, typename ChunkIndexer>
    struct indexer_no_offset: public indexer_base {
        using indexer_base::indexer_base;

        void finalize(const std::string &slice_id, const chunk_id_list &chunk_ids) override
        {
            std::vector<std::string> chunks {};
            size_t slice_size = 0;
            for (const auto &chunk_id: chunk_ids) {
                auto path = _chunk_path(slice_id, chunk_id);
                slice_size += writer<T>::disk_size(path);
                chunks.emplace_back(path);
            }
            _merge_index("merge-" + _idx_name, slice_size >> 20, chunks, reader_path(slice_id));
        }

        virtual std::unique_ptr<chunk_indexer_base> make_chunk_indexer(const std::string &slice_id, uint64_t chunk_id) override
        {
            return std::make_unique<ChunkIndexer>(_chunk_path(slice_id, chunk_id), _sched.num_workers());
        }

        index::reader<T> make_reader(const std::string slice_id="") const
        {
            return index::reader<T> { reader_path(slice_id) };
        }

    protected:

        struct merge_item {
            T val;
            size_t stream_idx;

            merge_item(const merge_item &i): val { i.val }, stream_idx { i.stream_idx }
            {}

            merge_item(const T &v, size_t idx): val { v }, stream_idx { idx }
            {}

            merge_item &operator=(const merge_item &v)
            {
                val = v.val;
                stream_idx = v.stream_idx;
                return *this;
            }

            bool operator<(const merge_item& v) const noexcept
            {
                // priority queue returns the greatest element but we need the smallest!
                return !(val < v.val);
            }
        };

        using merge_queue = std::priority_queue<merge_item>;

        static void _merge_index_part(index::writer<T> &out_idx, size_t part_idx, const std::vector<std::shared_ptr<index::reader_mt<T>>> &readers)
        {
            std::vector<typename index::reader_mt<T>::thread_data> reader_data {};
            merge_queue items_to_consider {};
            uint64_t max_offset = 0;
            for (size_t i = 0; i < readers.size(); ++i) {
                reader_data.emplace_back(readers[i]->init_thread(part_idx));
                T val;
                if (readers[i]->read_part(part_idx, val, reader_data[i])) items_to_consider.emplace(std::move(val), i);
                auto r_max_offset = buffer::to<uint64_t>(readers[i]->get_meta("max_offset"));
                if (r_max_offset > max_offset)
                    max_offset = r_max_offset;
            }
            out_idx.set_meta("max_offset", buffer::from(max_offset));
            while (items_to_consider.size() > 0) {
                merge_item next { items_to_consider.top() };
                items_to_consider.pop();
                out_idx.emplace_part(part_idx, next.val);
                if (readers[next.stream_idx]->read_part(part_idx, next.val, reader_data[next.stream_idx])) items_to_consider.emplace(std::move(next));
            }
        }

        void _merge_one_step(const std::string &task_group, size_t task_prio, const std::vector<std::string> &chunks, const std::string &final_path)
        {
            if (chunks.size() == 0)
                return;
            std::vector<std::shared_ptr<index::reader_mt<T>>> readers {};
            size_t num_parts = 0;
            for (size_t i = 0; i < chunks.size(); ++i) {
                auto &reader = readers.emplace_back(std::make_shared<index::reader_mt<T>>(chunks[i]));
                if (num_parts == 0)
                    num_parts = reader->num_parts();
                if (num_parts != reader->num_parts())
                    throw error("chunk {} has a partition count: {} different for other chunks: {}!", reader->num_parts(), num_parts);
            }
            auto out_idx = std::make_shared<index::writer<T>>(final_path, num_parts);
            // Tasks are added to a running scheduler here.
            // So, if they are very quick task_count() == 0 can be reached before all task have been scheduled
            auto scheduled = std::make_shared<std::atomic_bool>(false);
            _sched.on_result(task_group, [this, scheduled, out_idx, task_group, readers, chunks](const auto &res) mutable {
                if (res.type() == typeid(scheduled_task_error)) {
                    logger::error("task {} {}", task_group, std::any_cast<scheduled_task_error>(res).what());
                    return;
                }
                if (!*scheduled || _sched.task_count(task_group) > 0) return;
                // close files before removing
                readers.clear();
                out_idx->commit();
                for (const auto &path: chunks)
                    index::writer<T>::remove(path);
            });
            for (size_t pi = 0; pi < num_parts; ++pi) {
                _sched.submit(task_group, task_prio, [=]() {
                    _merge_index_part(*out_idx, pi, readers);
                    return pi;
                });
            }
            *scheduled = true;
        }

        void _merge_two_step_lvl1(const std::vector<std::string> &chunks, const std::string &final_path)
        {
            std::vector<std::shared_ptr<index::reader_mt<T>>> readers {};
            size_t num_parts = 0;
            for (const auto &path: chunks) {
                auto &reader = readers.emplace_back(std::make_shared<index::reader_mt<T>>(path));
                if (num_parts == 0)
                    num_parts = reader->num_parts();
                if (num_parts != reader->num_parts())
                    throw error("chunk {} has a partition count: {} different for other chunks: {}!", reader->num_parts(), num_parts);
            }
            index::writer<T> out_idx { final_path, num_parts };
            for (size_t pi = 0; pi < num_parts; pi++)
                _merge_index_part(out_idx, pi, readers);
            readers.clear();
            out_idx.commit();
            for (const auto &path: chunks)
                index::writer<T>::remove(path);
        }

        void _merge_two_step(const std::string &task_name, size_t prio, const std::vector<std::string> &chunks, const std::string &final_path)
        {
            auto level_task_name = task_name + "-lvl1";
            auto todo_chunks = std::make_shared<std::vector<std::string>>(chunks);
            size_t num_groups = (todo_chunks->size() + (two_step_merge_num_files - 1)) / two_step_merge_num_files;
            auto level_chunks = std::make_shared<std::vector<std::string>>();
            for (size_t gi = 0; gi < num_groups; gi++)
                level_chunks->emplace_back(fmt::format("{}.lvl1-{}", final_path, gi));
            auto scheduled = std::make_shared<std::atomic_bool>(false);
            _sched.on_result(level_task_name, [this, scheduled, level_task_name, level_chunks, todo_chunks, task_name, prio, final_path](const auto &res) mutable {
                if (res.type() == typeid(scheduled_task_error)) {
                    logger::error("task {} {}", level_task_name, std::any_cast<scheduled_task_error>(res).what());
                    return;
                }
                if (*scheduled && _sched.task_count(level_task_name) == 0)
                    _merge_one_step(task_name, prio, *level_chunks, final_path);
            });
            for (size_t gi = 0; gi < num_groups; gi++) {
                _sched.submit(level_task_name, 2 * prio, [this, gi, todo_chunks, level_chunks] {
                    std::vector<std::string> step_chunks {};
                    for (size_t ci = gi * two_step_merge_num_files, ce = (gi + 1) * two_step_merge_num_files; ci < ce && ci < todo_chunks->size(); ++ci) {
                        step_chunks.emplace_back(todo_chunks->at(ci));
                    }
                    _merge_two_step_lvl1(step_chunks, level_chunks->at(gi));
                    return gi;
                });
            }
            *scheduled = true;
        }

        void _merge_index(const std::string &task_name, size_t prio, const std::vector<std::string> &chunks, const std::string &final_path)
        {
            if (chunks.size() > two_step_merge_num_files)
                _merge_two_step(task_name, prio, chunks, final_path);
            else
                _merge_one_step(task_name, prio, chunks, final_path);
        }
    };

    template<typename T>
    concept HasOffsetField = requires(T a) {
        { a.offset + 1 };
    };

    template<HasOffsetField T, typename ChunkIndexer>
    struct indexer_offset: public indexer_no_offset<T, ChunkIndexer> {
        using indexer_no_offset<T, ChunkIndexer>::indexer_no_offset;

        uint64_t disk_size(const std::string &slice_id="") const override
        {
            return writer<T>::disk_size(indexer_no_offset<T, ChunkIndexer>::reader_path(slice_id));
        }

        void combine(const std::string &out_slice_id, const std::string &del_slice_id) override
        {
            const std::string task_name { "combine-" + indexer_no_offset<T, ChunkIndexer>::_idx_name + "-" + out_slice_id };
            auto del_path = indexer_no_offset<T, ChunkIndexer>::reader_path(del_slice_id);
            if (!index::writer<T>::exists(del_path))
                return;
            auto out_path = indexer_no_offset<T, ChunkIndexer>::reader_path(out_slice_id);
            if (!index::writer<T>::exists(out_path)) {
                index::writer<T>::rename(del_path, out_path);
                return;
            }
            auto reader_out = std::make_shared<index::reader_mt<T>>(out_path);
            auto out_max_offset = buffer::to<uint64_t>(reader_out->get_meta("max_offset"));
            auto reader_del = std::make_shared<index::reader_mt<T>>(del_path);
            auto del_max_offset = buffer::to<uint64_t>(reader_del->get_meta("max_offset"));
            auto num_parts = reader_out->num_parts();
            if (num_parts != reader_del->num_parts())
                throw error("slice {}'s part count: {} differs from the one in slice {}: {}!",
                        del_path, reader_del->num_parts(), out_path, num_parts);
            auto writer = std::make_shared<index::writer<T>>(out_path + "-new", num_parts);
            if (del_max_offset <= out_max_offset)
                throw error("the newer index part has an older max offset {} than the max offset {} in the older index part", del_max_offset, out_max_offset);
            writer->set_meta("max_offset", buffer::from(del_max_offset));
            auto scheduled = std::make_shared<std::atomic_bool>(false);
            indexer_no_offset<T, ChunkIndexer>::_sched.on_result(task_name, [this, out_path, del_path, reader_out, reader_del, writer, scheduled, task_name](const auto &res) mutable {
                if (res.type() == typeid(scheduled_task_error)) {
                    logger::error("task {} {}", task_name, std::any_cast<scheduled_task_error>(res).what());
                    return;
                }
                if (!*scheduled || indexer_no_offset<T, ChunkIndexer>::_sched.task_count(task_name) > 0)
                    return;
                reader_del->close();
                reader_out->close();
                writer->commit();
                writer->rename(out_path);
                index::writer<T>::remove(del_path);
            });
            for (size_t pi = 0; pi < num_parts; ++pi) {
                indexer_no_offset<T, ChunkIndexer>::_sched.submit(task_name, (reader_out->size() + reader_del->size()) >> 20, [reader_out, reader_del, writer, pi]() {
                    auto thread_data_out = reader_out->init_thread(pi);
                    auto thread_data_del = reader_del->init_thread(pi);
                    T item_out {}, item_del {};
                    if (!reader_out->eof_part(pi, thread_data_out) && !reader_del->eof_part(pi, thread_data_del)) {
                        reader_out->read_part(pi, item_out, thread_data_out);
                        reader_del->read_part(pi, item_del, thread_data_del);
                        for (;;) {
                            if (item_out < item_del) {
                                writer->emplace_part(pi, item_out);
                                if (!reader_out->read_part(pi, item_out, thread_data_out)) {
                                    writer->emplace_part(pi, item_del);
                                    break;
                                }
                            } else {
                                writer->emplace_part(pi, item_del);
                                if (!reader_del->read_part(pi, item_del, thread_data_del)) {
                                    writer->emplace_part(pi, item_out);
                                    break;
                                }
                            }
                        }
                    }
                    while (reader_out->read_part(pi, item_out, thread_data_out))
                        writer->emplace_part(pi, item_out);
                    while (reader_del->read_part(pi, item_del, thread_data_del))
                        writer->emplace_part(pi, item_del);
                    return pi;
                });
            }
            *scheduled = true;
        }

        void truncate(const std::string &slice_id, uint64_t new_end_offset) override
        {
            const std::string task_name { "truncate-" + indexer_no_offset<T, ChunkIndexer>::_idx_name + "-" + slice_id };
            auto src_path = indexer_no_offset<T, ChunkIndexer>::reader_path(slice_id);
            logger::debug("truncate {} to {} bytes", src_path, new_end_offset);
            if (!index::writer<T>::exists(src_path))
                return;
            if (new_end_offset > 0) {
                auto reader = std::make_shared<index::reader_mt<T>>(src_path);
                // skip filtering if max_offset is known to be less or equal to new_end_offset
                if (buffer::to<uint64_t>(reader->get_meta("max_offset")) < new_end_offset)
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
                        return max_offset;
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