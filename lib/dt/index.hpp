/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_INDEX_HPP
#define DAEDALUS_TURBO_INDEX_HPP

#include <algorithm>
#include <cstring>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <tuple>

#include <dt/util.hpp>

namespace daedalus_turbo {

    template<class T>
    class index_writer {
        std::string path;
        std::ofstream os;
        std::vector<T> buf;
        size_t cnt;

    public:

        index_writer() =delete;
        index_writer(const index_writer<T> &) =delete;

        index_writer(const std::string &path_)
            : path(path_), os(path, std::ios::binary), buf(0x1000), cnt(0)
        {
            if (!os) throw error_sys_fmt("Can't open file {}", path);
        }

        index_writer(index_writer<T> &&i)
        {
            path = i.path;
            os = move(i.os);
            buf = move(i.buf);
            cnt = i.cnt;
        }

        ~index_writer() {
            flush();
        }

        void flush() {
            if (cnt > 0) {
                sort(buf.begin(), buf.begin() + cnt, item_comparator_typed<T>());
                if (!os.write(reinterpret_cast<const char *>(buf.data()), cnt * sizeof(T))) throw error_sys_fmt("ofstream write failed: {}", path);
                os.close();
                cnt = 0;
            }
        }

        T &writable() {
            while (cnt >= buf.size()) {
                buf.resize(buf.size() * 2);
            }
            return *(reinterpret_cast<T *>(buf.data() + cnt));
        }

        void next() {
            cnt++;
        }
    };

    template<class T>
    class index_radix_writer {
        std::vector<index_writer<T>> _writers;
        index_writer<T> *_last_writer = nullptr;
        const size_t _writer_range;

    public:
        index_radix_writer(const std::vector<std::string> &paths)
            : _writers(), _writer_range(1 + ((256 - 1) / paths.size()))
        {
            if (paths.size() < 1 || paths.size() > 255)
                throw error_fmt("index_radix_writer expected between 1 and 255 paths but got: {}", paths.size());
            _writers.reserve(paths.size());
            for (const auto &p: paths)
                _writers.emplace_back(p);
        }

        void flush()
        {
            for (auto &w: _writers) w.flush();
        }

        T &writable(uint8_t first_byte)
        {
            size_t writer_idx = first_byte / _writer_range;
            _last_writer = &_writers[writer_idx];
            return _last_writer->writable();
        }

        void next() {
            if (_last_writer == nullptr) throw error_fmt("There is no unclose writable!");
            _last_writer->next();
            _last_writer = nullptr;
        }
    };

    template<class T>
    class index_reader_seq {
    public:

        index_reader_seq(const std::string &path): _path(path), _is(_path, std::ios::binary), _size(std::filesystem::file_size(path))
        {
            if (!_is) throw error_sys_fmt("Can't open file {}", _path);
        }

        bool eof()
        {
            return _read >= _size;
        }

        void read(T& item)
        {
            _is.read(reinterpret_cast<char *>(&item), sizeof(item));
            if (_is.fail()) throw error_sys_fmt("file read from {} failed", _path);
            _read += sizeof(item);
        }

        void close()
        {
            _is.close();
        }

    private:
        std::string _path;
        std::ifstream _is;
        size_t _size = 0;
        size_t _read = 0;
    };

    template<class T>
    class index_reader {
        std::string _path;
        std::ifstream _is;
        size_t _cache_sparcity;
        std::map<size_t, T> _marker_cache;
        std::vector<T> _leaf_cache;
        size_t _leaf_cache_lo;
        size_t _leaf_cache_sz;
        size_t _size;

    public:
        using find_result = std::tuple<bool, T, size_t>;

        index_reader(const std::string &path, size_t final_read_size=0x10000)
            : _path(path), _is(path, std::ios::binary), _cache_sparcity(final_read_size / sizeof(T)), _marker_cache(), _leaf_cache(_cache_sparcity)
        {
            if (!_is) throw error_sys_fmt("failed to open file: {}", path);
            size_t file_size = std::filesystem::file_size(path);
            if (file_size % sizeof(T) != 0) throw error_fmt("the size of file {} is not evenly divisible by {}!", path, sizeof(T));
            _size =  file_size / sizeof(T);
            _leaf_cache_lo = _size;
            _leaf_cache_sz = 0;
        }

        find_result find(const buffer &search_key) {
            if (search_key.size() > sizeof(T)) throw error_fmt("search_key is larger than the search type: {}", search_key.size());
            bool match = false;
            T match_item {};
            size_t n_reads = 0;
            size_t lo = 0;
            size_t hi = _size;
            T item_buf;
            while (lo < hi) {
                size_t i = (hi + lo) / 2;
                if (hi - lo > _cache_sparcity) {
                    auto cache_it = _marker_cache.find(i);
                    if (cache_it != _marker_cache.end()) {
                        item_buf = cache_it->second;
                    } else {
                        ++n_reads;
                        _is.seekg(i * sizeof(T), std::ios::beg);
                        _is.read(reinterpret_cast<char *>(&item_buf), sizeof(item_buf));
                        _marker_cache.emplace(i, item_buf);
                    }
                } else {
                    if (i < _leaf_cache_lo || i >= _leaf_cache_lo + _leaf_cache_sz) {
                        _leaf_cache_lo = lo;
                        _leaf_cache_sz = _cache_sparcity;
                        if (_leaf_cache_lo + _leaf_cache_sz > _size) _leaf_cache_sz = _size - _leaf_cache_lo;
                        ++n_reads;
                        _is.seekg(_leaf_cache_lo * sizeof(T), std::ios::beg);
                        _is.read(reinterpret_cast<char *>(_leaf_cache.data()), sizeof(T) * _leaf_cache_sz);
                    }
                    item_buf = _leaf_cache[i - _leaf_cache_lo];
                }
                int cmp = memcmp(search_key.data(), &item_buf, search_key.size());
                if (cmp <= 0) {
                    if (cmp == 0) {
                        match = true;
                        match_item = item_buf;
                    }
                    hi = i;
                } else if (cmp > 0) {
                    lo = i + 1;
                }
            }
            // set the postion for a potential call to next()
            if (match) _is.seekg((lo + 1) * sizeof(T), std::ios::beg);
            return std::make_tuple(match, match_item, n_reads);
        }

        find_result next(const buffer &search_key) {
            T item_buf;
            _is.read(reinterpret_cast<char *>(&item_buf), sizeof(item_buf));
            int last_cmp = memcmp(search_key.data(), &item_buf, search_key.size());
            return std::make_tuple(last_cmp == 0, std::move(item_buf), 1);
        }

    };

    inline std::vector<std::string> make_radix_paths(const std::string &path, size_t num_writers)
    {
        std::vector<std::string> paths;
        paths.reserve(num_writers);
        for (size_t i = 0; i < num_writers; ++i)
            paths.emplace_back(path + ".radix-" + std::to_string(i));
        return paths;
    }

}

#endif // !DAEDALUS_TURBO_INDEX_HPP
