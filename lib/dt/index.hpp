/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
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
#include "util.hpp"

namespace daedalus_turbo {

    using namespace std;

    template<class T>
    class index_writer {
        string path;
        ofstream os;
        vector<T> buf;
        size_t cnt;

    public:

        index_writer() =delete;
        index_writer(const index_writer<T> &) =delete;

        index_writer(const string &path_)
            : path(path_), os(path, ios::binary), buf(0x1000), cnt(0)
        {
            if (!os) throw sys_error("Can't open file %s", path.c_str());
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
                if (!os.write(reinterpret_cast<const char *>(buf.data()), cnt * sizeof(T))) throw sys_error("ofstream write failed: %s", path.c_str());
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
        vector<index_writer<T>> _writers;
        index_writer<T> *_last_writer = nullptr;
        const size_t _writer_range;

    public:
        index_radix_writer(const vector<string> &paths)
            : _writers(), _writer_range(1 + ((256 - 1) / paths.size()))
        {
            if (paths.size() < 1 || paths.size() > 255)
                throw error("index_radix_writer expected between 1 and 255 paths but got: %zu", paths.size());
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
            if (_last_writer == nullptr) throw error("There is no unclose writable!");
            _last_writer->next();
            _last_writer = nullptr;
        }
    };

    template<class T>
    class index_reader {
        string path;
        ifstream is;
        size_t size;

    public:
        using find_result = tuple<bool, T, size_t>;

        index_reader(const string &path_)
            : path(path_), is(path, ios::binary)
        {
            if (!is) throw sys_error("failed to open file: %s", path.c_str());
            size_t file_size = filesystem::file_size(path);
            if (file_size % sizeof(T) != 0) throw error("the size of file %s is not evenly divisible by %zu!", path.c_str(), sizeof(T));
            size =  file_size / sizeof(T);
        }

        find_result find(const buffer &search_key) {
            if (search_key.size > sizeof(T)) throw error("search_key is larger than the search type: %zu", search_key.size);
            size_t lo = 0;
            size_t hi = size;
            size_t n_reads = 1; // starts with one because of the final verification read
            T item_buf;
            int last_cmp = -1;
            while (lo < hi) {
                ++n_reads;
                size_t i = (hi + lo) / 2;
                is.seekg(i * sizeof(T), ios::beg);
                is.read(reinterpret_cast<char *>(&item_buf), sizeof(item_buf));
                last_cmp = memcmp(search_key.data, &item_buf, search_key.size);
                if (last_cmp <= 0) {
                    hi = i;
                } else if (last_cmp > 0) {
                    lo = i + 1;
                }
            }
            is.seekg(lo * sizeof(T), ios::beg);
            is.read(reinterpret_cast<char *>(&item_buf), sizeof(item_buf));
            last_cmp = memcmp(search_key.data, &item_buf, search_key.size);
            return make_tuple(last_cmp == 0, move(item_buf), n_reads);
        }

        find_result next(const buffer &search_key) {
            T item_buf;
            is.read(reinterpret_cast<char *>(&item_buf), sizeof(item_buf));
            int last_cmp = memcmp(search_key.data, &item_buf, search_key.size);
            return make_tuple(last_cmp == 0, move(item_buf), 1);
        }

    };

}

#endif // !DAEDALUS_TURBO_INDEX_HPP
