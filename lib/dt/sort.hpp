/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_PARALLEL_SORT_HPP
#define DAEDALUS_TURBO_PARALLEL_SORT_HPP 1

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <sstream>
#include <vector>

#include <dt/scheduler.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo {

    typedef std::string (*merge_sort_func)(const std::string &out_path, const std::vector<std::string> &paths, bool delete_source);

    class stdio_stream {
        FILE *_s = 0;
        bool _eof = false;

    public:

        stdio_stream()
        {
        }

        stdio_stream(const stdio_stream &) =delete;

        stdio_stream(stdio_stream &&v)
            : _s(v._s), _eof(v._eof)
        {
            v._s = 0;
        }

        stdio_stream(const char *path, const char *mode, bool buffered)
        {
            open(path, mode, buffered);
        }

        ~stdio_stream()
        {
            close();
        }

        stdio_stream &operator=(const stdio_stream &) =delete;

        stdio_stream &operator=(stdio_stream &&v)
        {
            close();
            _s = v._s;
            _eof = v._eof;
            v._s = 0;
            return *this;
        }

        void close()
        {
            if (_s) {
                if (fclose(_s) != 0) throw error_sys_fmt("Failed to close file!");
                _s = 0;
            }            
        }

        void open(const char *path, const char *mode, bool buffered)
        {
            close();
            _eof = false;
            _s = fopen(path, mode);
            if (!_s) throw error_fmt("Failed to open file {} with mode {}", path, mode);
            if (!buffered) {
                if (std::setvbuf(_s, NULL, _IONBF, 0) != 0) throw error_sys_fmt("Failed to remove stdio buffering");
            }
        }

        bool eof() {
            return _eof;
        }

        void seek(size_t offset)
        {
            if (std::fseek(_s, offset, SEEK_SET) != 0)
                throw error_sys_fmt("file seek operation failed!");
        }

        size_t read(uint8_t *data, size_t size)
        {
            if (!_s) throw error_fmt("a read request on a non-opened stream!");
            size_t n_read = std::fread(data, 1, size, _s);
            if (n_read != size) _eof = true;
            return n_read;
        }

        void write(const uint8_t *data, size_t size)
        {
            if (!_s) throw error_fmt("a read request on a non-opened stream!");
            size_t n_written = std::fwrite(data, 1, size, _s);
            if (n_written != size) throw error_sys_fmt("write failed!");
        }

    };

    template<typename T, size_t BUF_ITEMS>
    class item_read_stream
    {
        uint8_vector _buf;
        uint8_t *_buf_ptr = nullptr;
        uint8_t *_buf_end = nullptr;
        stdio_stream _s;
        bool _eof = false;

    public:

        item_read_stream()
            : _buf(sizeof(T) * BUF_ITEMS), _s()
        {
        }

        item_read_stream(item_read_stream &&v)
            : _buf(std::move(v._buf)), _buf_ptr(v._buf_ptr), _buf_end(v._buf_end), _s(std::move(v._s)), _eof(v._eof)
        {
        }

        item_read_stream(const item_read_stream &v) =delete;
        item_read_stream &operator=(const item_read_stream &v) =delete;
        
        item_read_stream &operator=(item_read_stream &&v)
        {
            _buf = std::move(v._buf);
            _buf_ptr = v._buf_ptr;
            _buf_end = v._buf_end;
            _s = std::move(v._s);
            _eof = v._eof;
            return *this;
        }

        void close()
        {
            _s.close();
        }

        void open(const char *path) {
            _s.open(path, "rb", false);
            _eof = false;
        }

        bool eof() {
            return _eof;
        }

        bool read(T &data) {
            if (_buf_ptr >= _buf_end) {
                size_t n_read = _s.read(_buf.data(), _buf.size());
                _buf_ptr = _buf.data();
                _buf_end = _buf.data() + n_read;
            }
            if (_buf_ptr < _buf_end) {
                memcpy(&data, _buf_ptr, sizeof(T));
                _buf_ptr += sizeof(T);
                return true;
            }
            _eof = true;
            return false;
        }

    };

    template<typename T, size_t BUF_ITEMS>
    class item_write_stream
    {
        uint8_vector _buf;
        uint8_t *_buf_ptr;
        uint8_t *_buf_end;
        stdio_stream _s;

    public:

        item_write_stream()
            : _buf(sizeof(T) * BUF_ITEMS), _buf_ptr(_buf.data()), _buf_end(_buf_ptr + _buf.size()), _s()
        {
        }

        void close()
        {
            if (_buf_ptr > _buf.data()) _s.write(_buf.data(), _buf_ptr - _buf.data());
            _s.close();
        }

        void open(const char *path) {
            _s.open(path, "wb", false);
        }

        void write(const T &data) {
            memcpy(_buf_ptr, &data, sizeof(T));
            _buf_ptr += sizeof(T);
            if (_buf_ptr >= _buf_end) {
                _s.write(_buf.data(), _buf.size());
                _buf_ptr = _buf.data();
                _buf_end = _buf.data() + _buf.size();
            }
        }

    };

    class stdio_stream_sync
    {
        alignas(hardware_destructive_interference_size) std::mutex _mutex;
        stdio_stream _stream;

    public:
        stdio_stream_sync(stdio_stream &&stream)
            : _stream(std::move(stream))
        {
        }

        void write(size_t offset, const uint8_t *data, size_t size)
        {
            std::scoped_lock lock(_mutex);
            _stream.seek(offset);
            _stream.write(data, size);
        }

    };

    template<typename T, typename S, size_t BUF_ITEMS>
    class item_seeking_write_stream
    {
        S &_s;
        size_t _offset;
        const size_t _offset_end;
        uint8_vector _buf;
        uint8_t *_buf_ptr;
        uint8_t *_buf_end;;

    public:

        item_seeking_write_stream(S &stream, size_t start_offset, size_t end_offset)
            : _s(stream), _offset(start_offset), _offset_end(end_offset),
                _buf(sizeof(T) * BUF_ITEMS), _buf_ptr(_buf.data()), _buf_end(_buf_ptr + _buf.size())
        {
            if (_offset > _offset_end) throw error_fmt("start_offset: {} must be smaller than or equal to end_offset: {}", start_offset, end_offset);
        }

        ~item_seeking_write_stream()
        {
            flush();
        }

        void flush()
        {
            if (_buf_ptr > _buf.data()) {
                _s.write(_offset, _buf.data(), _buf_ptr - _buf.data());
                _offset += _buf_ptr - _buf.data();
                _buf_ptr = _buf.data();
            }
        }

        void write(const T &data) {
            if (_offset + _buf_ptr - _buf.data() + sizeof(T) > _offset_end) throw error_fmt("a potential write past the end offset!");
            memcpy(_buf_ptr, &data, sizeof(T));
            _buf_ptr += sizeof(T);
            if (_buf_ptr >= _buf_end) flush();
        }

    };

    template<typename W, typename T>
    size_t merge_sort_queue_writer(W &output_stream, const std::vector<std::string> &paths, bool delete_source = true) {
        constexpr auto item_size = sizeof(T);
        item_read_stream<T, 400> streams[paths.size()];
        size_t total_in_size = 0;
        struct Item {
            T val;
            size_t stream_idx;

            Item(const Item &i) : val(i.val), stream_idx(i.stream_idx)
            {
            }

            Item(Item &&i) : val(std::move(i.val)), stream_idx(i.stream_idx)
            {
            }

            Item(T &&v, size_t idx) : val(std::move(v)), stream_idx(idx)
            {
            }

            Item &operator=(Item &&i)
            {
                val = std::move(i.val);
                stream_idx = i.stream_idx;
                return *this;
            }

            bool operator<(const Item& v) const noexcept
            {
                // priority queue returns the greatest element but we need the smallest!
                return !(val < v.val);
            }
        };
        using ItemQueue = std::priority_queue<Item>;
        ItemQueue items_to_consider;
        for (size_t i = 0; i < paths.size(); ++i) {
            size_t f_size = std::filesystem::file_size(paths[i]);
            if (f_size % item_size != 0) throw error_fmt("file size must be a multiple of item_size!");
            total_in_size += f_size;
            streams[i].open(paths[i].c_str());
            T val;
            if (streams[i].read(val)) items_to_consider.emplace(std::move(val), i);
        }

        while (items_to_consider.size() > 0) {
            Item next(items_to_consider.top());
            items_to_consider.pop();
            output_stream.write(next.val);
            if (streams[next.stream_idx].read(next.val)) items_to_consider.push(std::move(next));
        }
        for (size_t i = 0; i < paths.size(); ++i) {
            streams[i].close();
            if (delete_source) std::filesystem::remove(paths[i]);
        }
        return total_in_size;
    }

    template<typename T>
    std::string merge_sort_files(const std::string &out_path, const std::vector<std::string> &paths, bool delete_source = true) {
        using write_stream = item_write_stream<T, 10000>;
        write_stream os;
        os.open(out_path.c_str());
        size_t total_in_size = merge_sort_queue_writer<write_stream, T>(os, paths, delete_source);
        os.close();
        if (std::filesystem::file_size(out_path) != total_in_size) {
            throw error_fmt("{}: size: {} != total input size: {}", out_path, std::filesystem::file_size(out_path), total_in_size);
        }
        return out_path;
    }

    template<typename T>
    std::string merge_sort_radix(const std::string &out_path, const std::vector<std::string> &paths, const std::vector<std::string> &radix_suffixes, bool delete_source = true)
    {
        stdio_stream_sync sync_stream(stdio_stream(out_path.c_str(), "wb", false));
        size_t num_radixes = radix_suffixes.size();
        size_t radix_size[num_radixes];
        using write_stream = item_seeking_write_stream<T, stdio_stream_sync, 10000>;
        std::vector<write_stream> _write_streams;
        std::vector<std::string> radix_paths[num_radixes];

        memset(radix_size, 0, sizeof(radix_size));
        for (size_t ri = 0; ri < num_radixes; ++ri) {
            for (const auto &p: paths) {
                std::string radix_path = p + radix_suffixes[ri];
                radix_size[ri] += std::filesystem::file_size(radix_path);
                radix_paths[ri].push_back(std::move(radix_path));
            }
        }
        size_t offset = 0;
        _write_streams.reserve(num_radixes);
        for (size_t ri = 0; ri < num_radixes; ++ri) {
            _write_streams.emplace_back(sync_stream, offset, offset + radix_size[ri]);
            offset += radix_size[ri];
        }
        for (size_t ri = 0; ri < num_radixes; ++ri) {
            merge_sort_queue_writer<write_stream, T>(_write_streams[ri], radix_paths[ri], delete_source);
        }
        return out_path;
    }

}

#endif // !DAEDALUS_TURBO_PARALLEL_SORT_HPP
