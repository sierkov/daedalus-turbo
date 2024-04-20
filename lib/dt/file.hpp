/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_FILE_HPP
#define DAEDALUS_TURBO_FILE_HPP

#include <cstdio>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>
#include <zpp_bits.h>
#include <dt/logger.hpp>
#include <dt/util.hpp>
#include <dt/zstd.hpp>

namespace daedalus_turbo::file {
    struct tmp {
        tmp(const std::string &name): _path { (std::filesystem::temp_directory_path() / name).string() }
        {
        }

        ~tmp()
        {
            std::filesystem::remove(_path);
        }

        const std::string &path() const
        {
            return _path;
        }

        operator const std::string &() const
        {
            return _path;
        }

        operator std::filesystem::path() const
        {
            return std::filesystem::path { _path };
        }
    private:
        std::string _path;
    };

    struct tmp_directory {
        tmp_directory(const std::string &name)
            : _path { (std::filesystem::temp_directory_path() / name).string() }
        {
            std::filesystem::create_directories(_path);
        }

        ~tmp_directory()
        {
            std::filesystem::remove_all(_path);
        }

        const std::string &path() const
        {
            return _path;
        }

        operator const std::string &() const
        {
            return _path;
        }

        operator std::filesystem::path() const
        {
            return std::filesystem::path { _path };
        }
    private:
        std::string _path;
    };

    struct stream {
        static size_t open_files()
        {
            return _open_files;
        }

        static size_t max_open_files()
        {
            return _max_open_files;
        }
    protected:
        static std::atomic_size_t _open_files;
        static std::atomic_size_t _max_open_files;

        static void _report_open_file()
        {
            auto open = ++_open_files;
            for (;;) {
                auto max = _max_open_files.load();
                if (open <= max)
                    break;
                if (_max_open_files.compare_exchange_weak(max, open))
                    break;
            }
        }
    };

    // C-style IO is used since on Mac OS the standard C++ library has very slow I/O performance.
    // At the same time C-style IO works well on Mac, Linux, and Windows.
    struct read_stream: protected stream {
        read_stream(const std::string &path): _path { path }
        {
            _f = std::fopen(_path.c_str(), "rb");
            if (_f == NULL)
                throw error_sys("failed to open a file for reading {}", _path);
            if (std::setvbuf(_f, NULL, _IONBF, 0) != 0)
                throw error_sys("failed to disable read buffering for {}", _path);
            _report_open_file();
        }

        ~read_stream()
        {
            close();
        }

        void close()
        {
            if (_f != NULL) {
                if (std::fclose(_f) != 0)
                    throw error("failed to close file {}!", _path);
                _f = NULL;
                _open_files--;
            }
        }

        void seek(std::streampos off)
        {
#if     _WIN32
            if (_fseeki64(_f, off, SEEK_SET) != 0)
#else
            if (fseek(_f, off, SEEK_SET) != 0)
#endif
                throw error_sys("failed to seek in {}", _path);
        }

        void read(void *data, size_t num_bytes)
        {
            if (num_bytes > 0 && std::fread(data, 1, num_bytes, _f) != num_bytes)
                throw error_sys("failed to read {} bytes from {}", num_bytes, _path);
        }

    protected:
        std::FILE *_f = NULL;
        std::string _path {};
    };

    // C-style IO is used since on Mac OS the standard C++ library has very slow I/O performance.
    // At the same time C-style IO works well on Mac, Linux, and Windows.
    struct write_stream: protected stream {
        write_stream(const std::string &path, std::ios_base::openmode mode=std::ios::binary): _path { path }
        {
            auto dir_path = std::filesystem::path { _path }.parent_path();
            if (!dir_path.empty())
                std::filesystem::create_directories(dir_path);
            if (mode != std::ios::binary)
                throw error("unsupported write_stream mode: {}!", (int)mode);
            _f = std::fopen(_path.c_str(), "wb");
            if (_f == NULL)
                throw error_sys("failed to open a file for writing {}", _path);
            if (std::setvbuf(_f, NULL, _IONBF, 0) != 0)
                throw error_sys("failed to disable write buffering for {}", _path);
            _report_open_file();
        }

        write_stream(write_stream &&ws)
            : _f { ws._f }, _path { std::move(ws._path) }
        {
            ws._f = NULL;
        }

        ~write_stream()
        {
                close();
        }

        void close()
        {
            if (_f != NULL) {
                if (std::fclose(_f) != 0)
                    throw error("failed to close file {}!", _path);
                _f = NULL;
                _open_files--;
            }
        }

        void seek(std::streampos off)
        {
#if     _WIN32
            if (_fseeki64(_f, off, SEEK_SET) != 0)
#else
            if (fseek(_f, off, SEEK_SET) != 0)
#endif
                throw error_sys("failed to seek in {}", _path);
        }

        uint64_t tellp()
        {
#if     _WIN32
            auto pos = _ftelli64(_f);
#else
            auto pos = ftell(_f);
#endif
            if (pos < 0)
                throw error_sys("failed to tell the stream position in {}", _path);
            return pos;
        }

        void write(const void *data, size_t num_bytes)
        {
            if (num_bytes > 0 && std::fwrite(data, 1, num_bytes, _f) != num_bytes)
                throw error_sys("failed to write {} bytes to {}", num_bytes, _path);
        }

        void write(const buffer &data)
        {
            write(data.data(), data.size());
        }
    protected:
        FILE *_f = NULL;
        std::string _path {};
    };

    inline void read_raw(const std::string &path, uint8_vector &buffer) {
        auto file_size = std::filesystem::file_size(path);
        buffer.resize(file_size);
        read_stream is { path };
        is.read(buffer.data(), buffer.size());
    }

    inline uint8_vector read_raw(const std::string &path)
    {
        uint8_vector buf {};
        read_raw(path, buf);
        return buf;
    }

    inline void read(const std::string &path, uint8_vector &buffer) {
        read_raw(path, buffer);
        thread_local std::string_view match { ".zstd" };
        if (path.size() > 5 && path.substr(path.size() - 5) == match) {
            uint8_vector decompressed {};
            zstd::decompress(decompressed, buffer);
            buffer = std::move(decompressed);
        }
    }

    inline uint8_vector read(const std::string &path)
    {
        uint8_vector buf {};
        read(path, buf);
        return buf;
    }

    inline void read_span(const std::span<uint8_t> &v, const std::string &path, size_t num_bytes=0)
    {
        if (num_bytes == 0)
            num_bytes = std::filesystem::file_size(path);
        if (v.size() != num_bytes)
            throw error("span size: {} != the size of the file: {}", v.size(), num_bytes);
        read_stream is { path };
        is.read(v.data(), v.size());
    }

    inline void write(const std::string &path, const buffer &buffer) {
        auto tmp_path = fmt::format("{}.tmp", path);
        write_stream os { tmp_path };
        os.write(buffer.data(), buffer.size());
        os.close();
        std::filesystem::rename(tmp_path, path);
        logger::trace("written {} bytes to {}", buffer.size(), path);
    }

    inline void write_zstd(const std::string &path, const buffer &buffer)
    {
        const auto compressed = zstd::compress(buffer);
        write(path, compressed);
    }

    template<typename T>
    void read_zpp(T &v, const std::string &path)
    {
        uint8_vector zpp_data = file::read_raw(path);
        zpp::bits::in in { zpp_data };
        in(v).or_throw();
    }

    template<typename T>
    void write_zpp(const std::string &path, const T &v)
    {
        uint8_vector zpp_data {};
        zpp::bits::out out { zpp_data };
        out(v).or_throw();
        file::write(path, zpp_data);
    }

    inline uint64_t disk_used(const std::string &path)
    {
        uint64_t sz = 0;
        for (auto &e: std::filesystem::recursive_directory_iterator(path)) {
            if (e.is_regular_file()) {
                // On Mac file size is not cached so it is possible that the file does not exist any more
                // when its size is checked
                std::error_code ec {};
                auto e_sz = e.file_size(ec);
                if (!ec)
                    sz += e_sz;
            }
        }
        return sz;
    }

    inline uint64_t disk_available(const std::string &path)
    {
        auto storage = std::filesystem::space(path);
        return storage.available;
    }
}

#endif // !DAEDALUS_TURBO_FILE_HPP