/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_FILE_HPP
#define DAEDALUS_TURBO_FILE_HPP

#ifndef _WIN32
#    include <sys/resource.h>
#endif
#include <cstdio>
#include <atomic>
#include <filesystem>
#include <string>
#include <dt/logger.hpp>
#include <dt/util.hpp>
#include <dt/zstd.hpp>

namespace daedalus_turbo::file {
    constexpr size_t max_open_files = 8192;

    inline void set_max_open_files()
    {
        static size_t current_max_open_files = 0;
        if (current_max_open_files != max_open_files) {
#           ifdef _WIN32
                if (_setmaxstdio(max_open_files) != max_open_files)
                    throw error_sys("can't increase the max number of open files to {}!", max_open_files);
#           else
                struct rlimit lim;
                if (getrlimit(RLIMIT_NOFILE, &lim) != 0)
                    throw error_sys("getrlimit failed");
                logger::trace("before RLIMIT_NOFILE to cur: {} max: {}", lim.rlim_cur, lim.rlim_max);
                if (lim.rlim_cur < max_open_files || lim.rlim_max < max_open_files) {
                    lim.rlim_cur = max_open_files;
                    lim.rlim_max = max_open_files;
                    logger::trace("setting RLIMIT_NOFILE to cur: {} max: {}", lim.rlim_cur, lim.rlim_max);
                    if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
                        throw error_sys("failed to increase the max number of open files to {}", max_open_files);
                    if (getrlimit(RLIMIT_NOFILE, &lim) != 0)
                        throw error_sys("getrlimit failed");
                    logger::trace("after RLIMIT_NOFILE to cur: {} max: {}", lim.rlim_cur, lim.rlim_max);
                }
#           endif
            current_max_open_files = max_open_files;
        }
    }

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
        explicit read_stream(const std::string &path, const size_t buf_size=0):
            _path { path }, _buf(buf_size)
        {
            _f = std::fopen(_path.c_str(), "rb");
            if (_f == NULL) [[unlikely]]
                throw error_sys("failed to open a file for reading {}", _path);
            if (std::setvbuf(_f, reinterpret_cast<char *>(_buf.data()), _buf.empty() ? _IONBF : _IOFBF, _buf.size()) != 0) [[unlikely]]
                throw error_sys("failed to disable read buffering for {}", _path);
            _report_open_file();
        }

        read_stream(read_stream &&o): _f { o._f }, _path { std::move(o._path) }, _buf { std::move(o._buf) }
        {
            o._f = NULL;
        }

        read_stream(const read_stream &) =delete;

        ~read_stream()
        {
            close();
        }

        bool eof() const
        {
            return std::feof(_f) != 0;
        }

        void close()
        {
            if (_f != NULL) {
                if (std::fclose(_f) != 0)
                    throw error_sys("failed to close file {}!", _path);
                _f = NULL;
                --_open_files;
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

        size_t try_read(std::span<uint8_t> buf)
        {
            return std::fread(buf.data(), 1, buf.size(), _f);
        }

        void read(void *data, size_t num_bytes)
        {
            if (const auto num_read = try_read(std::span { reinterpret_cast<uint8_t *>(data), num_bytes }); num_read != num_bytes)
                throw error_sys("could read only {} bytes instead of {} from {} ferror: {} feof: {}",
                    num_read, num_bytes, _path, std::ferror(_f), std::feof(_f));
        }
    protected:
        std::FILE *_f = NULL;
        std::string _path {};
        uint8_vector _buf;
    };

    // C-style IO is used since on Mac OS the standard C++ library has very slow I/O performance.
    // At the same time C-style IO works well on Mac, Linux, and Windows.
    struct write_stream: protected stream {
        explicit write_stream(const std::string &path, const size_t buf_size=0):
            _path { path }, _buf(buf_size)
        {
            auto dir_path = std::filesystem::path { _path }.parent_path();
            if (!dir_path.empty())
                std::filesystem::create_directories(dir_path);
            _f = std::fopen(_path.c_str(), "wb");
            if (_f == NULL)
                throw error_sys("failed to open a file for writing {}", _path);
            if (std::setvbuf(_f, reinterpret_cast<char *>(_buf.data()), _buf.empty() ? _IONBF : _IOFBF, _buf.size()) != 0)
                throw error_sys("failed to disable write buffering for {}", _path);
            _report_open_file();
        }

        write_stream(write_stream &&ws)
            : _f { ws._f }, _path { std::move(ws._path) }, _buf { std::move(ws._buf) }
        {
            ws._f = NULL;
        }

        ~write_stream()
        {
            close();
        }

        write_stream &operator=(write_stream &&ws)
        {
            _f = ws._f;
            _path = std::move(ws._path);
            _buf = std::move(ws._buf);
            ws._f = NULL;
            return *this;
        }

        void close()
        {
            if (_f != NULL) {
                if (std::fclose(_f) != 0)
                    throw error("failed to close file {}!", _path);
                _f = NULL;
                _buf.clear();
                _buf.shrink_to_fit();
                --_open_files;
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

        void write(const void *data, const size_t num_bytes)
        {
            if (num_bytes > 0 && std::fwrite(data, 1, num_bytes, _f) != num_bytes)
                throw error_sys("failed to write {} bytes to {}", num_bytes, _path);
        }

        void write(const buffer data)
        {
            write(data.data(), data.size());
        }
    protected:
        FILE *_f = NULL;
        std::string _path {};
        uint8_vector _buf;
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

    inline void read_zstd(const std::string &path, uint8_vector &buffer) {
        read_raw(path, buffer);
        uint8_vector decompressed {};
        zstd::decompress(decompressed, buffer);
        buffer = std::move(decompressed);
    }

    inline uint8_vector read_zstd(const std::string &path)
    {
        uint8_vector buf {};
        read_zstd(path, buf);
        return buf;
    }

    inline void read(const std::string &path, uint8_vector &buffer) {
        thread_local std::string_view match { ".zstd" };
        if (path.size() > 5 && path.substr(path.size() - 5) == match) {
            read_zstd(path, buffer);
        } else {
            read_raw(path, buffer);
        }
    }

    inline uint8_vector read(const std::string &path)
    {
        uint8_vector buf {};
        read(path, buf);
        return buf;
    }

    inline uint8_vector read_all(const std::span<const std::string> &paths)
    {
        uint8_vector data {};
        for (const auto &p: paths)
            data << read(p);
        return data;
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
        const auto tmp_path = fmt::format("{}.tmp", path);
        {
            write_stream os { tmp_path };
            os.write(buffer.data(), buffer.size());
        }
        std::filesystem::rename(tmp_path, path);
        logger::trace("written {} bytes to {}", buffer.size(), path);
    }

    inline void write_zstd(const std::string &path, const buffer &buffer, const int level=3)
    {
        const auto compressed = zstd::compress(buffer, level);
        write(path, compressed);
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

    using path_list = vector<std::filesystem::path>;
    extern path_list files_with_ext(const std::string_view &dir, const std::string_view &ext);
    using path_list_str = vector<std::string>;
    extern path_list_str files_with_ext_str(const std::string_view &dir, const std::string_view &ext);
}

namespace fmt {
    template<>
    struct formatter<std::filesystem::path>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const std::filesystem::path &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", v.string());
        }
    };
}

#endif // !DAEDALUS_TURBO_FILE_HPP