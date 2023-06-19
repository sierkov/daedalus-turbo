/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_UTIL_HPP
#define DAEDALUS_TURBO_UTIL_HPP 1

#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <source_location>
#include <span>
#include <stdexcept>
#include <sstream>
#include <string_view>
#include <vector>

#include <dt/error.hpp>

namespace daedalus_turbo {

    class buffer;

    class uint8_vector: public std::vector<uint8_t>
    {
    public:
        using std::vector<uint8_t>::vector;

        inline uint8_vector(const buffer &buf);
        inline uint8_vector &operator=(const buffer &buf);
    };

    class buffer: public std::span<const uint8_t> {
    public:
        using std::span<const uint8_t>::span;

        buffer(const std::span<const uint8_t> s): std::span<const uint8_t>(s)
        {
        }

        buffer(const std::string_view &sv)
            : std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(sv.data()), sv.size())
        {
        }

        bool operator<(const buffer &rhs) const noexcept
        {
            size_t min_size = size();
            if (rhs.size() < min_size) min_size = rhs.size();
            int cmp = memcmp(data(), rhs.data(), min_size);
            if (cmp == 0) return size() < rhs.size();
            return cmp < 0;
        }
    };

    inline bool operator==(const buffer &lhs, const buffer &rhs) noexcept {
        if (lhs.size() != rhs.size()) return false;
        return memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
    }

    inline bool operator!=(const buffer &lhs, const buffer &rhs) noexcept {
        return !(lhs == rhs);
    }

    inline std::ostream &operator<<(std::ostream &os, const buffer &buf) {
        os << std::hex;
        for (const uint8_t *byte_ptr = buf.data(); byte_ptr < buf.data() + buf.size(); ++byte_ptr) {
            os << std::setfill('0') << std::setw(2) << static_cast<int>(*byte_ptr);
        }
        os << std::dec;
        return os;
    }

    inline uint8_vector::uint8_vector(const buffer &buf) : std::vector<uint8_t>(buf.size())
    {
        memcpy(data(), buf.data(), buf.size());
    }

    inline uint8_vector &uint8_vector::operator=(const buffer &buf)
    {
        resize(buf.size());
        memcpy(data(), buf.data(), buf.size());
        return *this;
    }

    inline std::ostream &operator<<(std::ostream &os, const uint8_vector &buf) {
        os << std::hex;
        for (auto &byte : buf) {
            os << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
        }
        os << std::dec;
        return os;
    }

    template <typename T>
    struct item_comparator_typed {        
        inline bool operator() (const T &item1, const T &item2) const {
            return memcmp(&item1, &item2, sizeof(T)) < 0;
        }
    };

    struct item_comparator {
        size_t item_size;

        item_comparator(size_t size)
            : item_size(size)
        {
        }

        inline bool operator() (const uint8_t* const item1, const uint8_t* const item2) const {
            return memcmp(item1, item2, item_size) < 0;
        }

        inline bool operator() (const char* const item1, const char* const item2) const {
            return memcmp(item1, item2, item_size) < 0;
        }
    };

    class timer_registry {
        using attr_map = std::map<std::string, std::string>;
        using timer_map = std::map<std::string, double>;
        alignas(64) std::mutex _mutex;
        attr_map _attrs;
        timer_map _timers;

    public:

        static timer_registry &instance()
        {
            alignas(64) static std::mutex _instance_mutex;
            static std::unique_ptr<timer_registry> _instance;
            std::scoped_lock lock(_instance_mutex);
            if (_instance.get() == nullptr) _instance = std::make_unique<timer_registry>();
            return *_instance;
        }

        timer_registry() : _attrs(), _timers()
        {
        }

        void set_attr(const std::string &name, const std::string &val)
        {
            std::scoped_lock lock(_mutex);
            _attrs[name] = val;
        }

        const attr_map attrs()
        {
            std::scoped_lock lock(_mutex);
            auto tmp = _attrs;
            return tmp;
        }

        void report_duration(const std::string &name, double sec)
        {
            std::scoped_lock lock(_mutex);
            _timers[name] = sec;
        }

        const timer_map timers()
        {
            std::scoped_lock lock(_mutex);
            auto tmp = _timers;
            return tmp;
        }

    };

    class timer {
        std::string title;
        std::ostream &out_stream;
        std::chrono::time_point<std::chrono::system_clock> start_time, end_time;
        bool stopped;
        timer_registry &_registry;

    public:

        timer(std::string &&title_, std::ostream &os=std::cerr)
            : title(std::move(title_)), out_stream(os), start_time(std::chrono::system_clock::now()), end_time(), stopped(false),
                _registry(timer_registry::instance())
        {
        }

        ~timer() {
            if (!stopped) stop_and_print();
        }

        void stop_and_print()
        {
            out_stream << "timer " << title << " finished in " << stop() << " secs" << std::endl;
        }

        double stop()
        {
            if (!stopped) {
                end_time = std::chrono::system_clock::now();
                stopped = true;
            }
            std::chrono::duration<double> elapsed_seconds = end_time - start_time;
            double secs = elapsed_seconds.count();
            _registry.report_duration(title, secs);
            return secs;
        }
        
    };

    inline void span_memcpy(const std::span<uint8_t> &dst, const buffer &src, const std::source_location &loc=std::source_location::current())
    {
        if (dst.size() != src.size()) throw error_fmt("expected src span to be of {} bytes but got {} in file {}, line {}!",
                                                  dst.size(), src.size(), loc.file_name(), loc.line());
        memcpy(dst.data(), src.data(), dst.size());
    }

    template <size_t SZ>
    inline void span_memcpy(const std::span<uint8_t> &dst, const std::span<const uint8_t, SZ> &src, const std::source_location &loc=std::source_location::current())
    {
        if (dst.size() != src.size()) throw error_fmt("expected src span to be of {} bytes but got {} in file {}, line {}!",
                                                  dst.size(), src.size(), loc.file_name(), loc.line());
        memcpy(dst.data(), src.data(), dst.size());
    }

    inline uint8_vector uint8_vector_copy(const std::span<const uint8_t> &src)
    {
        uint8_vector buf;
        buf.resize(src.size());
        memcpy(buf.data(), src.data(), buf.size());
        return buf;
    }

    template <size_t SZ>
    inline int span_memcmp(const std::span<uint8_t> &dst, const std::span<const uint8_t, SZ> &src, const std::source_location &loc=std::source_location::current())
    {
        if (dst.size() != src.size()) throw error_fmt("expected src span to be of {} bytes but got {} in file {}, line {}!",
                                                  dst.size(), src.size(), loc.file_name(), loc.line());
        return memcmp(dst.data(), src.data(), dst.size());
    }

    inline void read_whole_file(const std::string &path, uint8_vector &buffer, size_t size=0) {
        if (size == 0) size = std::filesystem::file_size(path);
        buffer.resize(size);
        std::ifstream is;
        is.rdbuf()->pubsetbuf(0, 0);
        is.open(path, std::ios::binary);
        if (!is) throw error_sys_fmt("Failed to open for read access: {}", path);
        if (!is.read(reinterpret_cast<char *>(buffer.data()), size)) throw error_sys_fmt("Failed to read from: {}", path);
    }

    inline uint8_vector read_whole_file(const std::string &path, size_t size=0)
    {
        uint8_vector buf;
        read_whole_file(path, buf, size);
        return buf;
    }

    template<typename T>
    inline void read_vector(std::vector<T> &v, const std::string &path)
    {
        std::ifstream is(path, std::ios::binary);
        if (!is) throw error_sys_fmt("can't open {}", path);
        size_t num_items = std::filesystem::file_size(path) / sizeof(T);
        v.resize(num_items);
        is.read(reinterpret_cast<char *>(v.data()), v.size() * sizeof(T));
        if (!is) throw error_sys_fmt("read from {} failed", path);
    }

    template<typename T>
    inline void write_vector(const std::string &path, const std::vector<T> &v)
    {
        std::ofstream os(path, std::ios::binary);
        if (!os) throw error_sys_fmt("can't open for writing {}", path);
        os.write(reinterpret_cast<const char *>(v.data()), v.size() * sizeof(T));
        if (!os) throw error_sys_fmt("write to {} failed", path);
    }

    inline void write_whole_file(const std::string &path, const buffer &buffer) {
        std::ofstream os(path, std::ios::binary);
        if (!os) throw error_sys_fmt("Failed to open for writing: {}", path);
        if (!os.write(reinterpret_cast<const char *>(buffer.data()), buffer.size())) throw error_sys_fmt("Failed to write to: {}", path);
        os.close();
    }

    inline uint8_t uint_from_hex(char k)
    {
        switch (std::tolower(k)) {
            case '0': return 0;
            case '1': return 1;
            case '2': return 2;
            case '3': return 3;
            case '4': return 4;
            case '5': return 5;
            case '6': return 6;
            case '7': return 7;
            case '8': return 8;
            case '9': return 9;
            case 'a': return 10;
            case 'b': return 11;
            case 'c': return 12;
            case 'd': return 13;
            case 'e': return 14;
            case 'f': return 15;
            default: throw error_fmt("unexpected character in a hex string: {}!", k);
        }
    }

    inline void bytes_from_hex(uint8_vector &data, const std::string_view& hex) {
        data.clear();
        if (hex.size() % 2 != 0) throw error_fmt("hex string must have an even number of characters but got {}!", hex.size());
        for (const char *p = hex.data(), *end = hex.data() + hex.size(); p < end; p += 2) {
            data.push_back(uint_from_hex(*p) << 4 | uint_from_hex(*(p + 1)));
        }
    }

    inline uint8_vector bytes_from_hex(const std::string_view& hex) {
        uint8_vector data;
        bytes_from_hex(data, hex);
        return data;
    }

}

namespace fmt {

    template<>
    struct formatter<daedalus_turbo::buffer>: public formatter<std::span<const uint8_t>> {
    };
}

#endif // !DAEDALUS_TURBO_UTIL_HPP
