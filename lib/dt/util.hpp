/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#ifndef DAEDALUS_TURBO_UTIL_HPP
#define DAEDALUS_TURBO_UTIL_HPP 1

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
#include <stdexcept>
#include <sstream>
#include <string_view>
#include <vector>

namespace daedalus_turbo {

    using namespace std;

    inline string format(const char *fmt, ...)
    {
        char buf[0x2000];
        va_list args;
        va_start(args, fmt);
        int res = vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        if (res >= 0) {
            return string(string_view(buf, res));
        } else {
            return string("exception formatting with format string ") + fmt + " has failed";
        }
    }

    class error: public runtime_error {
    public:

        template<typename... Args>
        error(const char *fmt, Args&&... a)
            : runtime_error(format(fmt, forward<Args>(a)...))
        {
        }
    };

    class sys_error: public error
    {
    public:

        template<typename... Args>
        sys_error(const char *fmt, Args&&... a)
            : error("%s, errno: %d, strerror: %s", format(fmt, forward<Args>(a)...).c_str(), errno, strerror(errno))
        {
        }
    };

    struct buffer;

    class bin_string: public vector<uint8_t>
    {
    public:
        bin_string() : vector<uint8_t>()
        {
        }

        bin_string(size_t size) : vector<uint8_t>(size)
        {
        }

        bin_string(const vector<uint8_t> &v) : vector<uint8_t>(v)
        {
        }

        inline bin_string(const buffer &buf);

        inline bin_string &operator=(const buffer &buf);
    };

    struct buffer {
        const uint8_t *data;
        size_t size;

        buffer()
            : data(0), size(0)
        {
        }

        buffer(const buffer &buf)
            : data(buf.data), size(buf.size)
        {
        }

        buffer(const bin_string &buf)
            : data(buf.data()), size(buf.size())
        {
        }

        buffer(const uint8_t *aData, size_t aSize)
            : data(aData), size(aSize)
        {
        }

        bool operator < (const buffer &aVal) const {
            size_t minSize = size;
            if (aVal.size < minSize) minSize = aVal.size;
            int res = memcmp(data, aVal.data, minSize);
            if (res == 0) return size < aVal.size;
            return res < 0;
        }

        bool operator==(const buffer &b) const {
            if (size != b.size) return false;
            return memcmp(data, b.data, size) == 0;
        }

        bool operator==(const string_view &v) const {
            if (size != v.size()) return false;
            return memcmp(data, v.data(), size) == 0;
        }

    };

    inline ostream &operator<<(ostream &os, const buffer &buf) {
        os << hex;
        for (const uint8_t *byte_ptr = buf.data; byte_ptr < buf.data + buf.size; ++byte_ptr) {
            os << setfill('0') << setw(2) << static_cast<int>(*byte_ptr);
        }
        os << dec;
        return os;
    }

    inline bin_string::bin_string(const buffer &buf) : vector<uint8_t>(buf.size)
    {
        memcpy(data(), buf.data, buf.size);
    }

    inline bin_string &bin_string::operator=(const buffer &buf)
    {
        resize(buf.size);
        memcpy(data(), buf.data, buf.size);
        return *this;
    }

    inline ostream &operator<<(ostream &os, const bin_string &buf) {
        os << hex;
        for (auto &byte : buf) {
            os << setfill('0') << setw(2) << static_cast<int>(byte);
        }
        os << dec;
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
        using attr_map = map<string, string>;
        using timer_map = map<string, double>;
        alignas(64) mutex _mutex;
        attr_map _attrs;
        timer_map _timers;

    public:

        static timer_registry &instance()
        {
            alignas(64) static mutex _instance_mutex;
            static unique_ptr<timer_registry> _instance;
            scoped_lock lock(_instance_mutex);
            if (_instance.get() == nullptr) _instance = make_unique<timer_registry>();
            return *_instance;
        }

        timer_registry() : _attrs(), _timers()
        {
        }

        void set_attr(const string &name, const string &val)
        {
            scoped_lock lock(_mutex);
            _attrs[name] = val;
        }

        const attr_map attrs()
        {
            scoped_lock lock(_mutex);
            auto tmp = _attrs;
            return tmp;
        }

        void report_duration(const string &name, double sec)
        {
            scoped_lock lock(_mutex);
            _timers[name] = sec;
        }

        const timer_map timers()
        {
            scoped_lock lock(_mutex);
            auto tmp = _timers;
            return tmp;
        }

    };

    class timer {
        string title;
        ostream &out_stream;
        chrono::time_point<chrono::system_clock> start_time, end_time;
        bool stopped;
        timer_registry &_registry;

    public:
        timer()
            : title("unnamed"), out_stream(cerr), start_time(chrono::system_clock::now()), end_time(), stopped(false),
                _registry(timer_registry::instance())
        {
        }

        timer(string &&title_)
            : title(move(title_)), out_stream(cerr), start_time(chrono::system_clock::now()), end_time(), stopped(false),
                _registry(timer_registry::instance())
        {
        }

        ~timer() {
            if (!stopped) stop_and_print();
        }

        void set_title(const string &new_title)
        {
            title = new_title;
        }

        void stop_and_print()
        {
            out_stream << "timer " << title << " finished in " << stop() << " secs" << endl;
        }

        double stop()
        {
            if (!stopped) {
                end_time = chrono::system_clock::now();
                stopped = true;
            }
            chrono::duration<double> elapsed_seconds = end_time - start_time;
            double secs = elapsed_seconds.count();
            _registry.report_duration(title, secs);
            return secs;
        }
        
    };

    inline void read_whole_file(const string &path, bin_string &buffer) {
        size_t size = filesystem::file_size(path);
        buffer.resize(size);
        ifstream is(path, ios::binary);
        if (!is) throw sys_error("Failed to open for read access: %s", path.c_str());
        if (!is.read(reinterpret_cast<char *>(buffer.data()), size)) throw sys_error("Failed to read from: %s", path.c_str());
    }

    inline void write_whole_file(const string &path, const bin_string &buffer) {
        ofstream os(path, ios::binary);
        if (!os) throw sys_error("Failed to open for writing: %s", path.c_str());
        if (!os.write(reinterpret_cast<const char *>(buffer.data()), buffer.size())) throw sys_error("Failed to write to: %s", path.c_str());
        os.close();
    }

    inline uint8_t uint_from_hex(char k)
    {
        switch (tolower(k)) {
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
            default: throw error("unexpected character in a hex string: %c!", k);
        }
    }

    inline void bytes_from_hex(bin_string &data, const string_view& hex) {
        data.clear();
        if (hex.size() % 2 != 0) throw error("hex string must have an even number of characters but got %zu!", hex.size());
        for (const char *p = hex.data(), *end = hex.data() + hex.size(); p < end; p += 2) {
            data.push_back(uint_from_hex(*p) << 4 | uint_from_hex(*(p + 1)));
        }
    }

}

template<>
struct std::hash<daedalus_turbo::buffer> {
    size_t operator()(const daedalus_turbo::buffer &val) const noexcept {
        size_t hash;
        memcpy(&hash, val.data, sizeof(hash));
        return hash;
    }
};

#endif // !DAEDALUS_TURBO_UTIL_HPP
