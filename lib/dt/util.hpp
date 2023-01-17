/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
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

    class buffer;

    class uint8_vector: public vector<uint8_t>
    {
    public:
        uint8_vector() : vector<uint8_t>()
        {
        }

        uint8_vector(size_t size) : vector<uint8_t>(size)
        {
        }

        uint8_vector(const vector<uint8_t> &v) : vector<uint8_t>(v)
        {
        }

        inline uint8_vector(const buffer &buf);

        inline uint8_vector &operator=(const buffer &buf);
    };

    class buffer {
        const uint8_t *_data;
        size_t _size;

    public:

        buffer()
            : _data(0), _size(0)
        {
        }

        buffer(const uint8_vector &buf)
            : _data(buf.data()), _size(buf.size())
        {
        }

        buffer(const uint8_t *data, size_t size)
            : _data(data), _size(size)
        {
        }

        bool operator<(const buffer &val) const {
            size_t min_size = _size;
            if (val._size < min_size) min_size = val._size;
            int res = memcmp(_data, val._data, min_size);
            if (res == 0) return _size < val._size;
            return res < 0;
        }

        bool operator==(const buffer &b) const {
            if (_size != b._size) return false;
            return memcmp(_data, b._data, _size) == 0;
        }

        bool operator==(const string_view &v) const {
            if (_size != v.size()) return false;
            return memcmp(_data, v.data(), _size) == 0;
        }

        inline void set(const uint8_t *data, size_t size)
        {
            _data = data;
            _size = size;
        }

        inline const uint8_t *data() const
        {
            return _data;
        }

        inline size_t size() const
        {
            return _size;
        }

    };

    inline ostream &operator<<(ostream &os, const buffer &buf) {
        os << hex;
        for (const uint8_t *byte_ptr = buf.data(); byte_ptr < buf.data() + buf.size(); ++byte_ptr) {
            os << setfill('0') << setw(2) << static_cast<int>(*byte_ptr);
        }
        os << dec;
        return os;
    }

    inline uint8_vector::uint8_vector(const buffer &buf) : vector<uint8_t>(buf.size())
    {
        memcpy(data(), buf.data(), buf.size());
    }

    inline uint8_vector &uint8_vector::operator=(const buffer &buf)
    {
        resize(buf.size());
        memcpy(data(), buf.data(), buf.size());
        return *this;
    }

    inline ostream &operator<<(ostream &os, const uint8_vector &buf) {
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

    inline void read_whole_file(const string &path, uint8_vector &buffer) {
        size_t size = filesystem::file_size(path);
        buffer.resize(size);
        ifstream is(path, ios::binary);
        if (!is) throw sys_error("Failed to open for read access: %s", path.c_str());
        if (!is.read(reinterpret_cast<char *>(buffer.data()), size)) throw sys_error("Failed to read from: %s", path.c_str());
    }

    inline void write_whole_file(const string &path, const uint8_vector &buffer) {
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

    inline void bytes_from_hex(uint8_vector &data, const string_view& hex) {
        data.clear();
        if (hex.size() % 2 != 0) throw error("hex string must have an even number of characters but got %zu!", hex.size());
        for (const char *p = hex.data(), *end = hex.data() + hex.size(); p < end; p += 2) {
            data.push_back(uint_from_hex(*p) << 4 | uint_from_hex(*(p + 1)));
        }
    }

}

#endif // !DAEDALUS_TURBO_UTIL_HPP
