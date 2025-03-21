/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_COMMON_BYTES_HPP
#define DAEDALUS_TURBO_COMMON_BYTES_HPP

#include <algorithm>
#include <span>
#include "error.hpp"
#include "format.hpp"

namespace daedalus_turbo {
    typedef std::span<uint8_t> write_buffer;

    template <typename T>
    constexpr T host_to_net(T value) noexcept
    {
        const int x = 1;
        if (*reinterpret_cast<const char *>(&x) == 1) {
            char* ptr = reinterpret_cast<char*>(&value);
            std::reverse(ptr, ptr + sizeof(T));
        }
        return value;
    }

    template <typename T>
    constexpr T net_to_host(T value) noexcept
    {
        const int x = 1;
        if (*reinterpret_cast<const char *>(&x) == 1) {
            char* ptr = reinterpret_cast<char*>(&value);
            std::reverse(ptr, ptr + sizeof(T));
        }
        return value;
    }

    struct buffer: std::span<const uint8_t> {
        buffer() =default;
        buffer(const buffer &) =default;

        template <typename T, size_t SZ>
        buffer(const std::span<T, SZ> bytes):
            buffer { reinterpret_cast<const uint8_t *>(bytes.data()), SZ * sizeof(T) }
        {
        }

        template <typename T>
        buffer(const std::span<T> bytes):
            buffer { reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size() * sizeof(T) }
        {
        }

        buffer(const uint8_t *data, const size_t sz):
            std::span<const uint8_t> { data, sz }
        {
        }

        buffer(const std::string_view s):
            buffer { reinterpret_cast<const uint8_t *>(s.data()), s.size() }
        {
        }

        buffer(const std::string &s):
            buffer { reinterpret_cast<const uint8_t *>(s.data()), s.size() }
        {
        }

        buffer &operator=(const buffer &o) =default;

        template<typename M>
        static constexpr buffer from(const M &val)
        {
            return buffer { reinterpret_cast<const uint8_t *>(&val), sizeof(val) };
        }

        template<typename M>
        constexpr M to() const
        {
            if (size() != sizeof(M)) [[unlikely]]
                throw error(fmt::format("buffer size: {} does not match the type's size: {}!", size(), sizeof(M)));
            return *reinterpret_cast<const M*>(data());
        }

        template<typename M>
        constexpr M to_host() const
        {
            if (size() != sizeof(M)) [[unlikely]]
                throw error(fmt::format("buffer size: {} does not match the type's size: {}!", size(), sizeof(M)));
            return net_to_host(*reinterpret_cast<const M*>(data()));
        }

        operator std::string_view() const noexcept
        {
            return { reinterpret_cast<const char *>(data()), size() };
        }

        std::strong_ordering operator<=>(const buffer &o) const noexcept
        {
            const auto min_sz = std::min(size(), o.size());
            const auto cmp = memcmp(data(), o.data(), min_sz);
            if (cmp < 0)
                return std::strong_ordering::less;
            if (cmp > 0)
                return std::strong_ordering::greater;
            return size() <=> o.size();
        }

        bool operator==(const buffer &o) const noexcept
        {
            return std::strong_ordering::equal == (*this <=> o);
        }

        buffer subbuf(const size_t offset, const size_t sz) const
        {
            if (offset + sz <= size()) [[likely]]
                return buffer { data() + offset, sz };
            throw error(fmt::format("requested offset: {} and size: {} end over the end of buffer's size: {}!", offset, sz, size()));
        }

        buffer subbuf(const size_t offset) const
        {
            if (offset <= size()) [[likely]]
                return subbuf(offset, size() - offset);
            throw error(fmt::format("a buffer's offset {} is greater than its size {}", offset, size()));
        }
    };

    inline uint8_t uint_from_oct(char k)
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
            default: throw error(fmt::format("unexpected character in an octal number: {}!", k));
        }
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
            default: throw error(fmt::format("unexpected character in a hex number: {}!", k));
        }
    }

    inline void init_from_hex(std::span<uint8_t> out, const std::string_view hex)
    {
        if (hex.size() != out.size() * 2)
            throw error(fmt::format("hex string must have {} characters but got {}: {}!", out.size() * 2, hex.size(), hex));
        for (size_t i = 0; i < out.size(); ++i)
            out[i] = uint_from_hex(hex[i * 2]) << 4 | uint_from_hex(hex[i * 2 + 1]);
    }

    struct uint8_vector: std::vector<uint8_t> {
        static uint8_vector from_hex(const std::string_view hex)
        {
            if (hex.size() % 2 != 0)
                throw error(fmt::format("hex string must have an even number of characters but got {}!", hex.size()));
            uint8_vector data(hex.size() / 2);
            init_from_hex(data, hex);
            return data;
        }

        uint8_vector() =default;

        uint8_vector(const size_t sz):
            std::vector<uint8_t>(sz)
        {
        }

        uint8_vector(const buffer bytes):
            std::vector<uint8_t> { bytes.begin(), bytes.end() }
        {
        }

        operator buffer() const noexcept
        {
            return { data(), size() };
        }

        std::string_view str() const noexcept
        {
            return { reinterpret_cast<const char *>(data()), size() };
        }

        uint8_vector &operator=(const buffer bytes)
        {
            resize(bytes.size());
            memcpy(data(), bytes.data(), bytes.size());
            return *this;
        }

        std::strong_ordering operator<=>(const buffer &o) const noexcept
        {
            return static_cast<buffer>(*this) <=> o;
        }

        std::strong_ordering operator<=>(const uint8_vector &o) const noexcept
        {
            return static_cast<buffer>(*this) <=> static_cast<buffer>(o);
        }

        bool operator==(const uint8_vector &o) const noexcept
        {
            return std::strong_ordering::equal == (*this <=> static_cast<buffer>(o));
        }

        bool operator==(const buffer &o) const noexcept
        {
            return std::strong_ordering::equal == (*this <=> o);
        }
    };

    static_assert(std::is_constructible_v<uint8_vector, buffer>);
    static_assert(std::is_constructible_v<buffer, uint8_vector>);
    static_assert(std::is_convertible_v<uint8_vector, buffer>);

    // Intended to be used as the target for IO operations. Does not initialize newly allocated memory.
    struct write_vector {
        write_vector(const write_vector &) =delete;
        write_vector() =default;

        write_vector(const size_t sz)
        {
            resize(sz);
        }

        write_vector(const buffer bytes)
        {
            resize(bytes.size());
            memcpy(data(), bytes.data(), _size);
        }

        write_vector(write_vector &&o):
            _capacity { o._capacity },
            _size { o._size },
            _ptr { std::move(o._ptr) }
        {
        }

        write_vector &operator=(write_vector &&o)
        {
            _capacity = o._capacity;
            _size = o._size;
            _ptr = std::move(o._ptr);
            return *this;
        }

        write_vector &operator=(const buffer bytes)
        {
            resize(bytes.size());
            memcpy(data(), bytes.data(), _size);
            return *this;
        }

        void clear()
        {
            resize(0);
        }

        void reserve(const size_t new_cap)
        {
            if (new_cap > _capacity) {
                ptr_type new_ptr { reinterpret_cast<uint8_t *>(::operator new (new_cap)) };
                // memcpy correctly handles the case when 0 bytes are copied
                memcpy(new_ptr.get(), _ptr.get(), _size);
                _ptr = std::move(new_ptr);
                _capacity = new_cap;
            }
        }

        void resize(const size_t new_sz)
        {
            reserve(new_sz);
            _size = new_sz;
        }

        size_t size() const noexcept
        {
            return _size;
        }

        size_t capacity() const noexcept
        {
            return _capacity;
        }

        // can return a nullptr when _size is 0!
        uint8_t *data() const noexcept
        {
            return _ptr.get();
        }

        uint8_t operator[](const size_t idx) const noexcept
        {
            return *(_ptr.get() + idx);
        }

        operator std::span<uint8_t>() const noexcept
        {
            return { data(), size() };
        }

        operator buffer() const noexcept
        {
            return { data(), size() };
        }

        std::string_view str() const noexcept
        {
            return { reinterpret_cast<const char *>(data()), size() };
        }

        std::strong_ordering operator<=>(const buffer &o) const noexcept
        {
            return static_cast<buffer>(*this) <=> o;
        }

        bool operator==(const buffer &o) const noexcept
        {
            return std::strong_ordering::equal == (*this <=> o);
        }

        bool operator==(const uint8_vector &o) const noexcept
        {
            return std::strong_ordering::equal == (*this <=> static_cast<buffer>(o));
        }

        bool operator==(const write_vector &o) const noexcept
        {
            return std::strong_ordering::equal == (*this <=> static_cast<buffer>(o));
        }
    private:
        struct deleter_t {
            void operator()(uint8_t *ptr)
            {
                ::operator delete(ptr);
            }
        };

        using value_type = uint8_t;
        using ptr_type = std::unique_ptr<value_type, deleter_t>;

        size_t _capacity = 0;
        size_t _size = 0;
        ptr_type _ptr {};
    };

    inline write_vector &operator<<(write_vector &v, const buffer buf)
    {
        const size_t end_off = v.size();
        v.resize(end_off + buf.size());
        memcpy(v.data() + end_off, buf.data(), buf.size());
        return v;
    }

    inline std::pmr::vector<uint8_t> &operator<<(std::pmr::vector<uint8_t> &v, const buffer buf)
    {
        const size_t end_off = v.size();
        v.resize(end_off + buf.size());
        memcpy(v.data() + end_off, buf.data(), buf.size());
        return v;
    }

    struct buffer_lowercase: buffer {
        using buffer::buffer;
    };

    inline uint8_vector &operator<<(uint8_vector &v, const uint8_t b)
    {
        const size_t end_off = v.size();
        v.resize(end_off + 1);
        v[end_off] = b;
        return v;
    }

    inline uint8_vector &operator<<(uint8_vector &v, const buffer buf)
    {
        const size_t end_off = v.size();
        v.resize(end_off + buf.size());
        memcpy(v.data() + end_off, buf.data(), buf.size());
        return v;
    }
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::buffer>: formatter<std::span<const uint8_t>> {
    };

    template<>
    struct formatter<daedalus_turbo::write_vector>: formatter<daedalus_turbo::buffer> {
    };

    template<>
    struct formatter<daedalus_turbo::uint8_vector>: formatter<daedalus_turbo::buffer> {
    };

    template<>
    struct formatter<daedalus_turbo::buffer_lowercase>: formatter<int> {
        template<typename FormatContext>
        auto format(const std::span<const uint8_t> &data, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = ctx.out();
            for (uint8_t v: data) {
                out_it = fmt::format_to(out_it, "{:02x}", v);
            }
            return out_it;
        }
    };
}

#endif // !DAEDALUS_TURBO_COMMON_BYTES_HPP
