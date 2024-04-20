/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_UTIL_HPP
#define DAEDALUS_TURBO_UTIL_HPP

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <source_location>
#include <span>
#include <vector>
#include <dt/array.hpp>
#include <dt/container.hpp>
#include <dt/error.hpp>

namespace daedalus_turbo {
    template <typename T>
    constexpr T host_to_net(T value) noexcept
    {
        constexpr int x = 1;
        if (*reinterpret_cast<const char *>(&x) == 1) {
            char* ptr = reinterpret_cast<char*>(&value);
            std::reverse(ptr, ptr + sizeof(T));
        }
        return value;
    }

    template <typename T>
    constexpr T net_to_host(T value) noexcept
    {
        constexpr int x = 1;
        if (*reinterpret_cast<const char *>(&x) == 1) {
            char* ptr = reinterpret_cast<char*>(&value);
            std::reverse(ptr, ptr + sizeof(T));
        }
        return value;
    }

    typedef std::span<uint8_t> write_buffer;

    struct buffer;

    struct uint8_vector: vector<uint8_t> {
        using vector::vector;

        static uint8_vector from_hex(const std::string_view& hex)
        {
            uint8_vector data {};
            if (hex.size() % 2 != 0)
                throw error("hex string must have an even number of characters but got {}!", hex.size());
            for (const char *p = hex.data(), *end = hex.data() + hex.size(); p < end; p += 2) {
                data.push_back(uint_from_hex(*p) << 4 | uint_from_hex(*(p + 1)));
            }
            return data;
        }

        inline uint8_vector(const buffer &buf);
        inline uint8_vector &operator=(const buffer &buf);
        inline const buffer span() const;

        inline std::string_view str() const
        {
            return std::string_view { reinterpret_cast<const char *>(data()), size() };
        }
    };

    struct buffer: std::span<const uint8_t> {
        using std::span<const uint8_t>::span;

        template<typename M>
        static buffer from(const M &val)
        {
            return buffer { reinterpret_cast<const uint8_t *>(&val), sizeof(val) };
        }

        buffer(const std::span<const uint8_t> &s): std::span<const uint8_t>(s)
        {
        }

        buffer(const std::string_view &sv)
            : std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(sv.data()), sv.size())
        {
        }

        buffer(const std::string &s)
            : std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()), s.size())
        {
        }

        buffer(const void *data, size_t sz)
            : std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(data), sz)
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

        template<typename M>
        const M to() const
        {
            if (size() != sizeof(M))
                throw error("buffer size: {} does not match the type's size: {}!", size(), sizeof(M));
            return *reinterpret_cast<const M*>(data());
        }

        inline std::string_view string_view() const
        {
            return std::string_view { reinterpret_cast<const char *>(data()), size() };
        }

        buffer subbuf(size_t offset, size_t sz) const
        {
            if (offset + sz > size()) throw error("requested offset: {} and size: {} end over the end of buffer's size: {}!", offset, sz, size());
            return buffer { data() + offset, sz };
        }

        buffer subspan(size_t offset, size_t sz) const
        {
            return subbuf(offset, sz);
        }

        template<size_t SZ>
        std::span<const uint8_t, SZ> subspan_fix(size_t offset) const
        {
            if (offset + SZ > size())
                throw error("not enough data to create {} sized span at offset {}", SZ, offset);
            return std::span<const uint8_t, SZ> { data() + offset, SZ };
        }

        inline const buffer span() const
        {
            return buffer { *this };
        }
    };

    struct buffer_readable: buffer {
        using buffer::buffer;
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

    inline uint8_vector::uint8_vector(const buffer &buf): vector(buf.size())
    {
        memcpy(data(), buf.data(), buf.size());
    }

    inline uint8_vector &uint8_vector::operator=(const buffer &buf)
    {
        resize(buf.size());
        memcpy(data(), buf.data(), buf.size());
        return *this;
    }

    inline const buffer uint8_vector::span() const
    {
        return buffer { *this };
    }

    inline uint8_vector &operator<<(uint8_vector &v, const buffer buf)
    {
        size_t end_off = v.size();
        v.resize(end_off + buf.size());
        memcpy(v.data() + end_off, buf.data(), buf.size());
        return v;
    }

    inline void span_memcpy_off(const std::span<uint8_t> &dst, size_t dst_off, const buffer &src, const std::source_location &loc=std::source_location::current())
    {
        if (dst_off >= dst.size())
            throw error("dst_off must be less than {} but got {} in file {} at line {}!",
                dst.size(), dst_off, loc.file_name(), loc.line());
        if (dst.size() - dst_off < src.size())
            throw error("expected dst must have more than {} bytes after offset {} but got {} in file {}, line {}!",
                src.size(), dst_off, dst.size() - dst_off, loc.file_name(), loc.line());
        memcpy(dst.data() + dst_off, src.data(), src.size());
    }

    inline void span_memcpy(const std::span<uint8_t> &dst, const buffer &src, const std::source_location &loc=std::source_location::current())
    {
        if (dst.size() != src.size()) throw error("expected src span to be of {} bytes but got {} in file {}, line {}!",
                                                  dst.size(), src.size(), loc.file_name(), loc.line());
        memcpy(dst.data(), src.data(), dst.size());
    }

    template <size_t SZ>
    inline void span_memcpy(const std::span<uint8_t> &dst, const std::span<const uint8_t, SZ> &src, const std::source_location &loc=std::source_location::current())
    {
        if (dst.size() != src.size()) throw error("expected src span to be of {} bytes but got {} in file {}, line {}!",
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
        if (dst.size() != src.size()) throw error("expected src span to be of {} bytes but got {} in file {}, line {}!",
                                                  dst.size(), src.size(), loc.file_name(), loc.line());
        return memcmp(dst.data(), src.data(), dst.size());
    }

    inline void bytes_from_hex(uint8_vector &data, const std::string_view& hex)
    {
        data = uint8_vector::from_hex(hex);
    }

    inline uint8_vector bytes_from_hex(const std::string_view& hex)
    {
        return uint8_vector::from_hex(hex);
    }

    template<class ForwardIt, class T, class Compare>
    ForwardIt binary_search(ForwardIt first, ForwardIt last, const T& value, Compare cmp)
    {
        ForwardIt i = std::lower_bound(first, last, value, cmp);
        if (i != last && !cmp(value, *i))
            return i;
        else
            return last;
    }
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::buffer>: formatter<std::span<const uint8_t>> {
    };

    template<>
    struct formatter<daedalus_turbo::uint8_vector>: formatter<std::span<const uint8_t>> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", v.span());
        }
    };

    template<>
    struct formatter<daedalus_turbo::buffer_readable>: formatter<daedalus_turbo::buffer> {
        template<typename FormatContext>
        auto format(const auto &bytes, FormatContext &ctx) const -> decltype(ctx.out()) {
            bool readable = true;
            bool has_space = false;
            for (const uint8_t *p = bytes.data(), *end = bytes.data() + bytes.size(); p < end; ++p) {
                if (*p == 0x20) has_space = true;
                if (*p < 0x20 || *p >= 0x7F) readable = false;
            }
            if (readable) {
                if (has_space) return fmt::format_to(ctx.out(), "'{}'", std::string_view { reinterpret_cast<const char *>(bytes.data()), bytes.size() });
                else return fmt::format_to(ctx.out(), "{}", std::string_view { reinterpret_cast<const char *>(bytes.data()), bytes.size() });
            } else {
                return fmt::format_to(ctx.out(), "{}", bytes.span());
            }
        }
    };
}

#endif // !DAEDALUS_TURBO_UTIL_HPP