/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

/*
 * This is a zero-copy CBOR parser. It has a very small memory overhead.
 * However, it's random access performance is poor since to save memory it recomputes things.
 * It was primarily developed for comparison of multi-gigabyte CBOR files in tight-on-RAM environments.
 * Furthermore, the low memory overhead, makes it well suited for parallel processing of CBOR data.
 *
 * The code is defined in a single header to benefit from maximum inlining for performance.
 */
#ifndef DAEDALUS_TURBO_CBOR_TURBO_HPP
#define DAEDALUS_TURBO_CBOR_TURBO_HPP

#include <dt/big_int.hpp>
#include <dt/cbor/types.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::cbor::zero {
    typedef daedalus_turbo::error error;
    using major_type = cbor::major_type;
    using special_val = cbor::special_val;

    struct value;

    struct decoder {
        decoder(const buffer data): _ptr { data.data() }, _end { data.data() + data.size() }
        {
        }

        decoder(const decoder &o): _ptr { o._ptr }, _end { o._end }
        {
        }

        bool done() const noexcept
        {
            return _ptr >= _end;
        }

        value read();
    protected:
        friend value;

        const uint8_t *_ptr;
        const uint8_t *_end;

        void _advance(size_t num_bytes);
        void _read_bytes(value &v);
        void _read_array(value &v);
        void _read_map(value &v);
        void _read_tag(value &v);
    };
    static_assert(sizeof(decoder) == 16);

    struct value {
        using array_observer = std::function<bool(const value &item, size_t idx)>;
        using map_observer = std::function<bool(const value &key, const value &val, size_t idx)>;
        using map_item = std::pair<value, value>;
        using tag_item = std::pair<uint64_t, value>;

        struct array_iterator {
            array_iterator(const value v): _dec { v.raw_span().subbuf(v.special_bytes()) }, _size { static_cast<uint32_t>(v.size()) }
            {
            }

            array_iterator(const array_iterator &o): _dec { o._dec }, _pos { o._pos }, _size { o._size }
            {
            }

            array_iterator &skip(const size_t num_items)
            {
                for (size_t i = 0; i < num_items; ++i)
                    next();
                return *this;
            }

            value next()
            {
                if (++_pos <= _size) [[likely]]
                    return _dec.read();
                throw error("iteration past the end of the array!");
            }

            bool done() const noexcept
            {
                return _pos >= _size;
            }

            size_t size() const noexcept
            {
                return _size;
            }
        private:
            decoder _dec;
            uint32_t _pos = 0;
            uint32_t _size;
        };

        struct map_iterator {
            map_iterator(const value v): _dec { v.raw_span().subbuf(v.special_bytes()) }, _size { static_cast<uint32_t>(v.size()) }
            {
            }

            map_iterator &skip(const size_t num_items)
            {
                for (size_t i = 0; i < num_items; ++i)
                    next();
                return *this;
            }

            map_item next()
            {
                if (++_pos <= _size) [[likely]] {
                    auto key = _dec.read();
                    auto val = _dec.read();
                    return { key, val };
                }
                throw error("iteration past the end of the array!");
            }

            bool done() const noexcept
            {
                return _pos >= _size;
            }

            size_t size() const noexcept
            {
                return _size;
            }
        private:
            decoder _dec;
            uint32_t _pos = 0;
            uint32_t _size;
        };

        static cpp_int _raw_big_int_from_value(value v)
        {
            if (!v.indefinite()) [[likely]]
                return big_int_from_bytes(v.bytes());
            uint8_vector bytes {};
            v.bytes_alloc(bytes);
            return big_int_from_bytes(bytes);
        }

        cpp_int big_int() const
        {
            switch (type()) {
                case major_type::uint: return cpp_int { uint() };
                case major_type::nint: return (cpp_int { uint() } + 1) * -1;
                case major_type::tag: {
                    const auto t = tag();
                    switch (t.first) {
                        case 2: return _raw_big_int_from_value(t.second);
                        case 3: return (_raw_big_int_from_value(t.second) + 1) * -1;
                        default: throw error(fmt::format("unsupported tag type for a bigint: {}!", t.first));
                    }
                }
                default: throw error(fmt::format("cannot interpret cbor value as a bigint: {}", stringify()));
            }
        }

        uint64_t uint() const
        {
            if (type() == major_type::uint || type() == major_type::nint) [[likely]]
                return special_uint();
            throw error(fmt::format("expected an uint but have {}", type()));
        }

        buffer bytes() const
        {
            if (type() == major_type::bytes) [[likely]] {
                if (special() != special_val::s_break) [[likely]]
                    return _subbuf(special_bytes());
                throw error("bytes method does not support indefinite byte strings, use bytes_alloc instead!");
            }
            throw error(fmt::format("expected a byte string but got {}", type()));
        }

        template<typename T>
        T &bytes_alloc(T &res) const
        {
            if (type() == major_type::bytes) [[likely]] {
                if (special() != special_val::s_break) [[likely]] {
                    res = _subbuf(special_bytes());
                    return res;
                }
                decoder dec { raw_span().subbuf(1) };
                for (size_t i = 0; i < 1024; ++i) {
                    const auto chunk = dec.read();
                    if (chunk.type() == major_type::simple && chunk.special() == special_val::s_break)
                        return res;
                    res << chunk.bytes();
                }
                throw error("indefinite byte strings of more than 1024 chunks are not supported!");
            }
            throw error(fmt::format("expected a byte string but got {}", type()));
        }

        std::string_view text() const
        {
            if (type() == major_type::text) [[likely]] {
                if (special() != special_val::s_break) [[likely]]
                    return _subbuf(special_bytes()).string_view();
                throw error("text method does not support indefinite byte strings use text_alloc instead!");
            }
            throw error(fmt::format("expected a text string but got {}", type()));
        }

        array_iterator array() const
        {
            if (type() == major_type::array) [[likely]]
                return { *this };
            throw error(fmt::format("expected an array but got {}", type()));
        }

        map_iterator map() const
        {
            if (type() == major_type::map) [[likely]]
                return { *this };
            throw error(fmt::format("expected a map but got {}", type()));
        }

        float float32() const
        {
            if (type() == major_type::simple || special() == special_val::four_bytes) [[likely]]
                return _subbuf(1, 4).to_host<float>();
            throw error(fmt::format("expected a float32 but have {} {}", type(), special()));
        }

        tag_item tag() const
        {
            if (type() == major_type::tag) [[likely]] {
                const auto id = special_uint();
                return { id, decoder { _subbuf(special_bytes()) }.read() };
            }
            throw error(fmt::format("expected a tag but got {}", type()));
        }

        special_val simple() const
        {
            if (type() == major_type::simple) [[likely]]
                return special();
            throw error(fmt::format("expected a simple value but got {}", type()));
        }

        value at(const size_t idx) const
        {
            return array().skip(idx).next();
        }

        major_type type() const noexcept
        {
            return static_cast<major_type>((_data[0] >> 5) & 0x7);
        }

        special_val special() const noexcept
        {
            return static_cast<special_val>(_data[0] & 0x1F);
        }

        bool indefinite() const
        {
            switch (type()) {
                case major_type::bytes:
                case major_type::text:
                case major_type::array:
                case major_type::map:
                    return special() == special_val::s_break;
                default:
                    throw error(fmt::format("indefinite is supported only for bytes, text, array, and map but got {}", type()));
            }
        }

        bool operator==(const value &o) const
        {
            return raw_span() == o.raw_span();
        }

        bool operator<(const value &o) const
        {
            return raw_span() < o.raw_span();
        }

        size_t size() const
        {
            const auto typ = type();
            if (typ == major_type::array || typ == major_type::map) [[likely]]
                return special_uint();
            throw error(fmt::format("the number of items is available only in array and maps but got {}", type()));
        }

        buffer raw_span() const
        {
            return { _data, _size };
        }

        size_t special_bytes() const
        {
            return _spec_bytes;
        }

        uint64_t special_uint() const
        {
            return _spec_uint;
        }

        std::string stringify(size_t max_seq_to_expand=0) const;
    protected:
        friend decoder;

        explicit value(const buffer data): _data { _check_data(data) }
        {
            switch (const auto sv = special(); sv) {
                case special_val::one_byte:
                    _spec_bytes = 2;
                    _spec_uint = data.subbuf(1, 1).to_host<uint8_t>();
                    break;
                case special_val::two_bytes:
                    _spec_bytes = 3;
                    _spec_uint = data.subbuf(1, 2).to_host<uint16_t>();
                    break;
                case special_val::four_bytes:
                    _spec_bytes = 5;
                    _spec_uint = data.subbuf(1, 4).to_host<uint32_t>();
                    break;
                case special_val::eight_bytes:
                    _spec_bytes = 9;
                    _spec_uint = data.subbuf(1, 8).to_host<uint64_t>();
                    break;
                default:
                    _spec_bytes = 1;
                    _spec_uint = static_cast<uint64_t>(sv);
                    break;
            }
            _size = _spec_bytes;
        }

        buffer _subbuf(const size_t pos, const size_t sz) const
        {
            return buffer { _data, _size }.subbuf(pos, sz);
        }

        buffer _subbuf(const size_t pos) const
        {
            return buffer { _data, _size }.subbuf(pos);
        }
    private:
        const uint8_t *_data;
        uint64_t _size: 60;
        uint64_t _spec_bytes: 4;
        uint64_t _spec_uint;

        static const uint8_t *_check_data(const buffer data)
        {
            if (!data.empty()) [[likely]]
                return data.data();
            throw error("cbor value data must contain at least one byte!");
        }

    };
    static_assert(sizeof(value) == 24);

    inline value decoder::read()
    {
        value v { buffer { _ptr, static_cast<size_t>(_end - _ptr) } };
        _advance(v.special_bytes());
        switch (v.type()) {
            case major_type::uint:
            case major_type::nint:
            case major_type::simple:
                break;
            case major_type::bytes:
            case major_type::text:
                _read_bytes(v);
                break;
            case major_type::array:
                _read_array(v);
                break;
            case major_type::map:
                _read_map(v);
                break;
            case major_type::tag:
                _read_tag(v);
                break;
            default:
                throw error(fmt::format("unsupported type {}", v.type()));
        }
        return v;
    }

    inline void decoder::_advance(const size_t num_bytes)
    {
        const auto new_ptr = _ptr + num_bytes;
        if (new_ptr < _ptr) [[unlikely]]
            throw error("a cbor item size is too large and leads to an overflow in pointer arithmetic!");
        if (new_ptr > _end) [[unlikely]]
            throw error("insufficient data to parse a CBOR value");
        _ptr = new_ptr;
    }

    inline void decoder::_read_bytes(value &v)
    {
        if (v.special() != special_val::s_break) [[likely]] {
            const auto sz = v.special_uint();
            _advance(sz);
            v._size += sz;
        } else {
            for (;;) {
                const auto chunk = read();
                v._size += chunk._size;
                if (chunk.type() == major_type::simple && chunk.special() == special_val::s_break) [[unlikely]]
                    break;
            }
        }
    }

    inline void decoder::_read_array(value &v)
    {
        if (v.special() == special_val::s_break) [[unlikely]] {
            v._spec_uint = 0;
            for (;;) {
                value item = read();
                v._size += item._size;
                if (item.type() == major_type::simple && item.special() == special_val::s_break) [[unlikely]]
                    break;
                ++v._spec_uint;
            }
        } else {
            for (auto num_items = v.special_uint(); num_items; --num_items) {
                const value item = read();
                v._size += item._size;
            }
        }
    }

    inline void decoder::_read_map(value &v)
    {
        if (v.special() == special_val::s_break) [[unlikely]] {
            v._spec_uint = 0;
            for (;;) {
                const value key = read();
                v._size += key._size;
                if (key.type() == major_type::simple && key.special() == special_val::s_break) [[unlikely]]
                    break;
                v._size += read()._size;
                ++v._spec_uint;
            }
        } else {
            for (auto num_items = v.special_uint(); num_items; --num_items) {
                v._size += read()._size;
                v._size += read()._size;
            }
        }
    }

    inline void decoder::_read_tag(value &v)
    {
        v._size += read()._size;
    }

    inline bool is_ascii(const buffer b)
    {
        for (const uint8_t *p = b.data(), *end = p + b.size(); p < end; ++p) {
            if (*p < 32 || *p > 127) [[unlikely]]
                return false;
        }
        return true;
    }

    inline std::back_insert_iterator<std::string> my_stringify(std::back_insert_iterator<std::string> out_it, const value v, const size_t depth, const size_t max_seq_to_expand)
    {
        switch (v.type()) {
            case major_type::uint: return fmt::format_to(out_it, "I {}", v.uint());
            case major_type::nint: return fmt::format_to(out_it, "I -{}", v.uint() + 1);
            case major_type::bytes: {
                std::optional<uint8_vector> storage {};
                buffer b;
                if (!v.indefinite()) [[likely]] {
                    b = v.bytes();
                } else {
                    storage.emplace();
                    v.bytes_alloc(*storage);
                    b = *storage;
                }
                if (cbor::zero::is_ascii(b))
                    return fmt::format_to(out_it, "B {}#{} ('{}')", v.indefinite() ? "indefinite " : "", b, b.string_view());
                return fmt::format_to(out_it, "B {}#{}", v.indefinite() ? "indefinite " : "", b);
            }
            case major_type::text:
                return fmt::format_to(out_it, "T {}'{}'", v.indefinite() ? "indefinite " : "", v.text());
            case major_type::array: {
                out_it = fmt::format_to(out_it, "[(items: {}{})", v.size(), v.indefinite() ? ", indefinite" : "");
                if (v.size() > 0 && (max_seq_to_expand == 0 || v.size() <= max_seq_to_expand)) {
                    auto it = v.array();
                    out_it = fmt::format_to(out_it, "\n");
                    for (size_t i = 0; i < v.size(); ++i) {
                        out_it = fmt::format_to(out_it, "{:{}}    #{}: ", "", depth * 4, i);
                        out_it = my_stringify(out_it, it.next(), depth + 1, max_seq_to_expand);
                        out_it = fmt::format_to(out_it, "\n");
                    }
                    out_it = fmt::format_to(out_it, "{:{}}", "", depth * 4);
                }
                return fmt::format_to(out_it, "]");
            }
            case major_type::map: {
                out_it = fmt::format_to(out_it, "{{(items: {}{})", v.size(), v.indefinite() ? ", indefinite" : "");
                if (v.size() > 0 && (max_seq_to_expand == 0 || v.size() <= max_seq_to_expand)) {
                    auto it = v.map();
                    out_it = fmt::format_to(out_it, "\n");
                    while (!it.done()) {
                        out_it = fmt::format_to(out_it, "{:{}}    ", "", depth * 4);
                        const auto [k, v] = it.next();
                        out_it = my_stringify(out_it, k, depth + 1, max_seq_to_expand);
                        out_it = fmt::format_to(out_it, ": ");
                        out_it = my_stringify(out_it, v, depth + 1, max_seq_to_expand);
                        out_it = fmt::format_to(out_it, "\n");
                    }
                    out_it = fmt::format_to(out_it, "{:{}}", "", depth * 4);
                }
                return fmt::format_to(out_it, "}}");
            }
            case major_type::tag: {
                const auto t = v.tag();
                out_it = fmt::format_to(out_it, "TAG {} ", t.first);
                return my_stringify(out_it, t.second, depth, max_seq_to_expand);
            }
            case major_type::simple:
                if (v.special() == special_val::four_bytes)
                    return fmt::format_to(out_it, "F32 {}", v.float32());
                return fmt::format_to(out_it, "{}", v.special());
            default:
                throw error(fmt::format("unsupported CBOR type {}", v.type()));
        }
    }

    inline std::string value::stringify(const size_t max_seq_to_expand) const
    {
        std::string res {};
        my_stringify(std::back_inserter(res), *this, 0, max_seq_to_expand);
        return res;
    }

    inline value extract(const value v, const std::span<const size_t> path, const size_t idx=0)
    {
        if (idx < path.size()) [[likely]]
            return extract(v.at(path[idx]), path, idx + 1);
        return v;
    }

    inline value parse(const buffer data)
    {
        decoder dec { data };
        return dec.read();
    }

    inline vector<value> parse_all(const buffer data)
    {
        decoder dec { data };
        vector<value> vals {};
        while (!dec.done())
            vals.emplace_back(dec.read());
        return vals;
    }
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::cbor::zero::value>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", v.stringify());
        }
    };
}

#endif // !DAEDALUS_TURBO_CBOR_TURBO_HPP