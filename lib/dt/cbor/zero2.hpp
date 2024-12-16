/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

/*
 * This is a zero-copy one-pass CBOR parser. It has a very small memory overhead and
 * ensures that nested data structures are accessed only once.
 * It was primarily developed for comparison of multi-gigabyte CBOR files in tight-on-RAM environments.
 * Furthermore, the low memory overhead, makes it well suited for parallel processing of CBOR data.
 *
 * The code is defined in a single header to benefit from maximum inlining for performance.
 */
#ifndef DAEDALUS_TURBO_CBOR_ZERO2_HPP
#define DAEDALUS_TURBO_CBOR_ZERO2_HPP

#include <variant>
#include <dt/big_int.hpp>
#include <dt/cbor/types.hpp>
#include <dt/narrow-cast.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::cbor::zero2 {
    template<typename T, typename Y>
    T &get_nice(Y &v, const std::source_location &loc=std::source_location::current())
    {
        if (!std::holds_alternative<T>(v)) [[unlikely]] {
            std::visit([&](auto &vo) {
                throw error(loc, "expected type {} but got {}", typeid(T).name(), typeid(vo).name());
            }, v);
        }
        return std::get<T>(v);
    }

    typedef daedalus_turbo::error error;
    using major_type = cbor::major_type;
    using special_val = cbor::special_val;

    struct value;

    struct decoder {
        decoder(const buffer data): _ptr { data.data() }, _end { data.data() + data.size() }
        {
        }

        bool done() const noexcept
        {
            return _ptr >= _end;
        }

        void step(value &);
        value read();
        const uint8_t *pos() const noexcept;
    protected:
        friend value;

        const uint8_t *_ptr;
        const uint8_t *_end;

        void _step(const ptrdiff_t num_bytes)
        {
            _ptr += num_bytes;
        }

        void _done()
        {
            _end = _ptr;
        }

        uint8_t _next_byte() const
        {
            if (_ptr >= _end) [[unlikely]]
                throw error("_next_byte is not available for completed decoders");
            return *_ptr;
        }
    };
    static_assert(sizeof(decoder) == 16);

    struct value {
        struct chunked_reader {
            chunked_reader(chunked_reader &&) =delete;
            chunked_reader(const chunked_reader &) =delete;

            chunked_reader(value &parent):
                _parent(parent)
            {
            }

            template<typename T>
            void consume(T *res=nullptr)
            {
                if (res)
                    res->clear();
                for (size_t i = 0; i < 1024; ++i) {
                    auto chunk = _parent.get()._dec.read();
                    if (chunk.type_byte() == 0xFF) {
                        _parent.get()._dec.step(chunk);
                        _parent.get()._dec._done();
                        return;
                    }
                    if (res) {
                        const auto bytes = chunk.data_special();
                        res->insert(res->end(), bytes.begin(), bytes.end());
                    }
                }
                throw error("CBOR chunked values may not have more than 1024 chunks!");
            }
        private:
            friend value;

            std::reference_wrapper<value> _parent;
        };
        static_assert(sizeof(chunked_reader) == 8);

        struct tag_reader {
            tag_reader(tag_reader &&) =delete;
            tag_reader(const tag_reader &) =delete;

            tag_reader(value &parent):
                _parent(parent),
                _begin_ptr(_parent.get()._dec.pos())
            {
            }

            void consume()
            {
                if (_parent.get()._dec.pos() == _begin_ptr) {
                    auto v = read();
                    _parent.get()._dec.step(v);
                }
                _parent.get()._dec._done();
            }

            uint64_t id() const noexcept
            {
                return _parent.get().special_uint();
            }

            value read()
            {
                return _parent.get()._dec.read();
            }
        private:
            friend value;

            std::reference_wrapper<value> _parent;
            const uint8_t *_begin_ptr;
        };
        static_assert(sizeof(tag_reader) == 16);

        struct array_reader {
            array_reader(array_reader &&) =delete;
            array_reader(const array_reader &) =delete;

            array_reader(value &parent):
                _parent { parent }
            {
            }

            // a virtual destructor is not needed since values are stores as direct class instances

            virtual bool done()
            {
                if (!_parent.get()._dec.done()) {
                    if (_parent.get()._dec._next_byte() != 0xFF)
                        return false;
                    _parent.get()._dec._step(1);
                    _parent.get()._dec._done();
                }
                return true;
            }

            virtual value read()
            {
                return _parent.get()._dec.read();
            }

            void skip(const size_t num_items)
            {
                for (size_t i = 0; i < num_items; ++i) {
                    read();
                }
            }

            void consume()
            {
                while (!done()) {
                    read();
                }
            }
        private:
            friend value;

            std::reference_wrapper<value> _parent;
        };
        static_assert(sizeof(array_reader) == 16);

        struct array_reader_sized: array_reader {
            using array_reader::array_reader;

            bool done() override
            {
                if (_pos < _parent.get().special_uint())
                    return false;
                _parent.get()._dec._done();
                return true;
            }

            value read() override
            {
                ++_pos;
                return _parent.get()._dec.read();
            }
        private:
            size_t _pos = 0;
        };
        static_assert(sizeof(array_reader_sized) == 24);

        struct map_reader {
            map_reader(map_reader &&) =delete;
            map_reader(const map_reader &) =delete;

            map_reader(value &parent):
                _parent { parent }
            {
            }

            // a virtual destructor is not needed since values are stores as direct class instances

            virtual bool done()
            {
                if (!_parent.get()._dec.done()) {
                    if (_parent.get()._dec._next_byte() != 0xFF)
                        return false;
                    _parent.get()._dec._step(1);
                    _parent.get()._dec._done();
                }
                return true;
            }

            value read_key()
            {
                return _parent.get()._dec.read();
            }

            virtual value read_val(value &key)
            {
                _parent.get()._dec.step(key);
                return _parent.get()._dec.read();
            }

            void consume()
            {
                while (!done()) {
                    auto k = read_key();
                    auto v = read_val(k);
                }
            }

            void skip(const size_t num_items)
            {
                for (size_t i = 0; i < num_items; ++i) {
                    auto k = read_key();
                    auto v = read_val(k);
                }
            }
        private:
            friend value;

            std::reference_wrapper<value> _parent;
        };
        static_assert(sizeof(map_reader) == 16);

        struct map_reader_sized: map_reader {
            using map_reader::map_reader;

            bool done() override
            {
                if (_pos < _parent.get().special_uint())
                    return false;
                _parent.get()._dec._done();
                return true;
            }

            value read_val(value &k) override
            {
                ++_pos;
                _parent.get()._dec.step(k);
                return _parent.get()._dec.read();
            }
        private:
            size_t _pos = 0;
        };
        static_assert(sizeof(map_reader_sized) == 24);

        static cpp_int _raw_big_int_from_value(value &v)
        {
            if (!v.indefinite()) [[likely]]
                return big_int_from_bytes(v.bytes());
            uint8_vector bytes {};
            v.to_bytes(bytes);
            return big_int_from_bytes(bytes);
        }

        value(value &&) =delete;
        value(const value &o) =delete;

        explicit value(const buffer data): value { data, nullptr }
        {
        }

        ~value()
        {
            if (_parent)
                _parent->step(*this);
        }

        value clone() const
        {
            return value { data_raw(), nullptr };
        }

        cpp_int bigint() const;

        uint64_t uint() const
        {
            if ((type() == major_type::uint) + (type() == major_type::nint)) [[likely]]
                return _spec_uint;
            throw error(fmt::format("expected an uint but have {}", type()));
        }

        buffer bytes() const
        {
            if (type() == major_type::bytes) [[likely]] {
                if (special() != special_val::s_break) [[likely]]
                    return data_special();
                throw error("bytes method does not support chunked byte strings, use bytes_alloc instead!");
            }
            throw error(fmt::format("expected a byte string but got {}", type()));
        }

        template<typename T>
        void to_bytes(T &res) const
        {
            if (type() != major_type::bytes) [[unlikely]]
                throw error(fmt::format("expected a byte string but got {}", type()));
            if (special() != special_val::s_break) [[likely]]{
                res = data_special();
            } else {
                get_nice<chunked_reader>(_reader).consume(&res);
            }
        }

        std::string_view text() const
        {
            if (type() == major_type::text) [[likely]] {
                if (special() != special_val::s_break) [[likely]]
                    return data_special().string_view();
                throw error("text method does not support chunked strings use text_alloc instead!");
            }
            throw error(fmt::format("expected a text string but got {}", type()));
        }

        template<typename T>
        void to_text(T &res) const
        {
            if (type() != major_type::text) [[unlikely]]
                throw error(fmt::format("expected a byte string but got {}", type()));
            if (special() != special_val::s_break) [[likely]]{
                res = data_special().string_view();
            } else {
                get_nice<chunked_reader>(_reader).consume(&res);
            }
        }

        array_reader &array() const
        {
            if (indefinite())
                return get_nice<array_reader>(_reader);
            return get_nice<array_reader_sized>(_reader);
        }

        map_reader &map() const
        {
            if (indefinite())
                return get_nice<map_reader>(_reader);
            return get_nice<map_reader_sized>(_reader);
        }

        float float32() const
        {
            if (*_data == 0xFA) [[likely]]
                return data_raw().subbuf(1, 4).to_host<float>();
            throw error(fmt::format("expected a float32 but have {} {}", type(), special()));
        }

        tag_reader &tag() const
        {
            return get_nice<tag_reader>(_reader);
        }

        special_val simple() const
        {
            if (type() == major_type::simple) [[likely]]
                return special();
            throw error(fmt::format("expected a simple value but got {}", type()));
        }

        uint8_t type_byte() const
        {
            return *_data;
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
            return data_raw() == o.data_raw();
        }

        bool operator<(const value &o) const
        {
            return data_raw() < o.data_raw();
        }

        buffer data_raw() const
        {
            return { _data, static_cast<size_t>(_dec._end - _data) };
        }

        buffer data_special() const
        {
            const auto *special_ptr = _data + special_bytes(special());
            return buffer { special_ptr, static_cast<size_t>(_dec._end - special_ptr) };
        }

        uint64_t special_uint() const noexcept
        {
            return _spec_uint;
        }

        std::string stringify(size_t max_seq_to_expand=0) const;
    protected:
        friend decoder;
        friend array_reader;
        friend map_reader;
        friend tag_reader;
        friend chunked_reader;

        decoder _dec;

        explicit value(const buffer data, decoder *parent):
            _dec { data },
            _data { data.data() },
            _parent { parent }
        {
            if (data.empty()) [[unlikely]]
                throw error("cbor value data must contain at least one byte!");
            switch (_data[0]) {
                case 0x00:
                case 0x01:
                case 0x02:
                case 0x03:
                case 0x04:
                case 0x05:
                case 0x06:
                case 0x07:
                case 0x08:
                case 0x09:
                case 0x0A:
                case 0x0B:
                case 0x0C:
                case 0x0D:
                case 0x0E:
                case 0x0F:
                case 0x10:
                case 0x11:
                case 0x12:
                case 0x13:
                case 0x14:
                case 0x15:
                case 0x16:
                case 0x17:
                    _spec_uint = _data[0];
                    _dec._step(1);
                    _dec._done();
                    break;
                case 0x18:
                    _spec_uint = data.subbuf(1, 1).to_host<uint8_t>();
                    _dec._step(2);
                    _dec._done();
                    break;
                case 0x19:
                    _spec_uint = data.subbuf(1, 2).to_host<uint16_t>();
                    _dec._step(3);
                    _dec._done();
                    break;
                case 0x1A:
                    _spec_uint = data.subbuf(1, 4).to_host<uint32_t>();
                    _dec._step(5);
                    _dec._done();
                    break;
                case 0x1B:
                    _spec_uint = data.subbuf(1, 8).to_host<uint64_t>();
                    _dec._step(9);
                    _dec._done();
                    break;
                case 0x20:
                case 0x21:
                case 0x22:
                case 0x23:
                case 0x24:
                case 0x25:
                case 0x26:
                case 0x27:
                case 0x28:
                case 0x29:
                case 0x2A:
                case 0x2B:
                case 0x2C:
                case 0x2D:
                case 0x2E:
                case 0x2F:
                case 0x30:
                case 0x31:
                case 0x32:
                case 0x33:
                case 0x34:
                case 0x35:
                case 0x36:
                case 0x37:
                    _spec_uint = _data[0] & 0x1F;
                    _dec._step(1);
                    _dec._done();
                    break;
                case 0x38:
                    _spec_uint = data.subbuf(1, 1).to_host<uint8_t>();
                    _dec._step(2);
                    _dec._done();
                    break;
                case 0x39:
                    _spec_uint = data.subbuf(1, 2).to_host<uint16_t>();
                    _dec._step(3);
                    _dec._done();
                    break;
                case 0x3A:
                    _spec_uint = data.subbuf(1, 4).to_host<uint32_t>();
                    _dec._step(5);
                    _dec._done();
                    break;
                case 0x3B:
                    _spec_uint = data.subbuf(1, 8).to_host<uint64_t>();
                    _dec._step(9);
                    _dec._done();
                    break;
                case 0x40:
                case 0x41:
                case 0x42:
                case 0x43:
                case 0x44:
                case 0x45:
                case 0x46:
                case 0x47:
                case 0x48:
                case 0x49:
                case 0x4A:
                case 0x4B:
                case 0x4C:
                case 0x4D:
                case 0x4E:
                case 0x4F:
                case 0x50:
                case 0x51:
                case 0x52:
                case 0x53:
                case 0x54:
                case 0x55:
                case 0x56:
                case 0x57:
                    _spec_uint = _data[0] & 0x1F;
                    _dec._step(1 + _spec_uint);
                    _dec._done();
                    break;
                case 0x58:
                    _spec_uint = data.subbuf(1, 1).to_host<uint8_t>();
                    _dec._step(2 + _spec_uint);
                    _dec._done();
                    break;
                case 0x59:
                    _spec_uint = data.subbuf(1, 2).to_host<uint16_t>();
                    _dec._step(3 + _spec_uint);
                    _dec._done();
                    break;
                case 0x5A:
                    _spec_uint = data.subbuf(1, 4).to_host<uint32_t>();
                    _dec._step(5 + _spec_uint);
                    _dec._done();
                    break;
                case 0x5B:
                    _spec_uint = data.subbuf(1, 8).to_host<uint64_t>();
                    _dec._step(9 + _spec_uint);
                    _dec._done();
                    break;
                case 0x5F:
                    _dec._step(1);
                    _reader.emplace<chunked_reader>(*this);
                    break;
                case 0x60:
                case 0x61:
                case 0x62:
                case 0x63:
                case 0x64:
                case 0x65:
                case 0x66:
                case 0x67:
                case 0x68:
                case 0x69:
                case 0x6A:
                case 0x6B:
                case 0x6C:
                case 0x6D:
                case 0x6E:
                case 0x6F:
                case 0x70:
                case 0x71:
                case 0x72:
                case 0x73:
                case 0x74:
                case 0x75:
                case 0x76:
                case 0x77:
                    _spec_uint = _data[0] & 0x1F;
                    _dec._step(1 + _spec_uint);
                    _dec._done();
                    break;
                case 0x78:
                    _spec_uint = data.subbuf(1, 1).to_host<uint8_t>();
                    _dec._step(2 + _spec_uint);
                    _dec._done();
                    break;
                case 0x79:
                    _spec_uint = data.subbuf(1, 2).to_host<uint16_t>();
                    _dec._step(3 + _spec_uint);
                    _dec._done();
                    break;
                case 0x7A:
                    _spec_uint = data.subbuf(1, 4).to_host<uint32_t>();
                    _dec._step(5 + _spec_uint);
                    _dec._done();
                    break;
                case 0x7B:
                    _spec_uint = data.subbuf(1, 8).to_host<uint64_t>();
                    _dec._step(9 + _spec_uint);
                    _dec._done();
                    break;
                case 0x7F:
                    _dec._step(1);
                    _reader.emplace<chunked_reader>(*this);
                    break;
                case 0x80:
                case 0x81:
                case 0x82:
                case 0x83:
                case 0x84:
                case 0x85:
                case 0x86:
                case 0x87:
                case 0x88:
                case 0x89:
                case 0x8A:
                case 0x8B:
                case 0x8C:
                case 0x8D:
                case 0x8E:
                case 0x8F:
                case 0x90:
                case 0x91:
                case 0x92:
                case 0x93:
                case 0x94:
                case 0x95:
                case 0x96:
                case 0x97:
                    _spec_uint = _data[0] & 0x1F;
                    _dec._step(1);
                    _reader.emplace<array_reader_sized>(*this);
                    break;
                case 0x98:
                    _spec_uint = data.subbuf(1, 1).to_host<uint8_t>();
                    _dec._step(2);
                    _reader.emplace<array_reader_sized>(*this);
                    break;
                case 0x99:
                    _spec_uint = data.subbuf(1, 2).to_host<uint16_t>();
                    _dec._step(3);
                    _reader.emplace<array_reader_sized>(*this);
                    break;
                case 0x9A:
                    _spec_uint = data.subbuf(1, 4).to_host<uint32_t>();
                    _dec._step(5);
                    _reader.emplace<array_reader_sized>(*this);
                    break;
                case 0x9B:
                    _spec_uint = data.subbuf(1, 8).to_host<uint64_t>();
                    _dec._step(9);
                    _reader.emplace<array_reader_sized>(*this);
                    break;
                case 0x9F:
                    _dec._step(1);
                    _reader.emplace<array_reader>(*this);
                    break;
                case 0xA0:
                case 0xA1:
                case 0xA2:
                case 0xA3:
                case 0xA4:
                case 0xA5:
                case 0xA6:
                case 0xA7:
                case 0xA8:
                case 0xA9:
                case 0xAA:
                case 0xAB:
                case 0xAC:
                case 0xAD:
                case 0xAE:
                case 0xAF:
                case 0xB0:
                case 0xB1:
                case 0xB2:
                case 0xB3:
                case 0xB4:
                case 0xB5:
                case 0xB6:
                case 0xB7:
                    _spec_uint = _data[0] & 0x1F;
                    _dec._step(1);
                    _reader.emplace<map_reader_sized>(*this);
                    break;
                case 0xB8:
                    _spec_uint = data.subbuf(1, 1).to_host<uint8_t>();
                    _dec._step(2);
                    _reader.emplace<map_reader_sized>(*this);
                    break;
                case 0xB9:
                    _spec_uint = data.subbuf(1, 2).to_host<uint16_t>();
                    _dec._step(3);
                    _reader.emplace<map_reader_sized>(*this);
                    break;
                case 0xBA:
                    _spec_uint = data.subbuf(1, 4).to_host<uint32_t>();
                    _dec._step(5);
                    _reader.emplace<map_reader_sized>(*this);
                    break;
                case 0xBB:
                    _spec_uint = data.subbuf(1, 8).to_host<uint64_t>();
                    _dec._step(9);
                    _reader.emplace<map_reader_sized>(*this);
                    break;
                case 0xBF:
                    _dec._step(1);
                    _reader.emplace<map_reader>(*this);
                    break;
                case 0xC0:
                case 0xC1:
                case 0xC2:
                case 0xC3:
                case 0xC4:
                case 0xC5:
                case 0xC6:
                case 0xC7:
                case 0xC8:
                case 0xC9:
                case 0xCA:
                case 0xCB:
                case 0xCC:
                case 0xCD:
                case 0xCE:
                case 0xCF:
                case 0xD0:
                case 0xD1:
                case 0xD2:
                case 0xD3:
                case 0xD4:
                case 0xD5:
                case 0xD6:
                case 0xD7:
                    _spec_uint = _data[0] & 0x1F;
                    _dec._step(1);
                    _reader.emplace<tag_reader>(*this);
                    break;
                case 0xD8:
                    _spec_uint = data.subbuf(1, 1).to_host<uint8_t>();
                    _dec._step(2);
                    _reader.emplace<tag_reader>(*this);
                    break;
                case 0xD9:
                    _spec_uint = data.subbuf(1, 2).to_host<uint16_t>();
                    _dec._step(3);
                    _reader.emplace<tag_reader>(*this);
                    break;
                case 0xDA:
                    _spec_uint = data.subbuf(1, 4).to_host<uint32_t>();
                    _dec._step(5);
                    _reader.emplace<tag_reader>(*this);
                    break;
                case 0xDB:
                    _spec_uint = data.subbuf(1, 8).to_host<uint64_t>();
                    _dec._step(9);
                    _reader.emplace<tag_reader>(*this);
                    break;
                case 0xE0:
                case 0xE1:
                case 0xE2:
                case 0xE3:
                case 0xE4:
                case 0xE5:
                case 0xE6:
                case 0xE7:
                case 0xE8:
                case 0xE9:
                case 0xEA:
                case 0xEB:
                case 0xEC:
                case 0xED:
                case 0xEE:
                case 0xEF:
                case 0xF0:
                case 0xF1:
                case 0xF2:
                case 0xF3:
                case 0xF4:
                case 0xF5:
                case 0xF6:
                case 0xF7:
                    _dec._step(1);
                    break;
                case 0xF8:
                    _dec._step(2);
                    break;
                case 0xF9:
                    _dec._step(3);
                    break;
                case 0xFA:
                    _dec._step(5);
                    break;
                case 0xFB:
                    _dec._step(9);
                    break;
                case 0xFF:
                    _dec._step(1);
                    break;
                default:
                    throw error(fmt::format("an unsupported first byte of a CBOR value: #{:02X}!", _data[0]));
            }
        }

        const uint8_t *end()
        {
            if (!_dec.done()) {
                std::visit([&](auto &&r) {
                    using T = std::decay_t<decltype(r)>;
                    if constexpr (std::is_same_v<T, chunked_reader>) {
                        uint8_vector *res = nullptr;
                        r.consume(res);
                    } else if constexpr (!std::is_same_v<T, std::monostate>) {
                        r.consume();
                    }
                }, _reader);
            }
            return _dec._ptr;
        }
    private:
        using reader_type = std::variant<std::monostate, array_reader, array_reader_sized,
            map_reader, map_reader_sized, tag_reader, chunked_reader>;

        const uint8_t *_data;
        uint64_t _spec_uint;
        mutable reader_type _reader { std::monostate {} };

        static size_t special_bytes(const special_val sv)
        {
            switch (sv) {
                case special_val::one_byte: return 2;
                case special_val::two_bytes: return 3;
                case special_val::four_bytes: return 5;
                case special_val::eight_bytes: return 9;
                default: return 1;
            }
        }
    protected:
        decoder *_parent; // keep it the last since it is referenced in the last
    };
    static_assert(sizeof(value) == 72); // Ensure each value fits into a single cache line

    inline cpp_int value::bigint() const
    {
        switch (type()) {
            case major_type::uint: return cpp_int { uint() };
            case major_type::nint: return (cpp_int { uint() } + 1) * -1;
            case major_type::tag: {
                auto &t = tag();
                switch (const auto id = t.id(); id) {
                    case 2: {
                        auto v = t.read();
                        return _raw_big_int_from_value(v);
                    }
                    case 3: {
                        auto v = t.read();
                        return (_raw_big_int_from_value(v) + 1) * -1;
                    }
                    default: throw error(fmt::format("unsupported tag type for a bigint: {}!", id));
                }
            }
            default: throw error(fmt::format("cannot interpret cbor value as a bigint: {}", stringify()));
        }
    }

    inline const uint8_t *decoder::pos() const noexcept
    {
        return _ptr;
    }

    inline value decoder::read()
    {
        return value { buffer { _ptr, static_cast<size_t>(_end - _ptr) }, this };
    }

    inline void decoder::step(value &v)
    {
        if (v._parent == this) {
            v._parent = nullptr;
            _ptr = v.end();
        }
    }

    inline std::back_insert_iterator<std::string> my_stringify(std::back_insert_iterator<std::string> out_it, const value &v, const size_t depth, const size_t max_seq_to_expand)
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
                    v.to_bytes(*storage);
                    b = *storage;
                }
                if (cbor::is_ascii(b))
                    return fmt::format_to(out_it, "B {}#{} ('{}')", v.indefinite() ? "indefinite " : "", b, b.string_view());
                return fmt::format_to(out_it, "B {}#{}", v.indefinite() ? "indefinite " : "", b);
            }
            case major_type::text: {
                std::optional<std::string> storage {};
                std::string_view s;
                if (!v.indefinite()) [[likely]] {
                    s = v.text();
                } else {
                    storage.emplace();
                    v.to_text(*storage);
                    s = *storage;
                }
                return fmt::format_to(out_it, "T {}'{}'", v.indefinite() ? "indefinite " : "", s);
            }
            case major_type::array: {
                auto &it = v.array();
                if (v.indefinite())
                    out_it = fmt::format_to(out_it, "[(items: indefinite)");
                else
                    out_it = fmt::format_to(out_it, "[(items: {})", v.special_uint());
                if (v.indefinite() || (v.special_uint() > 0 && (max_seq_to_expand == 0 || v.special_uint() <= max_seq_to_expand))) {
                    out_it = fmt::format_to(out_it, "\n");
                    for (size_t i = 0; !it.done(); ++i) {
                        out_it = fmt::format_to(out_it, "{:{}}    #{}: ", "", depth * 4, i);
                        auto av = it.read();
                        out_it = my_stringify(out_it, av, depth + 1, max_seq_to_expand);
                        out_it = fmt::format_to(out_it, "\n");
                    }
                    out_it = fmt::format_to(out_it, "{:{}}", "", depth * 4);
                }
                return fmt::format_to(out_it, "]");
            }
            case major_type::map: {
                auto &it = v.map();
                if (v.indefinite())
                    out_it = fmt::format_to(out_it, "{{(items: indefinite)");
                else
                    out_it = fmt::format_to(out_it, "{{(items: {})", v.special_uint());
                if (v.indefinite() || (v.special_uint() > 0 && (max_seq_to_expand == 0 || v.special_uint() <= max_seq_to_expand))) {
                    out_it = fmt::format_to(out_it, "\n");
                    while (!it.done()) {
                        out_it = fmt::format_to(out_it, "{:{}}    ", "", depth * 4);
                        auto key = it.read_key();
                        out_it = my_stringify(out_it, key, depth + 1, max_seq_to_expand);
                        out_it = fmt::format_to(out_it, ": ");
                        auto val = it.read_val(key);
                        out_it = my_stringify(out_it, val, depth + 1, max_seq_to_expand);
                        out_it = fmt::format_to(out_it, "\n");
                    }
                    out_it = fmt::format_to(out_it, "{:{}}", "", depth * 4);
                }
                return fmt::format_to(out_it, "}}");
            }
            case major_type::tag: {
                auto &t = v.tag();
                out_it = fmt::format_to(out_it, "TAG {} ", t.id());
                out_it = my_stringify(out_it, t.read(), depth, max_seq_to_expand);
                return out_it;
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

    inline value extract(const value &v, const std::span<const size_t> path, const size_t idx=0)
    {
        if (idx < path.size()) [[likely]] {
            auto &it = v.array();
            it.skip(path[idx]);
            auto next_v = it.read();
            return extract(next_v, path, idx + 1);
        }
        return v.clone();
    }

    inline value parse(const buffer data)
    {
        return value { data };
    }
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::cbor::zero2::value>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", v.stringify());
        }
    };
}

#endif // !DAEDALUS_TURBO_CBOR_ZERO2_HPP