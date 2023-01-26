/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_CBOR_HPP
#define DAEDALUS_TURBO_CBOR_HPP

#include <map>
#include <stdexcept>
#include <iomanip>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "util.hpp"

namespace daedalus_turbo {

    using cbor_error = error;

    class cbor_incomplete_data_error: public cbor_error
    {
    public:
        cbor_incomplete_data_error(): cbor_error("CBOR value extends beyond the end of stream")
        {
        }
    };

    using cbor_buffer = buffer;
    struct cbor_value;

    typedef std::vector<cbor_value> cbor_array;
    typedef std::pair<cbor_value, cbor_value> cbor_map_value;
    typedef std::vector<cbor_map_value> cbor_map;

    enum cbor_value_type {
        CBOR_UINT,
        CBOR_NINT,
        CBOR_BYTES,
        CBOR_TEXT,
        CBOR_ARRAY,
        CBOR_MAP,
        CBOR_TAG,
        CBOR_SIMPLE_FALSE,
        CBOR_SIMPLE_TRUE,
        CBOR_SIMPLE_NULL,
        CBOR_SIMPLE_UNDEFINED,
        CBOR_SIMPLE_BREAK,
        CBOR_FLOAT16,
        CBOR_FLOAT32,
        CBOR_FLOAT64
    };

    typedef pair<uint64_t, unique_ptr<cbor_value>> cbor_tag;

    typedef std::variant<
            uint64_t,
            float,
            cbor_buffer,
            cbor_array,
            cbor_map,
            cbor_tag
        > cbor_value_content;

    struct cbor_value {
        const uint8_t *data;
        size_t size;
        cbor_value_type type;
        unique_ptr<uint8_vector> storage = nullptr;

        cbor_value()
        {
        }

        inline bool operator<(const cbor_value &aVal) const {
            size_t minSize = size;
            if (aVal.size < minSize) minSize = aVal.size;
            int res = memcmp(data, aVal.data, minSize);
            if (res == 0) return size < aVal.size;
            return res < 0;
        }

        inline uint64_t uint() const
        {
            return get<uint64_t>(content);
        }

        inline uint64_t nint() const
        {
            return get<uint64_t>(content) + 1;
        }

        inline float float32() const {
            return get<float>(content);
        }

        inline const cbor_buffer &buf() const
        {
            return get<cbor_buffer>(content);
        }

        inline const cbor_array &array() const
        {
            return get<cbor_array>(content);
        }

        inline const cbor_map &map() const
        {
            return get<cbor_map>(content);
        }

        inline const cbor_tag &tag() const
        {
            return get<cbor_tag>(content);
        }

        inline size_t offset(const uint8_t *base) const noexcept
        {
            return data - base;
        }

        template<typename T>
        inline void set_content(T &&val)
        {
            content = move(val);
        }

    private:

        cbor_value_content content;
    };

    class cbor_parser {
        const uint8_t *_data;
        const size_t _size;
        size_t _offset;

        void _read_unsigned_int(cbor_value &val, uint8_t augVal, const cbor_buffer &augBuf) {
            uint64_t x = 0;
            if (augBuf.size() > 0) {
                for (size_t i = 0; i < augBuf.size(); ++i) {
                    x <<= 8;
                    x |= augBuf.data()[i];
                }
            } else {
                x = augVal;
            }
            val.type = CBOR_UINT;
            val.set_content(x);
        }

        void _read_negative_int(cbor_value &val, uint8_t augVal, const cbor_buffer &augBuf) {
            _read_unsigned_int(val, augVal, augBuf);
            val.type = CBOR_NINT;
        }

        void _read_byte_string(cbor_value &val, uint8_t augVal, const cbor_buffer &augBuf, bool indefinite) {
            val.type = CBOR_BYTES;
            if (!indefinite) {
                cbor_value size;
                _read_unsigned_int(size, augVal, augBuf);
                size_t stringSize = size.uint();
                if (_offset + stringSize > _size) throw cbor_incomplete_data_error();
                val.set_content(cbor_buffer(&_data[_offset], stringSize));
                _offset += stringSize;
            } else {
                unique_ptr<uint8_vector> storage = make_unique<uint8_vector>();
                cbor_value chunk;
                for (;;) {
                    read(chunk);
                    if (chunk.type == CBOR_SIMPLE_BREAK) break;
                    if (chunk.type != val.type) throw cbor_error("badly encoded indefinite byte string!");
                    const cbor_buffer &chunk_buf = chunk.buf();
                    size_t chunk_off = storage->size();
                    storage->resize(storage->size() + chunk_buf.size());
                    memcpy(storage->data() + chunk_off, chunk_buf.data(), chunk_buf.size());
                }
                storage->shrink_to_fit();
                val.set_content(buffer(storage->data(), storage->size()));
                val.storage = move(storage);
            }
        }

        void _read_text_string(cbor_value &val, uint8_t augVal, const cbor_buffer &augBuf, bool indefinite) {
            if (indefinite) throw cbor_error("indefinite text strings are not supported yet");
            cbor_value size;
            _read_unsigned_int(size, augVal, augBuf);
            val.type = CBOR_TEXT;
            size_t stringSize = size.uint();
            if (_offset + stringSize > _size) throw cbor_incomplete_data_error();
            val.set_content(cbor_buffer(&_data[_offset], stringSize));
            _offset += stringSize;
        }

        void _read_array(cbor_value &val, uint8_t augVal, const cbor_buffer &augBuf, bool indefinite) {
            cbor_array items;
            if (indefinite) {
                for (;;) {
                    cbor_value item;
                    read(item);
                    if (item.type == CBOR_SIMPLE_BREAK) break;
                    items.emplace_back(move(item));
                }
            } else {
                cbor_value size;
                _read_unsigned_int(size, augVal, augBuf);
                size_t arraySize = size.uint();
                items.resize(arraySize);
                for (size_t i = 0; i < arraySize; ++i) {
                    read(items[i]);
                }
            }
            val.type = CBOR_ARRAY;
            val.set_content(move(items));
        }

        void _read_map(cbor_value &val, uint8_t augVal, const cbor_buffer &augBuf, bool indefinite) {
            cbor_map map;
            if (indefinite) {
                for (;;) {
                    cbor_value itemKey, itemValue;
                    read(itemKey);
                    if (itemKey.type == CBOR_SIMPLE_BREAK) break;
                    read(itemValue);
                    map.emplace_back(move(itemKey), move(itemValue));
                }
            } else {
                cbor_value size;
                _read_unsigned_int(size, augVal, augBuf);
                size_t mapSize = size.uint();
                map.resize(mapSize);
                for (size_t i = 0; i < mapSize; ++i) {
                    read(map[i].first);
                    read(map[i].second);
                }
            }
            val.type = CBOR_MAP;
            val.set_content(move(map));
        }

        void _read_tagged_value(cbor_value &val, uint8_t augVal, const cbor_buffer &augBuf) {
            cbor_value tag;
            _read_unsigned_int(tag, augVal, augBuf);
            unique_ptr<cbor_value> item(new cbor_value());
            read(*item);
            val.type = CBOR_TAG;
            cbor_tag new_tag(tag.uint(), move(item));
            val.set_content(move(new_tag));
        }

        void _read_float32(cbor_value &val, uint8_t /*augVal*/, const cbor_buffer &augBuf)
        {
            static_assert(sizeof(float) == 4);
            if (augBuf.size() != 4) throw cbor_error("a float32 value with aug buffer size != 4!");
            val.type = CBOR_FLOAT32;
            uint8_t local_order[sizeof(float)];
            for (size_t i = 0; i < augBuf.size(); ++i)
                local_order[i] = augBuf.data()[augBuf.size() - 1 - i];
            float tmp;
            memcpy(&tmp, local_order, sizeof(tmp));
            val.set_content(move(tmp));
        }

        void _read_simple_value(cbor_value &val, uint8_t augVal, const cbor_buffer &augBuf, bool) {
            switch (augVal) {
                case 20:
                    val.type = CBOR_SIMPLE_FALSE;
                    break;

                case 21:
                    val.type = CBOR_SIMPLE_TRUE;
                    break;

                case 22:
                    val.type = CBOR_SIMPLE_NULL;
                    break;

                case 23:
                    val.type = CBOR_SIMPLE_UNDEFINED;
                    break;

                case 26:
                    _read_float32(val, augVal, augBuf);
                    break;

                case 31:
                    val.type = CBOR_SIMPLE_BREAK;
                    break;

                default:
                    throw cbor_error("simple values beyond BREAK are not supported yet! augVal: %d, augBuf.size: %zu", (int)augVal, augBuf.size());
            }            
        }

    public:

        cbor_parser(const uint8_t *data, const size_t size)
            : _data(data), _size(size), _offset(0) {
        }

        void read(cbor_value &val) {
            if (_offset + 1 > _size) throw cbor_incomplete_data_error();
            val.data = &_data[_offset];
            uint8_t hdr = _data[_offset++];
            uint8_t type = (hdr >> 5) & 0x7;
            uint8_t augVal = hdr & 0x1F;
            bool indefinite = false;
            cbor_buffer augBuf;

            switch (augVal) {
                case 24:
                    if (_offset + 1 > _size) throw cbor_incomplete_data_error();
                    augBuf.set(&_data[_offset], 1);
                    _offset += 1;
                    break;

                case 25:
                    if (_offset + 2 > _size) throw cbor_incomplete_data_error();
                    augBuf.set(&_data[_offset], 2);
                    _offset += 2;
                    break;

                case 26:
                    if (_offset + 4 > _size) throw cbor_incomplete_data_error();
                    augBuf.set(&_data[_offset], 4);
                    _offset += 4;
                    break;

                case 27:
                    if (_offset + 8 > _size) throw cbor_incomplete_data_error();
                    augBuf.set(&_data[_offset], 8);
                    _offset += 8;
                    break;

                case 28:
                case 29:
                case 30:
                    throw cbor_error("Invalid CBOR header argument value!");

                case 31:
                    if (type == 0 || type == 1 || type == 6) throw cbor_error("Invalid CBOR header: unexpected indefinite value");
                    indefinite = true;
                    break;

                default:
                    if (augVal >= 24) throw cbor_error("Internal error: reached an impossible state!");
                    break;
            }

            switch (type) {
                case 0:
                    _read_unsigned_int(val, augVal, augBuf);
                    break;

                case 1:
                    _read_negative_int(val, augVal, augBuf);
                    break;

                case 2:
                    _read_byte_string(val, augVal, augBuf, indefinite);
                    break;
                
                case 3:
                    _read_text_string(val, augVal, augBuf, indefinite);
                    break;

                case 4:
                    _read_array(val, augVal, augBuf, indefinite);
                    break;

                case 5:
                    _read_map(val, augVal, augBuf, indefinite);
                    break;

                case 6: 
                    _read_tagged_value(val, augVal, augBuf);
                    break;

                case 7:
                    _read_simple_value(val, augVal, augBuf, indefinite);
                    break;

                default: throw cbor_error("Internal error: reached an impossible state!");
            }
            val.size = _offset - val.offset(_data);
        }

        bool eof() const {
            return _offset >= _size;
        }

        size_t offset() const {
            return _offset;
        }

    };

    inline bool is_ascii(const buffer &b)
    {
        for (const uint8_t *p = b.data(), *end = p + b.size(); p < end; ++p) {
            if (*p < 32 || *p > 127) return false;
        }
        return true;
    }

    inline void print_cbor_value(ostream &os, const cbor_value &val, const size_t max_depth=0, const size_t depth = 0,
        const size_t max_array_to_expand=10, const size_t max_map_to_expand=10)
    {
        string shift_str = "";
        for (size_t i = 0; i < depth * 4; ++i) shift_str += ' ';
        switch (val.type) {
            case CBOR_UINT:
                os << shift_str << "UINT: " << val.uint() << endl;
                break;

            case CBOR_NINT:
                os << shift_str << "NINT: -" << val.nint() << endl;
                break;

            case CBOR_BYTES: {
                const cbor_buffer &b = val.buf();
                os << shift_str << "BYTES: " << b.size() << " bytes";
                if (b.size() <= 64) {
                    os << " data: " << b;
                    if (is_ascii(b)) {
                        const string_view sv(reinterpret_cast<const char *>(b.data()), b.size());
                        os << " text: '" << sv << "'";
                    }
                }
                os << endl;
                break;
            }

            case CBOR_TEXT: {
                const cbor_buffer &b = val.buf();
                const string_view sv(reinterpret_cast<const char *>(b.data()), b.size());
                os << shift_str << "TEXT: " << b.size() << " bytes";
                if (b.size() <= 64) os << " text: '" << sv << "'";
                else os << " text: '" << sv.substr(0, 64) << "...'";
                os << endl;
                break;
            }

            case CBOR_ARRAY: {
                const cbor_array &a = val.array();
                os << shift_str << "ARRAY: " << a.size() << " elements, data size: " << val.size << endl;
                if (a.size() <= max_array_to_expand && depth < max_depth) {
                    for (size_t i = 0; i < a.size(); ++i)
                        print_cbor_value(os, a[i], max_depth, depth + 1, max_array_to_expand, max_map_to_expand);
                }
                break;
            }

            case CBOR_MAP: {
                const cbor_map &m = val.map();
                os << shift_str << "MAP: " << m.size() << " elements, data size: " << val.size << endl;
                if (m.size() <= max_map_to_expand && depth + 1 < max_depth) {
                    for (size_t i = 0; i < m.size(); ++i) {
                        os << shift_str << "    KEY:" << endl;
                        print_cbor_value(os, m[i].first, max_depth, depth + 2, max_array_to_expand, max_map_to_expand);
                        os << shift_str << "    VAL:" << endl;
                        print_cbor_value(os, m[i].second, max_depth, depth + 2, max_array_to_expand, max_map_to_expand);
                    }
                }
                break;
            }

            case CBOR_TAG: {
                const cbor_tag &t = val.tag();
                os << shift_str << "TAG: " << t.first << " data size: " << val.size << endl;
                if (depth < max_depth) {
                    print_cbor_value(os, *t.second, max_depth, depth + 1, max_array_to_expand, max_map_to_expand);
                }
                break;
            }

            case CBOR_SIMPLE_NULL:
                os << shift_str << "NULL" << endl;
                break;

            default: {
                throw error("Unsupported CBOR type: %u!", (unsigned)val.type);
            }
        }
    }

}

#endif //!DAEDALUS_TURBO_CBOR_HPP
