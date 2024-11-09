/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CBOR_ENCODER_HPP
#define DAEDALUS_TURBO_CBOR_ENCODER_HPP

#include <ranges>
#include <dt/big_int.hpp>
#include <dt/cbor/types.hpp>
#include <dt/rational.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::cbor {
    struct encoder {
        using prepare_data_func = std::function<void()>;

        virtual ~encoder() =default;

        encoder &array()
        {
            _encode_item(major_type::array, static_cast<uint8_t>(special_val::s_break));
            return *this;
        }

        virtual encoder &set(const size_t sz, const prepare_data_func &prepare_data)
        {
            return array_compact(sz, prepare_data);
        }

        virtual std::unique_ptr<encoder> make_sibling() const
        {
            return std::make_unique<encoder>();
        }

        encoder &array(const size_t sz)
        {
            _encode_uint_item(major_type::array, sz);
            return *this;
        }

        encoder &array_compact(const size_t sz, const prepare_data_func &prepare_data)
        {
            if (sz >= 24)
                array();
            else
                array(sz);
            prepare_data();
            if (sz >= 24)
                s_break();
            return *this;
        }

        encoder &map()
        {
            _encode_item(major_type::map, static_cast<uint8_t>(special_val::s_break));
            return *this;
        }

        encoder &map(const size_t sz)
        {
            _encode_uint_item(major_type::map, sz);
            return *this;
        }

        encoder &map_compact(const size_t sz, const prepare_data_func &prepare_data)
        {
            if (sz >= 24)
                map();
            else
                map(sz);
            prepare_data();
            if (sz >= 24)
                s_break();
            return *this;
        }

        encoder &uint(const uint64_t val)
        {
            _encode_uint_item(major_type::uint, val);
            return *this;
        }

        // the negative value must be already converted to the uint64_t representation
        encoder &nint(const uint64_t val)
        {
            _encode_uint_item(major_type::nint, val);
            return *this;
        }

        encoder &bigint(cpp_int val)
        {
            if (val >= 0) [[likely]] {
                if (val <= std::numeric_limits<uint64_t>::max()) {
                    uint(static_cast<uint64_t>(val));
                    return *this;
                }
                tag(2);
            } else {
                val *= -1;
                --val;
                if (val <= std::numeric_limits<uint64_t>::max()) {
                    nint(static_cast<uint64_t>(val));
                    return *this;
                }
                tag(3);
            }
            uint8_vector buf {};
            while (val) {
                buf.emplace_back(val & 0xFF);
                val >>= 8;
            }
            _encode_uint_item(major_type::bytes, buf.size());
            for (const auto b: buf | std::ranges::views::reverse)
                _buf.emplace_back(b);
            return *this;
        }

        encoder &rational(const rational_u64 &val)
        {
            tag(30);
            array(2)
                .uint(val.numerator)
                .uint(val.denominator);
            return *this;
        }

        encoder &float32(const float val)
        {
            _encode_item(major_type::simple, static_cast<uint8_t>(special_val::four_bytes));
            _encode_data(buffer::from<float>(host_to_net(val)));
            return *this;
        }

        encoder &bytes(const buffer buf)
        {
            _encode_uint_item(major_type::bytes, buf.size());
            _encode_data(buf);
            return *this;
        }

        encoder &text(const std::string_view sv)
        {
            _encode_uint_item(major_type::text, sv.size());
            _encode_data(sv);
            return *this;
        }

        encoder &raw_cbor(const buffer buf)
        {
            _encode_data(buf);
            return *this;
        }

        encoder &s_null()
        {
            _encode_item(major_type::simple, static_cast<uint8_t>(special_val::s_null));
            return *this;
        }

        encoder &s_break()
        {
            _encode_item(major_type::simple, static_cast<uint8_t>(special_val::s_break));
            return *this;
        }

        encoder &s_false()
        {
            _encode_item(major_type::simple, static_cast<uint8_t>(special_val::s_false));
            return *this;
        }

        encoder &s_true()
        {
            _encode_item(major_type::simple, static_cast<uint8_t>(special_val::s_true));
            return *this;
        }

        encoder &tag(const uint64_t id)
        {
            _encode_uint_item(major_type::tag, id);
            return *this;
        }

        encoder &custom(const std::function<void(encoder &)> &gen)
        {
            gen(*this);
            return *this;
        }

        [[nodiscard]] uint8_vector &cbor()
        {
            return _buf;
        }

        [[nodiscard]] const uint8_vector &cbor() const
        {
            return _buf;
        }
    protected:
        void _encode_data(const buffer buf)
        {
            std::copy(buf.begin(), buf.end(), _it);
        }
    private:
        uint8_vector _buf {};
        std::back_insert_iterator<uint8_vector> _it { std::back_inserter(_buf) };

        void _encode_uint_item(const major_type typ, const uint64_t val)
        {
            if (val < 24) {
                _encode_item(typ, val);
            } else if (val <= std::numeric_limits<uint8_t>::max()) {
                _encode_item(typ, static_cast<uint8_t>(special_val::one_byte));
                const auto h_val = host_to_net<uint8_t>(val);
                _encode_data(buffer { &h_val, sizeof(h_val) });
            } else if (val <= std::numeric_limits<uint16_t>::max()) {
                _encode_item(typ, static_cast<uint16_t>(special_val::two_bytes));
                const auto h_val = host_to_net<uint16_t>(val);
                _encode_data(buffer { &h_val, sizeof(h_val) });
            } else if (val <= std::numeric_limits<uint32_t>::max()) {
                _encode_item(typ, static_cast<uint16_t>(special_val::four_bytes));
                const auto h_val = host_to_net<uint32_t>(val);
                _encode_data(buffer { &h_val, sizeof(h_val) });
            } else {
                _encode_item(typ, static_cast<uint16_t>(special_val::eight_bytes));
                const auto h_val = host_to_net<uint64_t>(val);
                _encode_data(buffer { &h_val, sizeof(h_val) });
            }
        }

        void _encode_item(const major_type typ, const uint8_t special)
        {
            _buf.emplace_back((static_cast<uint8_t>(typ) << 5) | (special & 0x1F));
        }
    };

    inline encoder &operator<<(encoder &dst, const encoder &src)
    {
        dst.cbor() << src.cbor();
        return dst;
    }

    inline encoder &operator<<(encoder &dst, const buffer &src)
    {
        dst.cbor() << src;
        return dst;
    }
}

#endif // !DAEDALUS_TURBO_CBOR_ENCODER_HPP