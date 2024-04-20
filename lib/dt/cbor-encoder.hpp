/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CBOR_ENCODER_HPP
#define DAEDALUS_TURBO_CBOR_ENCODER_HPP

#include <cppbor/cppbor.h>
#include <dt/util.hpp>

namespace daedalus_turbo::cbor {
    struct encoder {
        encoder &array(size_t sz)
        {
            cppbor::encodeHeader(cppbor::ARRAY, sz, _it);
            return *this;
        }

        encoder &map(size_t sz)
        {
            cppbor::encodeHeader(cppbor::MAP, sz, _it);
            return *this;
        }

        encoder &uint(uint64_t val)
        {
            cppbor::encodeHeader(cppbor::UINT, val, _it);
            return *this;
        }

        encoder &bytes(const buffer &buf)
        {
            cppbor::encodeHeader(cppbor::BSTR, buf.size(), _it);
            std::copy(buf.begin(), buf.end(), _it);
            return *this;
        }

        encoder &s_false()
        {
            cppbor::encodeHeader(cppbor::SIMPLE, cppbor::FALSE, _it);
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
    private:
        uint8_vector _buf {};
        std::back_insert_iterator<uint8_vector> _it { std::back_inserter(_buf) };
    };

    inline encoder &operator<<(encoder &dst, const encoder &src)
    {
        dst.cbor() << src.cbor();
        return dst;
    }
}

#endif // !DAEDALUS_TURBO_CBOR_ENCODER_HPP