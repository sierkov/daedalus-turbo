/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_KES_HPP
#define DAEDALUS_TURBO_KES_HPP 1

#include <array>
#include <span>
#include <dt/blake2b.hpp>
#include <dt/ed25519.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo {

    using kes_vkey = ed25519_vkey;
    using kes_vkey_span = std::span<const uint8_t, sizeof(kes_vkey)>;

    template <size_t DEPTH>
    class kes_signature
    {
    public:

        static constexpr size_t size()
        {
            return sizeof(ed25519_signature) + DEPTH * 2 * sizeof(ed25519_vkey);
        }

        kes_signature()
        {
        }

        kes_signature(const std::span<const uint8_t> &bytes)
            : _sigma(bytes.subspan(0, kes_signature<DEPTH - 1>::size()))
        {
            if (bytes.size() != kes_signature<DEPTH>::size())
                throw error_fmt("KES signature of depth {} is expected to have {} bytes but got only {}!", DEPTH, kes_signature<DEPTH>::size(), bytes.size());
            span_memcpy(_lhs_vk, bytes.subspan(kes_signature<DEPTH - 1>::size(), sizeof(_lhs_vk)));
            span_memcpy(_rhs_vk, bytes.subspan(kes_signature<DEPTH - 1>::size() + sizeof(_lhs_vk), sizeof(_lhs_vk)));
        }

        kes_signature &operator=(const std::span<const uint8_t> &bytes)
        {
            if (bytes.size() != kes_signature<DEPTH>::size())
                throw error_fmt("KES signature of depth {} is expected to have {} bytes but got only {}!", DEPTH, kes_signature<DEPTH>::size(), bytes.size());
            _sigma = bytes.subspan(0, kes_signature<DEPTH - 1>::size());
            span_memcpy(_lhs_vk, bytes.subspan(kes_signature<DEPTH - 1>::size(), sizeof(_lhs_vk)));
            span_memcpy(_rhs_vk, bytes.subspan(kes_signature<DEPTH - 1>::size() + sizeof(_lhs_vk), sizeof(_lhs_vk)));
            return *this;
        }

        bool verify(size_t period, const kes_vkey_span &vkey, const std::span<const uint8_t> &msg) const
        {
            std::array<uint8_t, sizeof(kes_vkey) * 2> hash_buf;
            auto hash_buf_span = std::span(hash_buf);
            span_memcpy(hash_buf_span.subspan(0, sizeof(kes_vkey)), _lhs_vk);
            span_memcpy(hash_buf_span.subspan(sizeof(kes_vkey), sizeof(kes_vkey)), _rhs_vk);
            auto computed_vkey = blake2b<blake2b_256_hash>(hash_buf_span);
            int vkey_cmp = span_memcmp(computed_vkey, vkey);
            if (vkey_cmp != 0) return false;
            size_t split = 1 << (DEPTH - 1);
            if (period < split) {
                return _sigma.verify(period, _lhs_vk, msg);
            } else {
                return _sigma.verify(period - split, _rhs_vk, msg);
            }
        }

    private:

        kes_signature<DEPTH - 1> _sigma {};
        blake2b_256_hash _lhs_vk {};
        blake2b_256_hash _rhs_vk {};
    };

    template <>
    class kes_signature<0>
    {
    public:

        static constexpr size_t size()
        {
            return sizeof(ed25519_signature);
        }

        kes_signature()
        {
        }

        kes_signature(const std::span<const uint8_t> &bytes)
        {
            if (bytes.size() != kes_signature<0>::size())
                throw error_fmt("KES signature of depth {} is expected to have {} bytes but got only {}!", 0, kes_signature<0>::size(), bytes.size());
            span_memcpy(_signature, bytes);
        }

        kes_signature &operator=(const std::span<const uint8_t> &bytes)
        {
            if (bytes.size() != kes_signature<0>::size())
                throw error_fmt("KES signature of depth {} is expected to have {} bytes but got only {}!", 0, kes_signature<0>::size(), bytes.size());
            span_memcpy(_signature, bytes);
            return *this;
        }

        bool verify(size_t period, const kes_vkey_span &vkey, const std::span<const uint8_t> &msg) const
        {
            if (period != 0) throw error_fmt("period value must be 0 but got: {}", period);
            return ed25519_verify(_signature, vkey, msg);
        }

    private:

        ed25519_signature _signature {};
    };

}

#endif //!DAEDALUS_TURBO_KES_HPP
