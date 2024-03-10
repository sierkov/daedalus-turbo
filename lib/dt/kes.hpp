/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_KES_HPP
#define DAEDALUS_TURBO_KES_HPP

#include <array>
#include <span>
#include <dt/blake2b.hpp>
#include <dt/ed25519.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo {
    using kes_vkey = ed25519_vkey;
    using kes_vkey_span = std::span<const uint8_t, sizeof(kes_vkey)>;

    template <size_t DEPTH>
    struct kes_signature {
        static constexpr size_t size()
        {
            return sizeof(ed25519_signature) + DEPTH * 2 * sizeof(ed25519_vkey);
        }

        explicit kes_signature(const buffer &bytes)
            : _signature { bytes.subspan(0, kes_signature<DEPTH - 1>::size()) },
                _lhs_vk { bytes.subspan(kes_signature<DEPTH - 1>::size(), sizeof(_lhs_vk)) },
                _rhs_vk { bytes.subspan(kes_signature<DEPTH - 1>::size() + sizeof(_lhs_vk), sizeof(_rhs_vk)) }
        {
        }

        [[nodiscard]] bool verify(size_t period, const kes_vkey_span &vkey, const buffer &msg) const
        {
            blake2b_256_hash computed_vkey;
            blake2b(computed_vkey, buffer { &_lhs_vk, sizeof(_lhs_vk) + sizeof(_rhs_vk) });
            if (span_memcmp(computed_vkey, vkey) != 0)
                return false;
            static constexpr size_t max_period = 1 << DEPTH;
            if (period >= max_period)
                throw error("KES period out of range: {}!", period);
            static constexpr size_t split = 1 << (DEPTH - 1);
            if (period < split)
                return _signature.verify(period, _lhs_vk, msg);
            return _signature.verify(period - split, _rhs_vk, msg);
        }
    private:
        kes_signature<DEPTH - 1> _signature {};
        blake2b_256_hash _lhs_vk {};
        blake2b_256_hash _rhs_vk {};
    };

    template <>
    struct kes_signature<0> {
        static constexpr size_t size()
        {
            return sizeof(ed25519_signature);
        }

        explicit kes_signature(const buffer &bytes)
            : _signature { bytes }
        {
        }

        [[nodiscard]] bool verify(size_t period, const kes_vkey_span &vkey, const buffer &msg) const
        {
            if (period != 0)
                throw error("period value must be 0 but got: {}", period);
            return ed25519::verify(_signature, vkey, msg);
        }
    private:
        ed25519_signature _signature {};
    };
}

#endif //!DAEDALUS_TURBO_KES_HPP