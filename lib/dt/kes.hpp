/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_KES_HPP
#define DAEDALUS_TURBO_KES_HPP

#include <array>
#include <span>
#include <boost/date_time/period.hpp>
#include <dt/blake2b.hpp>
#include <dt/ed25519.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo {
    using kes_vkey = ed25519::vkey;
    using kes_vkey_span = std::span<const uint8_t, sizeof(kes_vkey)>;

    template <size_t DEPTH>
    struct kes_signature {
        static constexpr size_t period_max = 1 << DEPTH;
        static constexpr size_t period_split_point = 1 << (DEPTH - 1);

        static constexpr size_t size()
        {
            return sizeof(ed25519::signature) + DEPTH * 2 * sizeof(ed25519::vkey);
        }

        explicit kes_signature(const buffer &bytes)
            : _lhs_vk { bytes.subspan(kes_signature<DEPTH - 1>::size(), sizeof(_lhs_vk)) },
                _rhs_vk { bytes.subspan(kes_signature<DEPTH - 1>::size() + sizeof(_lhs_vk), sizeof(_rhs_vk)) },
                _signature { bytes.subspan(0, kes_signature<DEPTH - 1>::size()) }
        {
        }

        [[nodiscard]] bool verify(size_t period, const kes_vkey_span &vkey, const buffer &msg) const
        {
            blake2b_256_hash computed_vkey;
            blake2b(computed_vkey, buffer { &_lhs_vk, sizeof(_lhs_vk) + sizeof(_rhs_vk) });
            if (span_memcmp(computed_vkey, vkey) != 0)
                return false;
            if (period >= period_max)
                throw error(fmt::format("KES period out of range: {}!", period));
            if (period < period_split_point)
                return _signature.verify(period, _lhs_vk, msg);
            return _signature.verify(period - period_split_point, _rhs_vk, msg);
        }
    private:
        blake2b_256_hash _lhs_vk {};
        blake2b_256_hash _rhs_vk {};
        kes_signature<DEPTH - 1> _signature {};
    };

    template <>
    struct kes_signature<0> {
        static constexpr size_t size()
        {
            return sizeof(_signature);
        }

        explicit kes_signature(const buffer &bytes)
            : _signature { bytes }
        {
        }

        [[nodiscard]] bool verify(size_t period, const kes_vkey_span &vkey, const buffer &msg) const
        {
            if (period != 0)
                throw error(fmt::format("period value must be 0 but got: {}", period));
            return ed25519::verify(_signature, vkey, msg);
        }
    private:
        ed25519::signature _signature {};
    };

    namespace kes {
        typedef daedalus_turbo::error error;

        struct split_seed {
            ed25519::seed left;
            ed25519::seed right;

            explicit split_seed(const buffer &sd) {
                if (sd.size() != sizeof(ed25519::seed))
                    throw error(fmt::format("seed buffer must be of of {} bytes but got {}!", sizeof(ed25519::seed), sd.size()));
                uint8_vector tmp {};
                tmp << std::string_view { "\x01" } << sd;
                blake2b(left, tmp);
                tmp.clear();
                tmp << std::string_view { "\x02" } << sd;
                blake2b(right, tmp);
            }
        };

        template<size_t DEPTH>
        using signature = kes_signature<DEPTH>;

        template <size_t DEPTH>
        struct secret {
            static constexpr size_t period_end = 1 << DEPTH;
            static constexpr size_t period_split_point = 1 << (DEPTH - 1);
            static constexpr size_t signature_size = sizeof(ed25519::signature) + DEPTH * 2 * sizeof(ed25519::vkey);

            using signature = array<uint8_t, signature_size>;

            explicit secret(const buffer &bytes)
                : _seed { bytes }, _left { _seed.left }, _right { _seed.right }
            {
                uint8_vector tmp {};
                tmp << _left.vkey() << _right.vkey();
                blake2b(_vk, tmp);
            }

            void update()
            {
                if (_period + 1 >= period_end)
                    throw error(fmt::format("KES secret of level {} cannot grow >= {} while the current period is {}", DEPTH, period_end, _period));
                ++_period;
            }

            void sign(const std::span<uint8_t> &signature, const buffer &msg) const
            {
                if (_period < period_split_point) {
                    //_left.sign(signature, msg, _period);
                    _left.sign(signature, msg);
                } else {
                    //_right.sign(signature, msg, _period - period_split_point);
                    _right.sign(signature, msg);
                }
                span_memcpy(signature.subspan(_left.signature_size, sizeof(ed25519::vkey)), _left.vkey());
                span_memcpy(signature.subspan(_left.signature_size + sizeof(ed25519::vkey), sizeof(ed25519::vkey)), _right.vkey());
            }

            [[nodiscard]] const ed25519::vkey &vkey() const
            {
                return _vk;
            }
        private:
            split_seed _seed;
            secret<DEPTH - 1> _left, _right;
            ed25519::vkey _vk;
            uint32_t _period = 0;
        };

        template <>
        struct secret<0> {
            static constexpr size_t signature_size = sizeof(ed25519::signature);
            using signature = array<uint8_t, signature_size>;

            explicit secret(const buffer &seed)
            {
                ed25519::create_from_seed(_sk, _vk, seed);
            }

            void update()
            {
                throw error("level 0 KES secret cannot be udpdated!");
            }

            [[nodiscard]] size_t period() const
            {
                return 0;
            }

            void sign(const std::span<uint8_t> &signature, const buffer &msg) const
            {
                ed25519::sign(signature.subspan(0, sizeof(ed25519::signature)), msg, _sk);
            }

            [[nodiscard]] const ed25519::vkey &vkey() const
            {
                return _vk;
            }
        private:
            ed25519::skey _sk;
            ed25519::vkey _vk;
        };
    }
}

#endif //!DAEDALUS_TURBO_KES_HPP