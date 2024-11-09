/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_RATIONAL_HPP
#define DAEDALUS_TURBO_RATIONAL_HPP

#include <numeric>
#include <dt/big_int.hpp>
#include <dt/json.hpp>

namespace daedalus_turbo {
    using rational = boost::multiprecision::cpp_rational;
    using boost::multiprecision::numerator;
    using boost::multiprecision::denominator;

    struct cbor_value;
    struct cbor_array;

    namespace cbor {
        struct encoder;
    }

    struct rational_u64 {
        uint64_t numerator = 0;
        uint64_t denominator = 1;

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.numerator, self.denominator);
        }

        rational_u64() =default;
        rational_u64(uint64_t, uint64_t);
        rational_u64(double);
        rational_u64(const cbor_array &);
        rational_u64(const cbor_value &);
        rational_u64(const json::value &v);

        bool operator==(const auto &b) const
        {
            return numerator == b.numerator && denominator == b.denominator;
        }

        operator double() const
        {
            return static_cast<double>(numerator) / denominator;
        }

        operator rational() const
        {
            return rational { numerator, denominator };
        }

        rational as_r() const
        {
            return static_cast<rational>(*this);
        }

        void normalize()
        {
            const auto div = std::gcd(numerator, denominator);
            if (div != 0) {
                numerator /= div;
                denominator /= div;
            }
        }

        void to_cbor(cbor::encoder &) const;
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::rational>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{} % {}", static_cast<uint64_t>(daedalus_turbo::numerator(v)), static_cast<uint64_t>(daedalus_turbo::denominator(v)));
        }
    };

    template<>
    struct formatter<daedalus_turbo::rational_u64>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{} % {}", v.numerator, v.denominator);
        }
    };
}

#endif //DAEDALUS_TURBO_RATIONAL_HPP