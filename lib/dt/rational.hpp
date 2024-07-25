/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_RATIONAL_HPP
#define DAEDALUS_TURBO_RATIONAL_HPP

#include <numeric>
#include <dt/big_int.hpp>
#include <dt/error.hpp>

namespace daedalus_turbo {
    using rational = boost::multiprecision::cpp_rational;
    using boost::multiprecision::numerator;
    using boost::multiprecision::denominator;

    struct rational_u64 {
        uint64_t numerator = 0;
        uint64_t denominator = 1;

        static rational_u64 from_double(const double &d)
        {
            double num = d;
            uint64_t denom = 1;
            while (std::fabs(num - static_cast<uint64_t>(num)) > 1e-6) {
                if (denom >= 1'000'000'000)
                    throw error("an unsupported value for a conversion to rational: {}", d);
                num *= 10;
                denom *= 10;
            }
            rational_u64 r { static_cast<uint64_t>(num), denom };
            const auto div = std::gcd(r.numerator, r.denominator);
            if (div != 0) {
                r.numerator /= div;
                r.denominator /= div;
            }
            return r;
        }

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.numerator, self.denominator);
        }

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