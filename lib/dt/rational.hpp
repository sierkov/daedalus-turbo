/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_RATIONAL_HPP
#define DAEDALUS_TURBO_RATIONAL_HPP

#include <boost/multiprecision/cpp_int.hpp>
#include <dt/format.hpp>

namespace daedalus_turbo {
    using cpp_int = boost::multiprecision::cpp_int;
    using rational = boost::multiprecision::cpp_rational;
    using boost::multiprecision::numerator;
    using boost::multiprecision::denominator;

    struct rational_u64 {
        uint64_t numerator = 0;
        uint64_t denominator = 1;

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.numerator, self.denominator);
        }

        bool operator==(const auto &b) const
        {
            return numerator == b.numerator && denominator == b.denominator;
        }

        operator rational() const
        {
            return rational { numerator, denominator };
        }

        inline rational as_r() const
        {
            return static_cast<rational>(*this);
        }
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::rational>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{} % {}", static_cast<uint64_t>(daedalus_turbo::numerator(v)), static_cast<uint64_t>(daedalus_turbo::denominator(v)));
        }
    };

    template<>
    struct formatter<daedalus_turbo::rational_u64>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{} % {}", v.numerator, v.denominator);
        }
    };
}

#endif //DAEDALUS_TURBO_RATIONAL_HPP