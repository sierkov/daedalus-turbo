/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_BIG_FLOAT_HPP
#define DAEDALUS_TURBO_BIG_FLOAT_HPP

#define BOOST_DETAIL_EMPTY_VALUE_BASE
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <dt/common/format.hpp>
#include <dt/common/bytes.hpp>

namespace daedalus_turbo {
    using cpp_float = boost::multiprecision::number<boost::multiprecision::cpp_bin_float<50>>;
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::cpp_float>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            std::ostringstream ss {};
            ss << v;
            return fmt::format_to(ctx.out(), "{}", ss.str());
        }
    };
}

#endif //DAEDALUS_TURBO_BIG_FLOAT_HPP