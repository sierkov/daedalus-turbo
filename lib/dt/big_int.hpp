/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_BIG_INT_HPP
#define DAEDALUS_TURBO_BIG_INT_HPP

#define BOOST_DETAIL_EMPTY_VALUE_BASE
#include <boost/multiprecision/cpp_int.hpp>
#include <dt/format.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo {
    using boost::multiprecision::cpp_int;

    static constexpr size_t big_int_max_size = 8192;

    inline cpp_int big_int_from_bytes(const buffer data)
    {
        if (data.size() > big_int_max_size)
            throw error(fmt::format("big ints larger than {} bytes are not supported but got: {}!", big_int_max_size, data.size()));
        cpp_int val {};
        for (const uint8_t b: data) {
            val <<= 8;
            val |= b;
        }
        return val;
    }
}

namespace fmt {
    template<typename T>
    struct formatter<boost::multiprecision::number<T>>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            std::ostringstream ss {};
            ss << v;
            return fmt::format_to(ctx.out(), "{}", ss.str());
        }
    };
}

#endif //DAEDALUS_TURBO_BIG_INT_HPP