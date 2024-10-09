/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_BIG_INT_HPP
#define DAEDALUS_TURBO_BIG_INT_HPP

#include <boost/multiprecision/cpp_int.hpp>
#include <dt/format.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo {
    using boost::multiprecision::cpp_int;

    inline cpp_int big_int_from_bytes(const buffer data)
    {
        if (data.size() > 64)
            throw error("big ints larger than 64 bytes are not supported but got: {}!", data.size());
        cpp_int val {};
        for (const uint8_t b: data) {
            val <<= 8;
            val |= b;
        }
        return val;
    }
}

namespace fmt {
    template<>
    struct formatter<boost::multiprecision::cpp_int>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            std::ostringstream ss {};
            ss << v;
            return fmt::format_to(ctx.out(), "{}", ss.str());
        }
    };
}

#endif //DAEDALUS_TURBO_BIG_INT_HPP