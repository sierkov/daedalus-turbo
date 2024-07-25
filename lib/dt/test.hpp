/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_TEST_HPP
#define DAEDALUS_TURBO_TEST_HPP

#define BOOST_UT_DISABLE_MODULE 1
#include <boost/ut.hpp>
#include <dt/array.hpp>
#include <dt/error.hpp>
#include <dt/file.hpp>
#include <dt/logger.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo {
    using namespace boost::ut;

    struct test_printer: boost::ut::printer {
        template<class T>
        test_printer& operator<<(T &&t) {
            constexpr auto &tid = typeid(t);
            if constexpr (tid == typeid(buffer) || tid == typeid(uint8_vector) || tid == typeid(array<uint8_t, 32>)) {
                std::cerr << fmt::format("{}", t);
            } else {
                std::cerr << std::forward<T>(t);
            }
            return *this;
        }

        test_printer& operator<<(const std::string_view sv) {
            std::cerr << sv;
            return *this;
        }
    };

    template<typename T>
    void test_close(const T &exp, const T &act, T eps=1e-4, const std::source_location &loc=std::source_location::current())
    {
        if (exp) {
            const auto e = std::fabs(act - exp) / act;
            expect(e <= eps, loc) << fmt::format("eps {} is too big for {} and {}", e, exp, act);
        } else {
            const auto d = std::fabs(act - exp);
            expect(d <= eps, loc) << fmt::format("delta {} is too big for {} and {}", d, exp, act);
        }
    }

    template<typename T, typename Y>
    void test_same(const T &x, const Y &y, const std::source_location &loc=std::source_location::current())
    {
        expect(x == static_cast<T>(y), loc) << fmt::format("{} != {}", x, y);
    }
}

template <class... Ts>
inline auto boost::ut::cfg<boost::ut::override, Ts...> = boost::ut::runner<boost::ut::reporter<daedalus_turbo::test_printer>> {};

#endif // !DAEDALUS_TURBO_TEST_HPP