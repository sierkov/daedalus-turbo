#include <array>
#include <cstring>
#include <functional>
#include <source_location>
#include <span>

#include <boost/ut.hpp>

#include <dt/error.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

template<typename F>
inline void expect_throws_msg(F &f, const char *exp_msg)
{
    expect(boost::ut::throws<error_fmt>(f));
    const char *msg = 0;
    try {
        f();
    } catch (error_fmt &ex) {
        msg = ex.what();
    }
    expect(msg != 0);
    if (msg != 0) expect(strcmp(msg, exp_msg) == 0) << msg;
}

suite error_suite = [] {
    "error"_test = [] {
        "no_args"_test = [] {
            auto f = [] { throw error_fmt("Hello!"); };
            expect_throws_msg(f, "Hello!");
        };
        "integers"_test = [] {
            auto f = [] { throw error_fmt("Hello {}!", 123); };
            expect_throws_msg(f, "Hello 123!");
        };
        "string"_test = [] {
            auto f = [&] { throw error_fmt("Hello {}!", "world"); };
            expect_throws_msg(f, "Hello world!");
        };
        "buffer"_test = [] {
            std::array<uint8_t, 4> buf { 0xDE, 0xAD, 0xBE, 0xEF };
            auto f = [&] { throw error_fmt("Hello {}!", std::span(buf)); };
            expect_throws_msg(f, "Hello DEADBEEF!");
        };
        "error_sys_ok"_test = [] {
            auto f = [&] { throw error_sys_fmt("Hello {}!", "world"); };
            expect_throws_msg(f, "Hello world!, errno: 0, strerror: Success");
        };
        "error_sys_fail"_test = [] {
            auto f = [&] { errno = 2; throw error_sys_fmt("Hello {}!", "world"); };
            expect_throws_msg(f, "Hello world!, errno: 2, strerror: No such file or directory");
        };
        "error_src_loc"_test = [] {
            auto f = [&] { throw error_src_loc(std::source_location::current(), "Hello {}!", "world"); };
            expect_throws_msg(f, "Hello world! at lib/dt/error.test.cpp:56");
        };
    };
};
