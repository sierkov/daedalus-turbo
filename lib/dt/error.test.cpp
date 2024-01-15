/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <cstring>
#include <functional>
#include <optional>
#include <source_location>
#include <span>
#include <boost/ut.hpp>
#include <dt/array.hpp>
#include <dt/error.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

static std::string no_error_msg {
#ifdef __clang__
    "Undefined error: 0"
#elif _WIN32
    "No error"
#else
    "Success"
#endif
};

template<typename F>
inline void expect_throws_msg(const F &f, const std::initializer_list<std::string> &matches, const std::source_location &src_loc=std::source_location::current())
{
    expect(boost::ut::throws<error>(f)) << "no exception has been thrown";
    std::optional<std::string> msg {};
    try {
        f();
    } catch (error &ex) {
        msg = ex.what();
    }
    expect((bool)msg) << "exception message is empty";
    if (msg) {
        for (const auto &match: matches) {
            expect(msg->find(match) != msg->npos) << fmt::format("'{}' does not contain '{}' from {}:{}", *msg, match, src_loc.file_name(), src_loc.line());
        }
    }
}

template<typename F>
inline void expect_throws_msg(const F &f, const std::string &match, const std::source_location &src_loc=std::source_location::current())
{
    expect_throws_msg(f, { match }, src_loc);
}

suite error_suite = [] {
    "error"_test = [] {
        "no_args"_test = [] {
            auto f = [] { throw error("Hello!"); };
            expect_throws_msg(f, "Hello!");
        };
        "integers"_test = [] {
            auto f = [] { throw error("Hello {}!", 123); };
            expect_throws_msg(f, "Hello 123!");
        };
        "string"_test = [] {
            auto f = [&] { throw error("Hello {}!", "world"); };
            expect_throws_msg(f, "Hello world!");
        };
        "buffer"_test = [] {
            array<uint8_t, 4> buf { 0xDE, 0xAD, 0xBE, 0xEF };
            auto f = [&] { throw error("Hello {}!", buf.span()); };
            expect_throws_msg(f, "Hello DEADBEEF!");
        };
        "error_sys_ok"_test = [] {
            auto f = [&] { errno = 0; throw error_sys("Hello {}!", "world"); };
            expect_throws_msg(f, "Hello world!, errno: 0, strerror: " + no_error_msg);
        };
        "error_sys_fail"_test = [] {
            auto f = [&] { errno = 2; throw error_sys("Hello {}!", "world"); };
            expect_throws_msg(f, "Hello world!, errno: 2, strerror: No such file or directory");
        };
        "error_src_loc"_test = [] {
            auto f = [&] { throw error_src_loc(std::source_location::current(), "Hello {}!", "world"); };
            expect_throws_msg(f, { "Hello world!", "lib/dt/error.test.cpp:79" });
        };
    };
};