/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <cstring>
#include <functional>
#include <optional>
#include <dt/common/test.hpp>
#include <dt/array.hpp>
#include <dt/common/error.hpp>

using namespace daedalus_turbo;

static std::string no_error_msg {
#ifdef __APPLE__
    "Undefined error: 0"
#elif _WIN32
    "No error"
#else
    "Success"
#endif
};

template<typename F>
void expect_throws_msg(const F &f, const std::optional<std::string> &matches, const std::source_location &src_loc=std::source_location::current())
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
        if (matches) {
            const auto descr = fmt::format("'{}' does not contain '{}' from {}:{}", *msg, *matches, src_loc.file_name(), src_loc.line());
            test_same(descr, true, msg->starts_with(*matches));
        }
    }
}

template<typename F>
void expect_throws_msg(const F &f, const char *match, const std::source_location &src_loc=std::source_location::current())
{
    expect_throws_msg(f, std::string { match }, src_loc);
}

suite error_suite = [] {
    using daedalus_turbo::array;
    "error"_test = [] {
        "no_args"_test = [] {
            auto f = [] { throw error("Hello!"); };
            expect_throws_msg(f, "Hello!");
        };
        "integers"_test = [] {
            auto f = [] { throw error(fmt::format("Hello {}!", 123)); };
            expect_throws_msg(f, "Hello 123!");
        };
        "string"_test = [] {
            auto f = [&] { throw error(fmt::format("Hello {}!", "world")); };
            expect_throws_msg(f, "Hello world!");
        };
        "buffer"_test = [] {
            byte_array<4> buf { 0xDE, 0xAD, 0xBE, 0xEF };
            auto f = [&] { throw error(fmt::format("Hello {}!", buf)); };
            expect_throws_msg(f, "Hello DEADBEEF!");
        };
        "error_sys_ok"_test = [] {
            auto f = [&] { errno = 0; throw error_sys(fmt::format("Hello {}!", "world")); };
            expect_throws_msg(f, "Hello world! errno: 0 strerror: " + no_error_msg);
        };
        "error_sys_fail"_test = [] {
            auto f = [&] { errno = 2; throw error_sys(fmt::format("Hello {}!", "world")); };
            expect_throws_msg(f, "Hello world! errno: 2 strerror: No such file or directory");
        };
    };
};