/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <boost/ut.hpp>
#include <dt/util.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite util_suite = [] {
    "util"_test = [] {
        "format"_test = [] {
            expect(format("Hello %02hhX\n", (char)0x16) == "Hello 16\n"s);
            expect(format("Hello %zu", (size_t)0x123456789ABC) == "Hello 20015998343868"s);
        };

        "Exception"_test = [] {
            auto my_throw = [] {
                errno = ENOENT;
                throw error("My Bad: %s!", "ABC");
            };
            expect(throws<error>(my_throw));
            string msg;
            try {
                my_throw();
            } catch (error &ex) {
                msg = ex.what();
            }
            expect(msg == "My Bad: ABC!"s) << msg;
        };

        "sys_error"_test = [] {
            auto my_throw = [] {
                errno = ENOENT;
                throw sys_error("My Bad: %s!", "ABC");
            };
            expect(throws<sys_error>(my_throw));
            string msg;
            try {
                my_throw();
            } catch (sys_error &ex) {
                msg = ex.what();
            }
            expect(msg == "My Bad: ABC!, errno: 2, strerror: No such file or directory"s) << msg;
        };
    };
};
