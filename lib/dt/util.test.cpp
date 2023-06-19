/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <boost/ut.hpp>

#include <dt/util.hpp>

using namespace std::literals;
using namespace boost::ut;
using namespace daedalus_turbo;

suite util_suite = [] {
    "util"_test = [] {

        "error"_test = [] {
            auto my_throw = [] {
                errno = ENOENT;
                throw error_fmt("My Bad: {}!", "ABC");
            };
            expect(throws<error_fmt>(my_throw));
            std::string msg;
            try {
                my_throw();
            } catch (error_fmt &ex) {
                msg = ex.what();
            }
            expect(msg == "My Bad: ABC!"s) << msg;
        };

        "error_sys_fmt"_test = [] {
            auto my_throw = [] {
                errno = ENOENT;
                throw error_sys_fmt("My Bad: {}!", "ABC");
            };
            expect(throws<error_sys_fmt>(my_throw));
            std::string msg;
            try {
                my_throw();
            } catch (error_sys_fmt &ex) {
                msg = ex.what();
            }
            expect(msg == "My Bad: ABC!, errno: 2, strerror: No such file or directory"s) << msg;
        };
    };
};
