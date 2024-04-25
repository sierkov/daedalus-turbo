/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/logger.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite logger_suite = [] {
    "logger"_test = [] {
        "api"_test = [] {
            // checks that the code compiles and does not fail
            logger::trace("OK - trace");
            logger::trace("OK - {}", "trace");
            logger::debug("OK - debug");
            logger::debug("OK - {}", "debug");
            logger::info("OK - info");
            logger::info("OK - {}", "info");
            logger::warn("OK - warn");
            logger::warn("OK - {}", "warn");
            logger::error("OK - error");
            logger::error("OK - {}", "error");
            expect(true);
        };
        "run_and_log_errors"_test = [] {
            const auto ex1 = logger::run_log_errors([] { return true; });
            expect(!ex1);
            const auto ex2 = logger::run_log_errors([] { throw error("Something bad!"); });
            expect(static_cast<bool>(ex2));
        };
        "run_log_errors_and_rethrow"_test = [] {
            expect(nothrow([] { logger::run_log_errors_rethrow([] { return true; }); }));
            expect(throws([] { logger::run_log_errors_rethrow([] { throw error("Something bad!"); }); }));
        };
    };
};