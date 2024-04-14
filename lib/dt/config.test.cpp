/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <cstdlib>
#include <dt/config.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

namespace {
    static void my_setenv(const char *name, const char *val)
    {
        if (name == nullptr)
            throw error("my_setenv: name cannot be null!");
#if _WIN32
        std::string putexpr { fmt::format("{}={}", name, val != nullptr ? val : "") };
        putenv(putexpr.c_str());
#else
        if (val != nullptr)
            setenv(name, val, 1);
        else
            unsetenv(name);
#endif
    }
}

suite config_suite = [] {
    "config"_test = [] {
        "required"_test = [] {
            const auto &cfg = configs::get();
            expect(cfg.at("turbo").at("vkey").as_string() == std::string_view { "F961D8754397FA2C39D69C97D598566A5E03C34E40FF71DB792E103380E7C105" });
            expect(cfg.at("cardano").at("networkMagic").as_int64() == 764824073_ll);
        };
        "non-standard-location"_test = [] {
            expect(std::getenv("DT_ETC") == nullptr);
            expect(configs::default_path() == "./etc");
            my_setenv("DT_ETC", "./etc-missing");
            expect(std::getenv("DT_ETC") != nullptr);
            expect(configs::default_path() == "./etc-missing") << configs::default_path();
            expect(throws([] { configs cfg { configs::default_path() }; }));
            my_setenv("DT_ETC", nullptr);
            expect(std::getenv("DT_ETC") == nullptr);
        };
    };
};