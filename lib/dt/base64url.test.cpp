/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>

#include <dt/base64url.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite base64url_suite = [] {
    "base64url"_test = [] {
        static std::vector<std::pair<std::string_view, uint8_vector>> test_vectors {
            { "-0Np4pyTOWF26iXWVIvu6fhz9QupwWRS2hcCaOEYlw0", bytes_from_hex("fb4369e29c93396176ea25d6548beee9f873f50ba9c16452da170268e118970d") },
            { "-0Np4pyTOWF26iXWVIvu6fhz9QupwWRS2hcCaOEYlw0=", bytes_from_hex("fb4369e29c93396176ea25d6548beee9f873f50ba9c16452da170268e118970d") },
            { "2pyVSDztfTSLEb8Cur4AjD9_WHhqgm-nY5_robtNnE4", bytes_from_hex("da9c95483ced7d348b11bf02babe008c3f7f58786a826fa7639feba1bb4d9c4e") },
            { "2pyVSDztfTSLEb8Cur4AjD9_WHhqgm-nY5_robtNnE4=", bytes_from_hex("da9c95483ced7d348b11bf02babe008c3f7f58786a826fa7639feba1bb4d9c4e") },
            { "JaoDbxwhRl7B9S1_s41dFgogEszb3zLoIiCCZehmw30", bytes_from_hex("25aa036f1c21465ec1f52d7fb38d5d160a2012ccdbdf32e822208265e866c37d") },
            { "JaoDbxwhRl7B9S1_s41dFgogEszb3zLoIiCCZehmw30=", bytes_from_hex("25aa036f1c21465ec1f52d7fb38d5d160a2012ccdbdf32e822208265e866c37d") }
        };
        for (const auto &[in, exp]: test_vectors) {
            auto out = base64url::decode(in);
            expect(out.size() == 32) << out.size();
            expect(out == exp) << out;
        }
    };
};
