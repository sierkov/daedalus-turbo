/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/type.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::cardano;

suite cardano_type_test = [] {
    "cardano"_test = [] {
        "address_buf"_test = [] {
            address_buf addr1 { "0xDEADBEAF" };
            expect(addr1.size() == 4_u);
            expect(addr1[0] == 0xDE);
            expect(addr1[1] == 0xAD);
            expect(addr1[2] == 0xBE);
            expect(addr1[3] == 0xAF);

            uint8_t exp[] = {
                0xf1, 0xc3, 0x7b, 0x1b, 0x5d, 0xc0, 0x66, 0x9f, 0x1d, 0x3c, 0x61, 0xa6, 0xfd, 0xdb, 0x2e, 0x8f,
                0xde, 0x96, 0xbe, 0x87, 0xb8, 0x81, 0xc6, 0x0b, 0xce, 0x8e, 0x8d, 0x54, 0x2f
            };
            address_buf addr2 { "stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5" };
            expect(addr2.size() == sizeof(exp));
            expect(memcmp(addr2.data(), exp, sizeof(exp)) == 0_i);
        };
    };
};