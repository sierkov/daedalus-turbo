/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <boost/ut.hpp>
#include <dt/index-type.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite index_type_suite = [] {
    "index_type"_test = [] {
        "pack_tx_size"_test = [] {
            expect(pack_tx_size(0) == 0);
            expect(pack_tx_size(55) == 1);
            expect(pack_tx_size(256) == 1);
            expect(pack_tx_size(512) == 2);
            expect(pack_tx_size(600) == 3);
            expect(pack_tx_size(16384) == 64);
            expect(pack_tx_size(16385) == 65);
            expect(pack_tx_size(32768) == 128);
            expect(pack_tx_size(32769) == 129);
        };
        "unpack_tx_size"_test = [] {
            expect(unpack_tx_size(0) == 0);
            expect(unpack_tx_size(1) == 256);
            expect(unpack_tx_size(2) == 512);
            expect(unpack_tx_size(64) == 16384);
        };
        "pack_offset"_test = [] {
            {
                uint8_t tx_off[5];
                pack_offset(tx_off, sizeof(tx_off), 0xAADEADBEAF);
                expect(tx_off[0] == 0xAA);
                expect(tx_off[1] == 0xDE);
                expect(tx_off[2] == 0xAD);
                expect(tx_off[3] == 0xBE);
                expect(tx_off[4] == 0xAF);
            }
            {
                uint8_t exp[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00 };
                uint8_t tx_off[8];
                pack_offset(tx_off, sizeof(tx_off), 2048);
                expect(memcmp(exp, tx_off, sizeof(tx_off)) == 0);
            }
        };
        "unpack_offset"_test = [] {
            {
                uint8_t tx_off[5] = { 0xAA, 0xDE, 0xAD, 0xBE, 0xAF };
                pack_offset(tx_off, sizeof(tx_off), 0xAADEADBEAF);
                expect(unpack_offset(tx_off, sizeof(tx_off)) == 0xAADEADBEAF);
            }
            {
                uint8_t tx_off[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00 };
                expect(unpack_offset(tx_off, sizeof(tx_off)) == 2048);
            }
        };
    };
};
