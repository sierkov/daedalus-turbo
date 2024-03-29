/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cbor-encoder.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite cbor_encoder_suite = [] {
    "cbor::encoder"_test = [] {
        cbor::encoder enc {};
        enc.bytes(std::string_view { "Hello" }).array(2)
            .uint(0)
            .map(1)
                .uint(7)
                .array(2)
                    .uint(764824073)
                    .s_false();
        auto act = enc.cbor();
        auto exp = uint8_vector::from_hex("4548656c6c6f8200A107821A2D964A09F4");
        expect(act == exp) << act;
    };
};