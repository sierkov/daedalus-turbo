/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <span>
#include <boost/ut.hpp>
#include <dt/file.hpp>
#include <dt/kes.hpp>
#include <dt/util.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite kes_suite = [] {
    "kes"_test = [] {
        auto vkey_data = file::read("./data/kes-vkey.bin");
        auto sig_data = file::read("./data/kes-sig.bin");
        auto msg_data = file::read("./data/kes-msg.bin");
        "construct"_test = [&] {
            expect(boost::ut::nothrow([&]{ kes_signature<6> sig(sig_data); })) << "constructor failed";
        };
        "verify_ok"_test = [&] {
            kes_signature<6> sig(sig_data);
            expect(sig.verify(34, kes_vkey_span(vkey_data), msg_data)) << "key verification failed";
        };
        "verify_fail"_test = [&] {
            kes_signature<6> sig(sig_data);
            expect(!sig.verify(33, kes_vkey_span(vkey_data), msg_data));
            expect(!sig.verify(35, kes_vkey_span(vkey_data), msg_data));
            expect( throws([&] { !sig.verify(10035, kes_vkey_span(vkey_data), msg_data); }));
            auto msg2 = msg_data;
            msg2[0] = msg2[0] ^ msg2[1];
            expect(!sig.verify(34, kes_vkey_span(vkey_data), msg2));
            auto vkey2 = vkey_data;
            vkey2[0] = vkey2[0] ^ vkey2[1];
            expect(!sig.verify(34, kes_vkey_span(vkey2), msg_data));

            auto sig_data2 = sig_data;
            sig_data2[0] = sig_data2[0] ^ sig_data2[1];
            kes_signature<6> sig2(sig_data2);
            expect(!sig2.verify(34, kes_vkey_span(vkey_data), msg_data));
        };
    };
};