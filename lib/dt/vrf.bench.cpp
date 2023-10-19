/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/benchmark.hpp>
#include <dt/util.hpp>
#include <dt/vrf.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite vrf_bench_suite = [] {
    "vrf"_test = [] {
        auto vkey = bytes_from_hex("5ca0ed2b774adf3bae5e3e7da2f8ec877d9f063cc3d7050a6c49dfbbe2641dec");
        auto proof = bytes_from_hex("02180c447320b66012420971b70b448d11fead6d6e334c398f4daf01ccd92bfbcc4a8730a296ab33241f72da3c3a1fd53f1206a2b9f27ff6a5d9b8860fd955c39f55f9293ab58d1a2c18d555d2686101");
        auto result = bytes_from_hex("deb23fdc1267fa447fb087796544ce02b0580df8f1927450bed0df134ddc3548075ed48ffd72ae2a9ea65f79429cfbe2e15b625cb239ad0ec3910003765a8eb3");
        auto msg = bytes_from_hex("fc9f719740f900ee2809f6fdcf31bb6f096f0af133c604a27aaf85379c");
        benchmark_r("vrf/verify", 2000.0, 2000,
            [&] {
                vrf03_verify(result, vkey, proof, msg);
            }
        );
    };
};