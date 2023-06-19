/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

extern "C" {
#   include <endian.h>
}

#include <span>
#include <boost/ut.hpp>
#include <dt/blake2b.hpp>
#include <dt/vrf.hpp>
#include <dt/util.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite vrf_suite = [] {
    "vrf-main"_test = [] {
        // vector 30 from C VRF library
        "verify_static_C_30"_test = [] {
            vrf_vkey vkey {0x5b,0x14,0xfd,0xe6,0xdb,0x37,0xa5,0x30,0x2f,0x01,0x50,0xa7,0x3f,0x6a,0xda,0x5a,0x05,0xa8,0x10,0xa2,0x4c,0x65,0x64,0x82,0xcb,0xde,0xb5,0x10,0x20,0xe9,0x2f,0xe7};
            vrf_proof proof {0x31,0xcd,0xab,0x62,0x0b,0xdf,0x82,0x31,0xab,0xce,0xe3,0x2d,0x61,0x5a,0xf3,0x46,0x49,0xe6,0x9b,0x13,0x22,0x86,0xcc,0x59,0xf9,0x50,0xf2,0x35,0x52,0x84,0xd9,0x53,0xa6,0xb7,0xea,0x97,0x5a,0x2f,0xd8,0x9a,0xf4,0x43,0xa1,0x5c,0x07,0x63,0x99,0xf3,0x90,0xc9,0x4a,0x6a,0xa3,0xf5,0xdb,0xf8,0xe1,0x57,0x67,0x80,0xa7,0xe1,0x6f,0xa4,0x8c,0x3a,0x09,0x59,0x72,0xac,0x3a,0xb1,0xe1,0xaa,0x07,0x6d,0x92,0x46,0xac,0x09};
            vrf_result res {0x15,0x2d,0xca,0x76,0x91,0x2d,0x4a,0x38,0x60,0x6f,0x46,0xd9,0x0d,0x4b,0x87,0x8b,0x3e,0x60,0xb9,0xce,0xf8,0x74,0x0e,0xf3,0x22,0x29,0x0f,0x18,0xa6,0x7a,0xd4,0x8e,0x71,0x6f,0x41,0x2e,0x70,0x13,0xd5,0xe1,0xee,0x4c,0x4a,0xaf,0x5e,0x7f,0x86,0xd1,0x58,0x24,0x9b,0xcd,0x06,0x7f,0x5e,0x62,0xb6,0x2c,0x25,0xb7,0x16,0x6b,0x94,0x29};
            std::array<uint8_t, 30> msg { 0x23, 0x0d, 0xd4, 0xc8, 0x55, 0xc1, 0x33, 0xc5, 0xb3, 0xc2, 0x4a, 0x72, 0xaf, 0x9b, 0xbb, 0xc4, 0x82, 0x05, 0x98, 0x4e, 0xa4, 0xf2, 0x04, 0x5f, 0xea, 0xac, 0x17, 0xfe, 0x1a, 0xf9 };
            expect(vrf03_verify(res, vkey, proof, msg)) << "VRF verification failed";
        };

        // vector 29 from Rust VRF library
        "verify_static_rust_1"_test = [] {
            auto vkey = bytes_from_hex("5ca0ed2b774adf3bae5e3e7da2f8ec877d9f063cc3d7050a6c49dfbbe2641dec");
            auto proof = bytes_from_hex("02180c447320b66012420971b70b448d11fead6d6e334c398f4daf01ccd92bfbcc4a8730a296ab33241f72da3c3a1fd53f1206a2b9f27ff6a5d9b8860fd955c39f55f9293ab58d1a2c18d555d2686101");
            auto result = bytes_from_hex("deb23fdc1267fa447fb087796544ce02b0580df8f1927450bed0df134ddc3548075ed48ffd72ae2a9ea65f79429cfbe2e15b625cb239ad0ec3910003765a8eb3");
            auto msg = bytes_from_hex("fc9f719740f900ee2809f6fdcf31bb6f096f0af133c604a27aaf85379c");
            expect(vrf03_verify(result, vkey, proof, msg)) << "VRF verification failed";
        };

        // Test vectors from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03#page-40

        "verify_static_ietf_1"_test = [] {
            auto vkey = bytes_from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
            auto proof = bytes_from_hex("b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900");
            auto result = bytes_from_hex("5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc");
            auto msg = bytes_from_hex("");
            expect(vrf03_verify(result, vkey, proof, msg)) << "VRF verification failed";
        };

        "verify_static_ietf_2"_test = [] {
            auto vkey = bytes_from_hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
            auto proof = bytes_from_hex("ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07");
            auto result = bytes_from_hex("94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8");
            auto msg = bytes_from_hex("72");
            expect(vrf03_verify(result, vkey, proof, msg)) << "VRF verification failed";
        };

        "verify_static_ietf_3"_test = [] {
            auto vkey = bytes_from_hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
            auto proof = bytes_from_hex("dfa2cba34b611cc8c833a6ea83b8eb1bb5e2ef2dd1b0c481bc42ff36ae7847f6ab52b976cfd5def172fa412defde270c8b8bdfbaae1c7ece17d9833b1bcf31064fff78ef493f820055b561ece45e1009");
            auto result = bytes_from_hex("2031837f582cd17a9af9e0c7ef5a6540e3453ed894b62c293686ca3c1e319dde9d0aa489a4b59a9594fc2328bc3deff3c8a0929a369a72b1180a596e016b5ded");
            auto msg = bytes_from_hex("af82");
            expect(vrf03_verify(result, vkey, proof, msg)) << "VRF verification failed";
        };
        
    };
};
