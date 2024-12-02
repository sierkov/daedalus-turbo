/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/test.hpp>
#include <dt/zstd-stream.hpp>

using namespace daedalus_turbo;

suite zstd_stream_suite = [] {
    "zstd::stream"_test = [] {
        const auto test_path = install_path("data/chunk-registry/compressed/chunk/977E9BB3D15A5CFF5C5E48617288C5A731DB654C0B42D63627C690CEADC9E1F3.zstd");
        "decomress"_test = [&] {
            zstd::read_stream s { test_path };
            uint8_vector data {};
            uint8_vector buf(0x1000);
            for (;;) {
                const auto num_read = s.try_read(buf);
                data << buffer { buf.data(), num_read };
                if (num_read < buf.size())
                    break;
            }
            const auto hash = blake2b<blake2b_256_hash>(data);
            test_same(54206949, data.size());
            test_same(blake2b_256_hash::from_hex("977E9BB3D15A5CFF5C5E48617288C5A731DB654C0B42D63627C690CEADC9E1F3"), hash);
        };
        "empty buf"_test = [&] {
            zstd::read_stream s { test_path };
            uint8_vector data {};
            expect(throws([&]{ s.try_read(data); }));
        };
        "decompression error"_test = [&] {
            const file::tmp tmp { "zstd-stream-err.zstd" };
            file::write(tmp.path(), uint8_vector::from_hex("DEADBEAF"));
            zstd::read_stream s { tmp.path() };
            uint8_vector data(0x1000);
            expect(throws([&]{ s.try_read(data); }));
        };
    };
};