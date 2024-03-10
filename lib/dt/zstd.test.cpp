/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/file.hpp>
#include <dt/test.hpp>
#include <dt/zstd.hpp>

using namespace daedalus_turbo;

suite zstd_suite = [] {
    "zstd"_test = [] {
        static const uint8_vector orig { std::string_view { "some text\0\x11\xFE" } };
        uint8_vector compressed {};

        "compress"_test = [&] {
            zstd::compress(compressed, std::string_view { "" });
            expect(compressed.size() > 8_u);
            zstd::compress(compressed, orig);
            expect(compressed.size() > 8_u);
        };
        "decompress"_test = [&] {
            uint8_vector out {};
            zstd::decompress(out, compressed);
            expect(out == orig);
        };
        "stream_decompressor"_test = [] {
            zstd::stream_decompressor dec {};
            // the loop checks the reuse correctness
            for (size_t i=0; i < 10; ++i) {
                file::read_stream is { "./data/chunk-registry/compressed/chunk/9C5C0267DCA941851D0330E19B91712618EB6DB4BF17E458BCF00829F84CF3CF.zstd" };
                uint8_vector buf {};
                expect(dec.read_start(buf, is) == 42052372_ull);
                expect(buf.size() > 10) << buf.size();
            }
        };
        "errors"_test = [&] {
            uint8_vector out {};
            compressed.clear();
            expect(throws([&] { zstd::decompress(out, compressed); }));
            uint64_t orig_size = 0;
            compressed.resize(9);
            memcpy(compressed.data(), &orig_size, sizeof(orig_size));
            expect(throws([&] { zstd::decompress(out, compressed); }));
            zstd::compress(compressed, orig);
            *reinterpret_cast<uint64_t *>(compressed.data()) = orig.size() + 10;
            expect(throws([&] { zstd::decompress(out, compressed); }));
            *reinterpret_cast<uint64_t *>(compressed.data()) = orig.size();
            array<uint8_t, 11> buf_too_small {};
            expect(throws([&] { zstd::decompress(buf_too_small, compressed); }));
            array<uint8_t, 13> buf_too_big {};
            expect(throws([&] { zstd::decompress(buf_too_big, compressed); }));
        };
    };
};