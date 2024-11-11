/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/file.hpp>
#include <dt/plutus/flat-encoder.hpp>
#include <dt/plutus/uplc.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::plutus;
using namespace daedalus_turbo::plutus::flat;

namespace {
    std::string stringify_diff(const buffer b1, const buffer b2)
    {
        std::string res {};
        auto out_it = std::back_inserter(res);
        if (b1.size() != b2.size())
            out_it = fmt::format_to(out_it, "sizes mismatch: {} vs {}\n", b1.size(), b2.size());
        const auto min_sz = std::min(b1.size(), b2.size());
        for (size_t i = 0; i < min_sz; ++i) {
            if (b1[i] != b2[i]) {
                out_it = fmt::format_to(out_it, "diff at byte {}: {:02x} != {:02x}\n", i, b1[i], b2[i]);
            }
        }
        return res;
    }

    void test_flat(const std::string &path)
    {
        auto cbor = file::read(path);
        if (path.ends_with(".hex")) {
            cbor = uint8_vector::from_hex(cbor.str());
        }
        const uint8_vector wo_cbor { cbor::zero::parse(cbor).bytes() };
        allocator alloc {};
        const script s { alloc, cbor };
        const auto new_cbor = encode(s.version(), s.program());
        if (!test_same(path, wo_cbor, new_cbor)) {
            logger::warn("{}", stringify_diff(wo_cbor, new_cbor));
        }
    }

    void test_uplc_code(const std::string &path, const buffer code)
    {
        try {
            allocator alloc {};
            const uplc::script s_uplc { alloc, code };
            const auto cbor = encode_cbor(s_uplc.version(), s_uplc.program());
            const script s_flat { alloc, cbor };
            test_same(path, s_uplc.version(), s_flat.version());
            test_same(path, s_uplc.program(), s_flat.program());
        } catch (const std::exception &ex) {
            if (!std::string { ex.what() } .starts_with("bls12"))
                expect(false) << path << "exception:" << ex.what();
        }
    }

    void test_uplc_code(const std::string &code)
    {
        test_uplc_code(code, buffer { code });
    }

    void test_uplc(const std::string &path)
    {
        test_uplc_code(path, file::read(path));
    }
}

suite plutus_flat_encoder_suite = [] {
    "plutus::flat_encoder"_test = [] {
        test_uplc_code("(program 1.0.0 (con (list (pair data data)) []))");
        test_flat("./data/plutus/script-v2/ECA13DA17F28EB51D7D90D2D16E95A39C21655DA130893A48997A38B.bin");
        "terms"_test = [] {
            for (const auto &path: file::files_with_ext("./data/plutus/conformance", ".uplc")) {
                const auto exp_path = (path.parent_path() / path.stem()).string() + ".uplc.expected";
                if (file::read(exp_path).str() != "parse error")
                    test_uplc(path.string());
            }
        };
        "conformance"_test = [] {
            for (const auto &path: file::files_with_ext_str("./data/plutus/term", ".hex")) {
                test_flat(path);
            }
        };
        "scripts"_test = [] {
            for (const auto &path: file::files_with_ext_str("./data/plutus/script-v2", ".bin")) {
                test_flat(path);
            }
        };
    };
};