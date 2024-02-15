/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <string>
#include <string_view>
#include <tuple>
#include <boost/ut.hpp>
#include <dt/blake2b.hpp>
#include <dt/cbor.hpp>
#include <dt/ed25519.hpp>
#include <dt/file.hpp>
#include <dt/util.hpp>
#include <dt/cardano/byron.hpp>
#include <dt/cardano.hpp>

using namespace std::literals;
using namespace boost::ut;
using namespace daedalus_turbo;

namespace {
    inline std::tuple<uint8_t, size_t> from_haskell_char(const std::string_view sv)
    {
        static std::map<uint8_t, uint8_t> one_char_codes {
            { '0', 0x00 }, { 'a', 0x07 }, { 'b', 0x08 }, { 'f', 0x0C },
            { 'n', 0x0A }, { 'r', 0x0D }, { 't', 0x09 }, { 'v', 0x0B },
            { '"', 0x22 }, { '\'', 0x27 }, { '\\', 0x5C }
        };
        static std::map<std::string, uint8_t> multichar_codes {
            { "BS"s, 0x08 }, { "HT"s, 0x09 }, { "LF"s, 0x0A }, { "VT"s, 0x0B },
            { "FF"s, 0x0C }, { "CR"s, 0x0D }, { "SO"s, 0x0E }, { "SI"s, 0x0F },
            { "EM"s, 0x19 }, { "FS"s, 0x1C }, { "GS"s, 0x1D }, { "RS"s, 0x1E },
            { "US"s, 0x1F }, { "SP"s, 0x20 },
            
            // SO and SOH share the same prefix, so the resolution should go from longest to shortest matches!
            { "NUL"s, 0x00 }, { "SOH"s, 0x01 }, { "STX"s, 0x02 }, { "ETX"s, 0x03 },
            { "EOT"s, 0x04 }, { "ENQ"s, 0x05 }, { "ACK"s, 0x06 }, { "BEL"s, 0x07 },            
            { "DLE"s, 0x10 }, { "DC1"s, 0x11 }, { "DC2"s, 0x12 }, { "DC3"s, 0x13 },
            { "DC4"s, 0x14 }, { "NAK"s, 0x15 }, { "SYN"s, 0x16 }, { "ETB"s, 0x17 },
            { "CAN"s, 0x18 }, { "SUB"s, 0x1A }, { "ESC"s, 0x1B }, { "DEL"s, 0x7F }
        };
        if (sv[0] >= '1' && sv[0] <= '9') {
            auto end = sv.find_first_not_of("0123456789"sv);
            if (end == std::string_view::npos) end = sv.size();
            std::string text { sv.substr(0, end) };
            uint8_t byte = std::stoul(text);
            return std::make_tuple(byte, end);
        } else if (sv[0] >= 'A' && sv[0] <= 'Z') {
            for (size_t n_chars = sv.size() > 3 ? 3 : sv.size(); n_chars >= 1; --n_chars) {
                std::string text { sv.substr(0, n_chars) };
                auto it = multichar_codes.find(text);
                if (it != multichar_codes.end()) {
                    return std::make_tuple(it->second, n_chars);
                }
            }
            throw error("Unsupported escape sequence starting with {}!", sv);
        } else {
            auto it = one_char_codes.find(sv[0]);
            if (it != one_char_codes.end()) {
                return std::make_tuple(it->second, 1);
            }
            throw error("Escape sequence starts from an unsupported character: '{}' code {}!", sv[0], (int)sv[0]);
        }
    }

    inline uint8_vector from_haskell(const std::string_view sv)
    {
        uint8_vector bytes;
        for (size_t i = 0; i < sv.size(); ++i) {
            if (sv[i] != '\\') {
                bytes.push_back(sv[i]);
            } else if (i + 1 < sv.size()) {
                if (sv[i + 1] != '&') {
                    const auto [byte, extra_size] = from_haskell_char(sv.substr(i + 1));
                    bytes.push_back(byte);
                    i += extra_size;
                } else {
                    // empty string, just skip it
                    i += 1;
                }
            }
        }
        return bytes;
    }
}

suite cardano_byron_suite = [] {
    "cardano::byron"_test = [] {
        "match slot 1 data"_test = [] {
            // dlgsig.dlg.delegate
            auto cbor_vkey_full = bytes_from_hex("e8c03a03c0b2ddbea4195caf39f41e669f7d251ecf221fbb2f275c0a5d7e05d190dcc246f56c8e33ac0037066e2f664ddaa985ea5284082643308dde4f5bfedf");
            auto cbor_vkey = buffer(cbor_vkey_full.data(), 32);
            // dlgsig.signature
            auto cbor_sig = bytes_from_hex("923c7714af7fe4b1272fc042111ece6fd08f5f16298d62bae755c70c1e1605697cbaed500e196330f40813128250d9ede9c8557b33f48e8a5f32f765929e4a0d");
            auto trace_vkey = from_haskell("\\232\\192:\\ETX\\192\\178\\221\\190\\164\\EM\\\\\\175\\&9\\244\\RSf\\159}%\\RS\\207\\\"\\US\\187/'\\\\\\n]~\\ENQ\\209"sv);
            auto trace_sig = from_haskell("\\146<w\\DC4\\175\\DEL\\228\\177'/\\192B\\DC1\\RS\\206o\\208\\143_\\SYN)\\141b\\186\\231U\\199\\f\\RS\\SYN\\ENQi|\\186\\237P\\SO\\EMc0\\244\\b\\DC3\\DC2\\130P\\217\\237\\233\\200U{3\\244\\142\\138_2\\247e\\146\\158J\\r"sv);
            expect(cbor_vkey.size() == trace_vkey.size()) << cbor_vkey.size() << "!=" << trace_vkey.size();
            expect(cbor_sig.size() == trace_sig.size()) << cbor_sig.size() << "!=" << trace_sig.size();
            expect(cbor_vkey == trace_vkey) << cbor_vkey << "!=" << trace_vkey;
            expect(cbor_sig == trace_sig) << cbor_sig << "!=" << trace_sig;
        };

        "block signature validation for slot 1"_test = [] {
            auto vkey = from_haskell("\\232\\192:\\ETX\\192\\178\\221\\190\\164\\EM\\\\\\175\\&9\\244\\RSf\\159}%\\RS\\207\\\"\\US\\187/'\\\\\\n]~\\ENQ\\209"sv);
            auto msg = from_haskell("01Ps1a\\253\\175\\182\\200\\203o\\174\\SO%\\189\\249UQ\\ENQ\\179g\\142\\251\\b\\241w[\\158\\144\\222O\\\\w\\188\\200\\206\\255\\248\\217\\SOH\\FS\\178x\\178\\143\\221\\200m\\155\\171\\t\\150V\\215zxV\\199a\\145\\b\\203\\246WR\\t\\SUB-\\150J\\t\\133X \\240\\247\\137+\\\\3<\\255\\196\\179\\196\\&4M\\228\\138\\244\\204c\\245^D\\147a\\150\\243e\\169\\239\\\"D\\DC3O\\132\\131\\NULX \\SOWQ\\192&\\229C\\178\\232\\171.\\176`\\153\\218\\161\\209\\229\\223Gw\\143w\\135\\250\\171E\\205\\241/\\227\\168X \\175\\192\\218d\\CAN;\\242fO=N\\236r8\\213$\\186`\\DEL\\174\\234\\178O\\193\\NUL\\235\\134\\GS\\186i\\151\\ESC\\131\\NULX %wz\\202\\158Js\\212\\143\\199;O\\150\\GS4[\\ACK\\212\\166\\243I\\203y\\SYNW\\r5S}SG\\159X \\211j&\\EM\\166rIF\\EOT\\225\\ESC\\180G\\203\\207R1\\233\\242\\186%\\194\\SYN\\145w\\237\\201A\\189P\\173lX \\175\\192\\218d\\CAN;\\242fO=N\\236r8\\213$\\186`\\DEL\\174\\234\\178O\\193\\NUL\\235\\134\\GS\\186i\\151\\ESCX Nf(\\f\\217MY\\DLEr4\\155\\236\\n0\\144\\165:\\169EV.\\251m\\b\\213nSeK\\SO@\\152\\130\\NUL\\SOH\\129\\STX\\132\\131\\NUL\\NUL\\NUL\\130jcardano-sl\\NUL\\160X K\\169*\\163 \\198\\n\\204\\154\\215\\185\\166O.\\218U\\196\\210\\236(\\230\\EOT\\250\\241\\134p\\139O\\fN\\142\\223"sv);
            auto sig = from_haskell("\\146<w\\DC4\\175\\DEL\\228\\177'/\\192B\\DC1\\RS\\206o\\208\\143_\\SYN)\\141b\\186\\231U\\199\\f\\RS\\SYN\\ENQi|\\186\\237P\\SO\\EMc0\\244\\b\\DC3\\DC2\\130P\\217\\237\\233\\200U{3\\244\\142\\138_2\\247e\\146\\158J\\r"sv);
            expect(vkey.size() == 32);
            expect(sig.size() == 64);
            expect(ed25519::verify(sig, vkey, msg));
        };

        "validate signature based from block CBOR"_test = [] {
            auto buf = file::read("./data/block-slot-1.bin");
            cbor_parser parser(buf);
            cbor_value block_raw;
            parser.read(block_raw);
            auto blk = cardano::make_block(block_raw, 0);
            auto &byron_blk = dynamic_cast<cardano::byron::block &>(*blk);
            auto msg = byron_blk.make_signed_data();
            const auto signature = byron_blk.signature();
            auto vkey = signature.delegate_vkey();
            auto sig = signature.signature();
            expect(ed25519::verify(sig, vkey, msg));
            expect(byron_blk.signature_ok());
        };

        "block signature validation - cardano test vector A0"_test = [] {
            auto msg = bytes_from_hex("011a2d964a095820a2dbee7247273125ea1c3b9f140d2ea370c705b55e03c36d8d60c6535920f9c6"sv);
            auto sig = bytes_from_hex("a2fc141c749d04e02a63a7df131d0bb1f47027801e1c22bc76cb9792d29ff0936c02666ac8e38347d02a7bfa13bd6cfada31d76087e754103eaf2e6dbf5d020b"sv);
            auto vkey_full = bytes_from_hex("3dd06d2f961b922192529557eb59ad93fcca5e751a816a34808232852b3decfc27ef927dbccf4c0dc8de6b854871cf7b6d88bf18984cb2fc7c49f39aecb97db0"sv);
            auto vkey = buffer(vkey_full.data(), 32);
            expect(ed25519::verify(sig, vkey, msg));
        };

        "block signature validation - cardano test vector A1"_test = [] {
            auto msg = bytes_from_hex("011a2d964a095820a2dbee7247273125ea1c3b9f140d2ea370c705b55e03c36d8d60c6535920f9c6"sv);
            auto sig = bytes_from_hex("e02e78a5184ed787160afa1637b6f39f74bbadd4f8cf5eb8ba7e306ab616409fe65b1f893b7784535b26f81bfd4a01cfbcb840664ab1764b3bae420954dadc06"sv);
            auto vkey_full = bytes_from_hex("34651bf3ef0b455f50d0db2a9f6e6446c2c5e2ce56ea796657aa01790ab552d105d5b7b8f544d892d52c46ce820048dec6e68e6e08c55ec566cb1207eb5a1cff"sv);
            auto vkey = buffer(vkey_full.data(), 32);
            expect(ed25519::verify(sig, vkey, msg));
        };

        "block signature validation - cardano test vector A2"_test = [] {
            auto msg = bytes_from_hex("011a2d964a095820a2dbee7247273125ea1c3b9f140d2ea370c705b55e03c36d8d60c6535920f9c6"sv);
            auto sig = bytes_from_hex("562ea76122fab1b0157c0522f027967765135c381706fc042e58abe4b68c545a8486ed6799d3309de3189481569e378c87ae080e5c94ada19308f167b0520e01"sv);
            auto vkey_full = bytes_from_hex("901326c5174cb72bd58852a6e3d5d5062bfb43a15551bd38335c5e44486a2aaf87aa927b7e117d9729284c6885cdd378e2613bb0b4362e837aa399a34d384bd6"sv);
            auto vkey = buffer(vkey_full.data(), 32);
            expect(ed25519::verify(sig, vkey, msg));
        };

        "block signature validation - cardano test vector A3"_test = [] {
            auto msg = bytes_from_hex("011a2d964a095820a2dbee7247273125ea1c3b9f140d2ea370c705b55e03c36d8d60c6535920f9c6"sv);
            auto sig = bytes_from_hex("f7f5863db6794e3fc6d2b55799c8d398bb76ff95cb045a2c765f2a591ccd3c96ade745f874b806554aca4676b78f309496b28851b9afe5ed6b90e3e4ddcee501"sv);
            auto vkey_full = bytes_from_hex("4b74a06bcb73309388b61daf0687ca66811d4dc2ca657cb7ded31fe5c4698e02413ef6845df77b3461da601348710be44572c7df5b2445a92cf0072005847494"sv);
            auto vkey = buffer(vkey_full.data(), 32);
            expect(ed25519::verify(sig, vkey, msg));
        };

        "boundary block hash"_test = [] {
            auto genesis_hash = bytes_from_hex("5F20DF933584822601F9E3F8C024EB5EB252FE8CEFB24D1317DC3D432E940EBB");
            auto hash = bytes_from_hex("89D9B5A5B8DDC8D7E5A6795E9774D97FAF1EFEA59B2CAF7EAF9F8C5B32059DF4");
            auto chunk = file::read("./data/chunk-registry/compressed/immutable/526D236112DB8E38E66F37D330C85AFE0C268D81DF853DDDE4E88551EB9B0637.zstd");
            cbor_parser parser { chunk };
            cbor_value block_tuple {};
            parser.read(block_tuple);
            expect(block_tuple.array().at(0).uint() == 0_ull);
            auto blk = cardano::make_block(block_tuple, 0);
            expect(blk->slot() == 0_ull);
            expect(blk->prev_hash() == genesis_hash);
            expect(blk->hash() == hash);
        };
    };  
};
