/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/genesis.hpp>
#include <dt/cardano/type.hpp>
#include <dt/base64.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::cardano;

suite cardano_genesis_suite = [] {
    "cardano::genesis"_test = [] {
        "load genesis"_test = [] {
            genesis::configs cfg { "./etc/genesis" };
            {
                auto exp_hash = blake2b_256_hash::from_hex("DBBDAEAB0EA4EA58225892D8B1294F178B417F4A9D1ED3BBF629C40D8F74E86B");
                const auto &byron = cfg.at("byron");
                const auto &act_hash = byron.hash();
                expect(exp_hash == act_hash) << fmt::format("{}", act_hash);
                static std::set<cardano::vkey> known_issuers {
                    cardano::vkey::from_hex("0BDB1F5EF3D994037593F2266255F134A564658BB2DF814B3B9CEFB96DA34FA9"),
                    cardano::vkey::from_hex("1BC97A2FE02C297880CE8ECFD997FE4C1EC09EE10FEEEE9F686760166B05281D"),
                    cardano::vkey::from_hex("26566E86FC6B9B177C8480E275B2B112B573F6D073F9DEEA53B8D99C4ED976B3"),
                    cardano::vkey::from_hex("50733161FDAFB6C8CB6FAE0E25BDF9555105B3678EFB08F1775B9E90DE4F5C77"),
                    cardano::vkey::from_hex("993A8F056D2D3E50B0AC60139F10DF8F8123D5F7C4817B40DAC2B5DD8AA94A82"),
                    cardano::vkey::from_hex("9A6FA343C8C6C36DE1A3556FEB411BFDF8708D5AF88DE8626D0FC6BFA4EEBB6D"),
                    cardano::vkey::from_hex("D2965C869901231798C5D02D39FCA2A79AA47C3E854921B5855C82FD14708915"),
                };
                for (const auto &[deleg_id, deleg_info]: byron.at("heavyDelegation").as_object()) {
                    auto issuer_key = base64::decode(deleg_info.at("issuerPk").as_string());
                    expect(known_issuers.contains(issuer_key.span().subspan(0, 32))) << fmt::format("{}", issuer_key);
                }
            }
            {
                auto exp_hash = blake2b_256_hash::from_hex("1A3BE38BCBB7911969283716AD7AA550250226B76A61FC51CC9A9A35D9276D81");
                const auto &act_hash = cfg.at("shelley").hash();
                expect(exp_hash == act_hash) << fmt::format("{}", act_hash);
            }
            {
                auto exp_hash = blake2b_256_hash::from_hex("7E94A15F55D1E82D10F09203FA1D40F8EEDE58FD8066542CF6566008068ED874");
                const auto &act_hash = cfg.at("alonzo").hash();
                expect(exp_hash == act_hash) << fmt::format("{}", act_hash);
            }
            {
                auto exp_hash = blake2b_256_hash::from_hex("F7D46BDD3B3C8CAF38351C4EEF3346A89241707270BE0D6106E8A407DB294CC6");
                const auto &act_hash = cfg.at("conway").hash();
                expect(exp_hash == act_hash) << fmt::format("{}", act_hash);
            }
        };
    };  
};