/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <boost/ut.hpp>
#include <dt/cardano/genesis.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;
using namespace daedalus_turbo::cardano;

suite cardano_genesis_suite = [] {
    "cardano::genesis"_test = [] {
        "load genesis"_test = [] {
            genesis::configs cfg { "./etc/genesis" };
            {
                auto exp_hash = blake2b_256_hash::from_hex("DBBDAEAB0EA4EA58225892D8B1294F178B417F4A9D1ED3BBF629C40D8F74E86B");
                const auto &act_hash = cfg.at("byron").hash();
                expect(exp_hash == act_hash) << fmt::format("{}", act_hash);
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