/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/json.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite json_suite = [] {
    "json"_test = [] {
        "load genesis"_test = [] {
            auto genesis = json::load("./etc/genesis/mainnet-shelley-genesis.json");
            expect(genesis.at("genDelegs").as_object().size() == 7_u);
        };
    };  
};