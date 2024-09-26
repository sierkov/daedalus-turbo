/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/plutus/costs.hpp>
#include <dt/plutus/machine.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::plutus;
using namespace daedalus_turbo::plutus::costs;

suite plutus_costs_suite = [] {
    "plutus::costs"_test = [] {
        "defaults"_test = [&] {
            // The cost functions are tested exhaustively in the plutus::machine unit test where
            // the plutus conformance test is run and the evaluation costs are compared.
            // This file is just a simple test the mimimum API works to not introduce redundancies
            const auto &defs = defaults().v3.value();
            const auto &div = defs.at(builtin_tag::divide_integer);
            test_same(131930, div.cpu->cost(arg_sizes { 1, 1 }, {}));
            test_same(1, div.mem->cost(arg_sizes { 1, 1 }, {}));
        };
    };
};