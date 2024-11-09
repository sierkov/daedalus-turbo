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
            allocator alloc {};
            const auto &v3 = defaults().v3.value();
            {
                const auto &div = v3.builtin_fun.at(builtin_tag::divide_integer);
                value_list empty { alloc };
                test_same(131930, div.cpu->cost(arg_sizes { 1, 1 }, empty));
                test_same(1, div.mem->cost(arg_sizes { 1, 1 }, empty));
            }
            const auto &v2 = defaults().v2.value();
            {
                const auto &b = v2.builtin_fun.at(builtin_tag::equals_data);
                const value arg1 { alloc, data::constr(alloc, 0, { data::constr(alloc, 1, { data::bstr(alloc, uint8_vector::from_hex("AABB")) }) }) };
                const value arg2 { alloc, data::constr(alloc, 0, { data::constr(alloc, 1, { data::bstr(alloc, uint8_vector::from_hex("DDDD")) }) }) };
                value_list args { alloc, { arg1, arg2 } };
                arg_sizes sizes { machine::mem_usage(args->at(0)), machine::mem_usage(args->at(1)) };
                test_same(13, sizes.at(0));
                test_same(13, sizes.at(1));
                test_same(1252775, b.cpu->cost(sizes, args));
                test_same(1, b.mem->cost(sizes, args));
            }
        };
    };
};