/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/plutus/machine.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::plutus;

suite plutus_machine_suite = [] {
    "plutus::machine"_test = [] {
        machine m {};
        for (auto &entry: std::filesystem::directory_iterator("./data/plutus/machine")) {
            const auto script_path = entry.path().string();
            if (entry.is_regular_file() && entry.path().extension().string() == ".hex") {
                const auto cbor = uint8_vector::from_hex(file::read(script_path).str());
                const auto res_path = fmt::format("{}.res", (entry.path().parent_path() / entry.path().stem()).string());
                const std::string exp_res { file::read(res_path).str() };
                script s { cbor };
                const auto res = fmt::format("{}", m.evaluate(s, term_list {}));
                expect(res == exp_res) << res;
            }
        }
    };
};