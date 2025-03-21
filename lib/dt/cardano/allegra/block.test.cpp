/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/common/test.hpp>
#include <dt/plutus/context.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::cardano;

suite cardano_allegra_suite = [] {
    "cardano::allegra"_test = [] {
        "native scripts"_test = [] {
            const configs_dir cfg { configs_dir::default_path() };
            const cardano::config ccfg { cfg };
            ccfg.shelley_start_epoch(208);
            for (const auto &path: file::files_with_ext_str(install_path("data/allegra"), ".zpp")) {
                const plutus::context ctx { path, ccfg };
                const auto wit_cnts = ctx.tx().witnesses_ok();
                test_same(true, wit_cnts);
            }
        };
    };
};