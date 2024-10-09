/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/plutus/uplc.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::plutus;
using namespace daedalus_turbo::plutus::uplc;

suite plutus_uplc_suite = [] {
    "plutus::uplc"_test = [] {
        "conformance scripts"_test = [&] {
            const auto paths = file::files_with_ext(install_path("./data/plutus/conformance"), ".uplc");
            size_t ok = 0;
            for (const auto &path: paths) {
                try {
                    allocator alloc {};
                    script s { alloc, file::read(path.string()) };
                    ++ok;
                } catch (...) {
                    const auto exp_path = (path.parent_path() / (path.stem().string() + ".uplc.expected")).string();
                    if (std::filesystem::exists(exp_path)) {
                        const std::string exp_res { file::read(exp_path).str() };
                        if (exp_res == "parse error") {
                            ++ok;
                            continue;
                        }
                    }
                    logger::error("{}: parse failed", path);
                }
            }
            test_same(paths.size(), ok);
        };
    };
};