/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/common/config.hpp>
#include <dt/cli.hpp>
#include <dt/plutus/flat.hpp>
#include <dt/plutus/machine.hpp>
#include <dt/plutus/uplc.hpp>

namespace daedalus_turbo::cli::plutus_parse {
    using namespace cardano;
    using namespace daedalus_turbo::plutus;

    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "plutus-decode";
            cmd.desc = "parse a Plutus script in the Flat format and print it as a UPLC";
            cmd.args.expect({ "<script-path>" });
            cmd.opts.try_emplace("cbor", "interpret the byte stream as a CBOR bytestring");
        }

        void run(const arguments &args, const options &opts) const override
        {
            allocator alloc {};
            flat::script s { alloc, file::read(args.at(0)), opts.contains("cbor") };
            fmt::print("{}\n", s.program());
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}