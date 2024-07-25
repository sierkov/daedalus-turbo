/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/cli.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/sync/turbo.hpp>

namespace daedalus_turbo::cli::node_export {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "node-export";
            cmd.desc = "export blockchain data and state from <data-dir> in Cardano Node's format to <node-dir>";
            cmd.args.expect({ "<data-dir>", "<node-dir>" });
            cmd.opts.try_emplace("ledger-only", "export only the ledger state");
        }

        void run(const arguments &args, const options &opts) const override
        {
            const auto &data_dir = args.at(0);
            const std::filesystem::path node_dir { args.at(1) };
            chunk_registry cr { data_dir };
            if (const auto tip = cr.tip(); tip) {
                cr.node_export(node_dir, opts.contains("ledger-only"));
                logger::info("exported state for the tip: {}", tip);
            } else {
                logger::warn("the chain is empty - nothing to export!");
            }
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}