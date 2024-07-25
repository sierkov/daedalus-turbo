/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/cli.hpp>
#include <dt/sync/hybrid.hpp>

namespace daedalus_turbo::cli::maintenance {
    using namespace daedalus_turbo::sync;

    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "maintenance";
            cmd.desc = "ensure that the blockchain data, indices and the ledger state are in agreement with each other";
            cmd.args.expect({ "<data-dir>" });
        }

        void run(const arguments &args, const options &opts) const override
        {
            const auto &data_dir = args.at(0);
            cardano::optional_slot max_slot {};
            if (const auto opt_it = opts.find("max-slot"); opt_it != opts.end() && opt_it->second)
                max_slot = std::stoull(*opt_it->second);
            chunk_registry cr { data_dir };
            cr.maintenance();
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}