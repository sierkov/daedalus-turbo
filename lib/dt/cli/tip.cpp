/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/cli.hpp>
#include <dt/chunk-registry.hpp>

namespace daedalus_turbo::cli::tip {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "tip";
            cmd.desc = "show the the last validated block and perform maintenance if necessary";
            cmd.args.expect({ "<data-dir>" });
        }

        void run(const arguments &args) const override
        {
            const auto &data_dir = args.at(0);
            chunk_registry cr { data_dir };
            if (const auto last_block = cr.last_block(); last_block)
                logger::info("the local tip: {} {}", cr.make_slot(last_block->slot), last_block->hash);
            else
                logger::info("the local chain is empty");
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}