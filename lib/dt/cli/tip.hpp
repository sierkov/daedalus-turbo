/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_TIP_HPP
#define DAEDALUS_TURBO_CLI_TIP_HPP

#include <dt/cli.hpp>
#include <dt/validator.hpp>

namespace daedalus_turbo::cli::tip {
    struct cmd: command {
        const command_info &info() const override
        {
            static const command_info i { "tip", "<data-dir>", "show the the last validated block and perform maintenance if necessary" };
            return i;
        }

        void run(const arguments &args) const override
        {
            if (args.size() < 1) _throw_usage();
            const auto &data_dir = args.at(0);
            validator::incremental cr { data_dir };
            if (const auto target_offset = cr.valid_end_offset(); target_offset != cr.max_end_offset()) {
                logger::warn("chain is not in a consistent state, performing maintenance ...");
                cr.truncate(target_offset);
                cr.remover().remove();
            }
            if (const auto last_block = cr.last_block(); last_block)
                logger::info("the local tip: {} {}", last_block->slot, last_block->hash);
            else
                logger::info("the local chain is empty");
        }
    };
}

#endif // !DAEDALUS_TURBO_CLI_TIP_HPP