/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_TRUNCATE_HPP
#define DAEDALUS_TURBO_CLI_TRUNCATE_HPP

#include <dt/cli.hpp>
#include <dt/validator.hpp>

namespace daedalus_turbo::cli::truncate {
    struct cmd: command {
        const command_info &info() const override
        {
            static const command_info i { "truncate", "<data-dir> <max-epoch>", "truncate the blockchain to the latest possible point before the end of epoch <max-epoch>" };
            return i;
        }

        void run(const arguments &args) const override
        {
            if (args.size() < 2) _throw_usage();
            const auto &data_dir = args.at(0);
            requirements::check(data_dir);
            const uint64_t epoch = std::stoull(args.at(1));
            validator::incremental idxr { validator::default_indexers(data_dir), data_dir };
            uint64_t min_offset = 0;
            for (const auto &[last_byte_offset, chunk]: idxr.chunks()) {
                if (chunk.last_slot.epoch() <= epoch && min_offset < last_byte_offset + 1)
                    min_offset = last_byte_offset + 1;
            }
            idxr.start_tx(min_offset, min_offset);
            idxr.prepare_tx();
            idxr.commit_tx();
            file_remover::get().remove();
        }
    };
}

#endif // !DAEDALUS_TURBO_CLI_DEBUG_TRUNCATE_HPP