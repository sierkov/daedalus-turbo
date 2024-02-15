/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_TRUNCATE_HPP
#define DAEDALUS_TURBO_CLI_TRUNCATE_HPP

#include <dt/cli.hpp>
#include <dt/validator.hpp>

namespace daedalus_turbo::cli::truncate {
    struct cmd: public command {
        const command_info &info() const override
        {
            static const command_info i { "truncate", "<data-dir> <max-epoch>", "truncate the blockchain to the last block of the epoch <max-epoch>" };
            return i;
        }

        void run(const arguments &args) const override
        {
            if (args.size() < 2) _throw_usage();
            const auto &data_dir = args.at(0);
            requirements::check(data_dir);
            const uint64_t epoch = std::stoull(args.at(1));
            scheduler sched {};
            auto indexers = validator::default_indexers(sched, data_dir);
            validator::incremental idxr { sched, data_dir, indexers };
            idxr.init_state();
            uint64_t min_offset = 0;
            for (const auto &[last_byte_offset, chunk]: idxr.chunks()) {
                    if (chunk.last_slot.epoch() <= epoch && min_offset < last_byte_offset + 1)
                        min_offset = last_byte_offset + 1;
            }
            logger::info("truncating blockchain data from {} to {} bytes", idxr.num_bytes(), min_offset);
            idxr.truncate(min_offset);
            idxr.save_state();
        }
    };
}

#endif // !DAEDALUS_TURBO_CLI_DEBUG_TRUNCATE_HPP