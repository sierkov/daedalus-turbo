/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_SYNC_LOCAL_HPP
#define DAEDALUS_TURBO_CLI_SYNC_LOCAL_HPP

#include <dt/cli.hpp>
#include <dt/sync/local.hpp>

namespace daedalus_turbo::cli::sync_local {
    struct cmd: public command {
        const command_info &info() const override
        {
            static const command_info i {
                "sync-local", "<cardano-node-dir> <compressed-dir> <idx-dir> [--zstd-max-level=3]",
                "create a compressed copy and index new data from Cardano Node data"
            };
            return i;
        }

        void run(const arguments &args) const override
        {
            if (args.size() < 3) _throw_usage();
            const auto &node_dir = args.at(0);
            const auto &db_dir = args.at(1);
            const std::string idx_dir =  args.at(2);
            size_t zstd_max_level = 3;
            bool strict = true;
            size_t num_threads = scheduler::default_worker_count();
            if (args.size() > 3) {
                static std::string_view p_threads { "--threads=" };
                static std::string_view p_zstd { "--zstd-max-level=" };
                static std::string_view p_no_strict { "--no-strict" };
                for (const auto &arg: std::ranges::subrange(args.begin() + 3, args.end())) {
                    if (arg.substr(0, p_threads.size()) == p_threads) {
                        size_t user_threads = std::stoul(arg.substr(p_threads.size()));
                        if (user_threads > 0 && user_threads < scheduler::default_worker_count())
                            num_threads = user_threads;
                    } else if (arg.substr(0, p_zstd.size()) == p_zstd) {
                        size_t user_zstd_level = std::stoul(arg.substr(p_zstd.size()));
                        if (user_zstd_level <= 22)
                            zstd_max_level = user_zstd_level;
                    } else if (arg == p_no_strict) {
                        strict = false;
                    } else {
                        throw error("unsupported option: {}", arg);
                    }
                }
            }
            timer tc { "sync-local" };
            scheduler sched { num_threads };
            auto indexers = indexer::default_list(sched, idx_dir);
            indexer::incremental idxr { sched, db_dir, indexers };
            sync::local::syncer syncr { sched, idxr, node_dir, strict, zstd_max_level };
            auto res = syncr.sync();
            logger::info("errors: {} updated: {} deleted: {} dist: {} db_last_slot: {} cycle time: {}",
                    res.errors.size(), res.updated.size(), res.deleted.size(), syncr.size(), res.last_slot, tc.stop(false));
            std::sort(res.errors.begin(), res.errors.end());
            for (const auto &err: res.errors)
                logger::error("sync error: {}", err);
        }
    };
}

#endif // !DAEDALUS_TURBO_CLI_SYNC_LOCAL_HPP