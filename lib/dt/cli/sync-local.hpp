/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_SYNC_LOCAL_HPP
#define DAEDALUS_TURBO_CLI_SYNC_LOCAL_HPP

#include <dt/cli.hpp>
#include <dt/requirements.hpp>
#include <dt/sync/local.hpp>
#include <dt/validator.hpp>

namespace daedalus_turbo::cli::sync_local {
    struct cmd: public command {
        const command_info &info() const override
        {
            static const command_info i {
                "sync-local", "<node-dir> <data-dir>",
                "synchronize from a local Cardano Node in <node-dir> into <data-dir>"
            };
            return i;
        }

        void run(const arguments &args) const override
        {
            if (args.size() < 2) _throw_usage();
            const auto &node_dir = args.at(0);
            const auto &data_dir = args.at(1);
            requirements::check(data_dir);
            size_t zstd_max_level = 3;
            bool strict = true;
            if (args.size() > 2) {
                static std::string_view p_zstd { "--zstd-max-level=" };
                static std::string_view p_no_strict { "--no-strict" };
                for (const auto &arg: std::ranges::subrange(args.begin() + 2, args.end())) {
                    if (arg.substr(0, p_zstd.size()) == p_zstd) {
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
            scheduler sched {};
            auto indexers = validator::default_indexers(sched, data_dir);
            validator::incremental cr { sched, data_dir, indexers };
            sync::local::syncer syncr { sched, cr, node_dir, strict, zstd_max_level, std::chrono::seconds { 0 } };
            auto res = syncr.sync();
            logger::info("errors: {} chunks: {} deleted: {} dist: {} db_last_slot: {} cycle time: {}",
                    res.errors.size(), res.updated.size(), res.deleted.size(), syncr.size(), res.last_slot, tc.stop(false));
            std::sort(res.errors.begin(), res.errors.end());
            for (const auto &err: res.errors)
                logger::error("sync error: {}", err);
        }
    };
}

#endif // !DAEDALUS_TURBO_CLI_SYNC_LOCAL_HPP