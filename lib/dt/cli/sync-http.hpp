/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_SYNC_HTTP_HPP
#define DAEDALUS_TURBO_CLI_SYNC_HTTP_HPP

#include <dt/cli.hpp>
#include <dt/requirements.hpp>
#include <dt/sync/http.hpp>

namespace daedalus_turbo::cli::sync_http {
    struct cmd: public command {
        const command_info &info() const override
        {
            static const command_info i { "sync-http", "<data-dir> [--host=<host>]", "synchronize blockchain over Turbo protocol from <host> into <data-dir>" };
            return i;
        }

        void run(const arguments &args) const override
        {
            if (args.size() < 1) _throw_usage();
            const auto &data_dir = args.at(0);
            requirements::check(data_dir);
            const std::string db_dir = data_dir + "/compressed";
            const std::string idx_dir = data_dir + "/index";
            std::string host = "turbo1.daedalusturbo.org";
            if (args.size() > 2) {
                static std::string_view p_host { "--host=" };
                for (const auto &arg: std::ranges::subrange(args.begin() + 2, args.end())) {
                    if (arg.substr(0, p_host.size()) == p_host) {
                        host = arg.substr(p_host.size());
                    } else {
                        throw error("unsupported option: {}", arg);
                    }
                }
            }
            timer tc { fmt::format("sync-http {} -> {}, {}", host, db_dir, idx_dir) };
            scheduler sched {};
            auto indexers = indexer::default_list(sched, idx_dir);
            indexer::incremental idxr { sched, db_dir, indexers };
            sync::http::syncer syncr { sched, idxr, host };
            syncr.sync();
        }
    };
}

#endif // !DAEDALUS_TURBO_CLI_SYNC_HTTP_HPP