/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_SYNC_HTTP_HPP
#define DAEDALUS_TURBO_CLI_SYNC_HTTP_HPP

#include <dt/cli.hpp>
#include <dt/validator.hpp>
#include <dt/requirements.hpp>
#include <dt/sync/http.hpp>

namespace daedalus_turbo::cli::sync_http {
    struct cmd: command {
        const command_info &info() const override
        {
            static const command_info i {
                "sync-http", "<data-dir> [--host=<host>] [--max-epoch=<epoch>]",
                "synchronize the blockchain from a Turbo server <host> into <data-dir>"
            };
            return i;
        }

        void run(const arguments &args) const override
        {
            if (args.size() < 1) _throw_usage();
            const auto &data_dir = args.at(0);
            requirements::check(data_dir);
            std::optional<uint64_t> max_epoch {};
            if (args.size() > 1) {
                static std::string_view p_max_epoch { "--max-epoch=" };
                for (const auto &arg: std::ranges::subrange(args.begin() + 1, args.end())) {
                    if (arg.substr(0, p_max_epoch.size()) == p_max_epoch) {
                        std::string max_epoch_s { arg.substr(p_max_epoch.size()) };
                        max_epoch = std::stoull(max_epoch_s);
                    } else {
                        throw error("unsupported option: {}", arg);
                    }
                }
            }
            timer tc { fmt::format("sync-http into {}", data_dir) };
            validator::incremental cr { validator::default_indexers(data_dir), data_dir };
            sync::http::syncer syncr { cr };
            syncr.sync(max_epoch);
        }
    };
}

#endif // !DAEDALUS_TURBO_CLI_SYNC_HTTP_HPP