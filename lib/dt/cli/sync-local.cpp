/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cli.hpp>
#include <dt/cli/common.hpp>
#include <dt/sync/local.hpp>
#include <dt/chunk-registry.hpp>

namespace daedalus_turbo::cli::sync_local {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "sync-local";
            cmd.desc = "synchronize the blockchain from a local Cardano Node in <node-dir> into <data-dir>";
            cmd.args.expect({ "<node-dir>", "<data-dir>" });
            cmd.opts.try_emplace("zstd-max-level", "do not validate or index data", "3");
            common::add_opts(cmd);
        }

        void run(const arguments &args, const options &opts) const override
        {
            const auto &node_dir = args.at(0);
            const auto &data_dir = args.at(1);
            requirements::check(data_dir);
            const auto mode = common::cr_mode(opts);
            size_t zstd_max_level = 3;
            if (const auto opt_it = opts.find("zstd-max-level"); opt_it != opts.end() && opt_it->second)
                zstd_max_level = std::stoull(*opt_it->second);
            chunk_registry cr { data_dir, mode };
            progress_guard pg { "download", "parse", "merge", "validate" };
            sync::local::syncer syncr { cr, zstd_max_level, std::chrono::seconds { 0 } };
            syncr.sync(syncr.find_peer(node_dir));
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}