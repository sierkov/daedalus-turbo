/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/cli.hpp>
#include <dt/requirements.hpp>
#include <dt/sync/turbo.hpp>

namespace daedalus_turbo::cli::sync_turbo {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "sync-turbo";
            cmd.desc = "synchronize the blockchain from a Turbo server <host> into <data-dir>";
            cmd.args.expect({ "<data-dir>" });
            cmd.opts.emplace("host", "the turbo peer to synchronize with");
            cmd.opts.emplace("max-slot", "do not synchronize beyond the end of this epoch");
        }

        void run(const arguments &args, const options &opts) const override
        {
            const auto &data_dir = args.at(0);
            requirements::check(data_dir);
            std::optional<std::string> host {};
            cardano::optional_slot max_slot {};
            if (const auto opt_it = opts.find("host"); opt_it != opts.end() && opt_it->second)
                host = *opt_it->second;
            if (const auto opt_it = opts.find("max-slot"); opt_it != opts.end() && opt_it->second)
                max_slot = std::stoull(*opt_it->second);
            timer tc { fmt::format("sync-turbo into {}", data_dir) };
            chunk_registry cr { data_dir };
            sync::turbo::syncer syncr { cr };
            progress_guard pg { "download", "parse", "merge", "validate" };
            const auto peer = syncr.find_peer(host);
            syncr.sync(peer, max_slot);
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}