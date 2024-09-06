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
            cmd.opts.emplace("max-epoch", "synchronize up to the last block of the given epoch; needs --shelley-start-epoch for post-shelley epochs");
            cmd.opts.emplace("shelley-start-epoch", "defines the first shelley epoch");
        }

        void run(const arguments &args, const options &opts) const override
        {
            const auto &data_dir = args.at(0);
            requirements::check(data_dir);
            std::optional<std::string> host {};
            cardano::optional_slot max_slot {};
            chunk_registry cr { data_dir };
            if (const auto opt_it = opts.find("host"); opt_it != opts.end() && opt_it->second)
                host = *opt_it->second;
            if (const auto opt_it = opts.find("shelley-start-epoch"); opt_it != opts.end() && opt_it->second)
                cr.config().shelley_start_slot(std::stoull(*opt_it->second) * cr.config().byron_epoch_length);
            if (const auto opt_it = opts.find("max-epoch"); opt_it != opts.end() && opt_it->second)
                max_slot = cardano::slot::from_epoch(std::stoull(*opt_it->second) + 1ULL, cr.config()) - 1;
            if (const auto opt_it = opts.find("max-slot"); opt_it != opts.end() && opt_it->second) {
                if (!max_slot) [[likely]]
                    max_slot = std::stoull(*opt_it->second);
                else
                    throw error("max_slot has already been set!");
            }
            if (const auto opt_it = opts.find("max-slot"); opt_it != opts.end() && opt_it->second) {
                if (!max_slot) [[likely]]
                    max_slot = std::stoull(*opt_it->second);
                else
                    throw error("max_slot has already been set!");
            }

            sync::turbo::syncer syncr { cr };
            progress_guard pg { "download", "parse", "merge", "validate" };
            const auto peer = syncr.find_peer(host);
            syncr.sync(peer, max_slot);
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}