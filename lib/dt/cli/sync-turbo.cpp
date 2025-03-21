/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
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
            cmd.opts.try_emplace("host", "the turbo peer to synchronize with");
            cmd.opts.try_emplace("max-slot", "do not synchronize beyond the end of this epoch");
            cmd.opts.try_emplace("max-epoch", "synchronize up to the last block of the given epoch; needs --shelley-start-epoch for post-shelley epochs");
            cmd.opts.try_emplace("shelley-start-epoch", "defines the first shelley epoch");
            cmd.opts.try_emplace("txwit", "the transaction witness validation method to use: full, turbo or none", "turbo");
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
                cr.config().shelley_start_epoch(std::stoull(*opt_it->second));
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
            const sync::validation_mode_t txwit_mode = sync::validation_mode_from_text(opts.at("txwit").value());
            syncr.sync(peer, max_slot, txwit_mode);
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}