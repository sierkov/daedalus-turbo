/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_SYNC_P2P_HPP
#define DAEDALUS_TURBO_CLI_SYNC_P2P_HPP

#include <dt/cardano/network.hpp>
#include <dt/cli.hpp>
#include <dt/sync/p2p.hpp>
#include <dt/validator.hpp>

namespace daedalus_turbo::cli::sync_p2p {
    using namespace daedalus_turbo::cardano::network;
    using namespace daedalus_turbo::cardano;

    struct cmd: command {
        const command_info &info() const override
        {
            static const command_info i {
                "sync-p2p", "<data-dir> [--max-epoch=<epoch>]",
                "synchronize the blockchain with the Cardano P2P network"
            };
            return i;
        }

        void run(const arguments &args) const override
        {
            if (args.empty())
                _throw_usage();
            const auto &data_dir = args.at(0);
            validator::incremental cr { data_dir };
            sync::p2p::syncer syncer { cr };
            syncer.sync();
        }
    };
}

#endif // !DAEDALUS_TURBO_CLI_SYNC_P2P_HPP