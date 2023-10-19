/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_DEBUG_TX_INFO_HPP
#define DAEDALUS_TURBO_CLI_DEBUG_TX_INFO_HPP

#include <dt/cli.hpp>
#include <dt/history.hpp>

namespace daedalus_turbo::cli::tx_info {
    struct cmd: public command {
        const command_info &info() const override
        {
            static const command_info i { "tx-info", "<compressed-dir> <index-dir> <tx-hash>", "show information about a transaction given its hash" };
            return i;
        }

        void run(const arguments &args) const override
        {
            if (args.size() < 3) _throw_usage();
            const std::string &db_path = args.at(0);
            const std::string &idx_path = args.at(1);
            const auto tx_hash = bytes_from_hex(args.at(2));
            size_t num_threads = scheduler::default_worker_count();
            if (args.size() >= 4) {
                size_t user_threads = std::stoull(args.at(3));
                if (user_threads > 0 && user_threads < scheduler::default_worker_count()) num_threads = user_threads;
            }
            scheduler sched { num_threads };
            daedalus_turbo::chunk_registry cr { sched, db_path };
            cr.init_state();
            reconstructor r { sched, cr, idx_path };
            auto tx_info = r.find_tx(tx_hash);
            if (!tx_info)
                throw error("unknown transaction hash {}", tx_hash.span());
            history_mock_block block { tx_info.block_info, tx_info.tx_raw, tx_info.offset };
            auto tx = cardano::make_tx(tx_info.tx_raw, block);
            std::cout << tx->to_json() << '\n';
        }
    };
}

#endif // !DAEDALUS_TURBO_CLI_DEBUG_TX_INFO_HPP