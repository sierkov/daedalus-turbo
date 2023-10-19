/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_PAY_HISTORY_HPP
#define DAEDALUS_TURBO_CLI_PAY_HISTORY_HPP

#include <dt/cardano.hpp>
#include <dt/cli.hpp>
#include <dt/history.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo::cli::pay_history {
    struct cmd: public command {
        const command_info &info() const override
        {
            static const command_info i { "pay-history", "<compressed-dir> <indices-dir> <pay-addr>", "list all transactions referencing a given stake address" };
            return i;
        }

        void run(const arguments &args) const override
        {
            if (args.size() < 3) _throw_usage();
            timer t { "reconstruction and serialization", logger::level::debug };
            const auto &db_path = args.at(0);
            const auto &idx_path = args.at(1);
            cardano::address_buf addr_raw { args.at(2) };
            if (addr_raw.size() == 28) addr_raw.insert(addr_raw.begin(), 0xE1);
            size_t num_threads = scheduler::default_worker_count();
            if (args.size() >= 4) {
                size_t user_threads = std::stoull(args.at(3));
                if (user_threads > 0 && user_threads < scheduler::default_worker_count()) num_threads = user_threads;
            }
            scheduler sched { num_threads };
            daedalus_turbo::chunk_registry cr { sched, db_path };
            cr.init_state();
            reconstructor r { sched, cr, idx_path };
            cardano::address addr { addr_raw.span() };
            std::cout << fmt::format("{}", r.find_pay_history(addr.pay_id()));
        }
    };
}

#endif // !DAEDALUS_TURBO_CLI_PAY_HISTORY_HPP