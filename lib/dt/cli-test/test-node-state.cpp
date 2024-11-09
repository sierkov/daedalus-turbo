/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/cli.hpp>
#include <dt/compare.hpp>
#include <dt/scheduler.hpp>
#include <dt/cardano/ledger/state-compare.hpp>

namespace daedalus_turbo::cli::test_node_state {
    using namespace cardano::ledger;

    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "test-node-state";
            cmd.desc = "compare the original and generated node state files";
            cmd.args.expect({ "<orig-state>", "<generated-state>" });
        }

        void run(const arguments &args) const override
        {
            const auto &orig_path = args.at(0);
            const auto &gen_path = args.at(1);
            uint8_vector orig_data {}, gen_data {};
            {
                timer t1 { "load", logger::level::info };
                auto &sched = scheduler::get();
                sched.submit_void("load-orig", 100, [&] {
                    orig_data = file::read(orig_path);
                });
                sched.submit_void("load-gen", 100, [&] {
                    gen_data = file::read(gen_path);
                });
                sched.process();
            }
            compare_node_state(orig_data, gen_data);
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}