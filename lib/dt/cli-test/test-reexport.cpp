/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/cli.hpp>
#include <dt/validator/state.hpp>
#include <dt/validator/state-compare.hpp>

namespace daedalus_turbo::cli::test_reexport {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "test-reexport";
            cmd.desc = "reexport node state by importing and exporting it and compare the results";
            cmd.args.expect({ "<node-state-path>" });
        }

        void run(const arguments &args) const override
        {
            const auto &orig_path = args.at(0);
            timer t1 { "load", logger::level::info };
            const auto orig_data = file::read(orig_path);
            t1.stop_and_print();
            timer t2 { "deserialize", logger::level::info };
            validator::state st {};
            const auto tip = st.deserialize_node(orig_data);
            t2.stop_and_print();
            timer t3 { "reserialize", logger::level::info };
            const auto own_data = st.serialize_node(tip).flat();
            t3.stop_and_print();
            validator::compare_node_state(orig_data, own_data);
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}