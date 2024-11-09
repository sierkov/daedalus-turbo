/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/cli.hpp>
#include <dt/compare.hpp>
#include <dt/requirements.hpp>
#include <dt/sync/turbo.hpp>
#include <dt/cardano/ledger/state-compare.hpp>

namespace daedalus_turbo::cli::test_export_full {
    using namespace cardano::ledger;

    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "test-export-full";
            cmd.desc = "generate, export and compare state for a range of epochs";
            cmd.args.expect({ "<data-dir>", "<orig-state-dir>" });
            cmd.opts.try_emplace("from", "the epoch from which to start the comparisons", "208");
            cmd.opts.try_emplace("to", "the epoch after which to stop the comparisons", "494");
        }

        void run(const arguments &args, const options &opts) const override
        {
            const auto &data_dir = args.at(0);
            const auto &orig_dir = args.at(1);
            chunk_registry cr { data_dir };
            sync::turbo::syncer syncr { cr };
            auto first_epoch = std::stoull(*opts.at("from"));
            if (first_epoch < 208)
                first_epoch = 208;
            auto last_epoch = std::stoull(*opts.at("to"));
            if (last_epoch < first_epoch)
                last_epoch = first_epoch;
            for (size_t epoch = first_epoch; epoch <= last_epoch; ++epoch) {
                const auto epoch_last_slot = 208 * 21600 + (epoch - 208 + 1) * 432000 - 1;
                logger::info("testing epoch: {} last slot: {}", epoch, epoch_last_slot);
                if (cr.max_slot() > epoch_last_slot) {
                    const auto new_tip = cr.epochs().at(epoch).chunks().back()->blocks.back().point();
                    logger::info("truncating the local chain to {}", new_tip);
                    cr.truncate(new_tip);
                }
                if (const auto tip = cr.tip(); !tip || tip->slot < epoch_last_slot - 200)
                    syncr.sync(syncr.find_peer(), epoch_last_slot);
                if (const auto tip = cr.tip(); tip) {
                    const auto orig_path = fmt::format("{}/{}-{}", orig_dir, epoch, tip->slot);
                    const auto gen_path = cr.node_export_ledger(data_dir, tip);
                    logger::info("exported the ledger state to {}", gen_path);
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
                    if (compare_node_state(orig_data, gen_data))
                        std::filesystem::remove(gen_path);
                }
            }
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}