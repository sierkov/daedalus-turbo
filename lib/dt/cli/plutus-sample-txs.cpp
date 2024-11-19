/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <random>
#include <dt/chunk-registry.hpp>
#include <dt/cli.hpp>
#include <dt/index/merge-zpp.hpp>
#include <dt/index/utxo.hpp>
#include <dt/plutus/context.hpp>
#include <dt/plutus/costs.hpp>
#include <dt/storage/partition.hpp>
#include <dt/cardano/ledger/state.hpp>

namespace daedalus_turbo::cli::plutus_sample_txs {
    using namespace cardano;
    using namespace cardano::ledger;
    using namespace plutus;

    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "plutus-sample-txs";
            cmd.desc = "Create a random sample of transaction with plutus script witnesses";
            cmd.args.expect({ "<data-dir>", "<sample-path>" });
            cmd.opts.try_emplace("seed", "the random seed", "123456");
            cmd.opts.try_emplace("sample", "the sample size (# of txs)", "256000");
        }

        void run(const arguments &args, const options &opts) const override
        {
            file::set_max_open_files();
            const chunk_registry cr { args.at(0), chunk_registry::mode::store };
            const auto &out_path = args.at(1);
            const uint32_t seed = std::stoul(*opts.at("seed"));
            const uint64_t sample_size = std::stoull(*opts.at("sample"));

            alignas(mutex::padding) mutex::unique_lock::mutex_type all_mutex {};
            vector<tx_hash> txs {};

            storage::parse_parallel_epoch<part_info>(cr,
                [&](auto &part, const auto &blk) {
                    blk.foreach_tx([&](const auto &tx) {
                        size_t num_redeemers = 0;
                        tx.foreach_redeemer([&](const auto &) {
                            ++num_redeemers;
                        });
                        if (num_redeemers) {
                            part.txs.emplace_back(tx.hash());
                        }
                    });
                },
                [&](const size_t, const storage::partition &) {
                    return part_info {};
                },
                [&](auto &&part, const size_t, const auto &) {
                    mutex::scoped_lock lk { all_mutex };
                    txs.reserve(txs.size() + part.txs.size());
                    for (const auto &tx: part.txs)
                        txs.emplace_back(tx);
                },
                "sample-txs"
            );
            std::sort(txs.begin(), txs.end());

            std::default_random_engine rnd { seed };
            set<tx_hash> sample {};
            while (sample.size() < sample_size && !txs.empty()) {
                std::uniform_int_distribution<size_t> dist { 0, txs.size() };
                const auto ri = dist(rnd);
                if (const auto [it, created] = sample.emplace(txs[ri]); !created) [[unlikely]]
                    throw error("trying to add a duplicate transaction id to the sample: {}", *it);
                if (ri + 1 != txs.size())
                    txs[ri] = txs.back();
                txs.pop_back();
            }

            std::string text {};
            for (const auto &tx: sample)
                text += fmt::format("{}\n", tx);
            file::write(out_path, text);
        }
    private:
        struct part_info {
            vector<tx_hash> txs {};
        };
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
