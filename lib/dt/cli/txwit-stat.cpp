/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/ledger/state.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/cli.hpp>
#include <dt/index/merge-zpp.hpp>
#include <dt/index/utxo.hpp>
#include <dt/plutus/context.hpp>
#include <dt/storage/partition.hpp>

namespace daedalus_turbo::cli::txwit_stat {
    using namespace cardano;
    using namespace cardano::ledger;
    using namespace plutus;

    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "txwit-stat";
            cmd.desc = "Print statistics tx witnesses";
            cmd.args.expect({ "<data-dir>" });
        }

        void run(const arguments &args) const override
        {
            const auto &data_dir = args.at(0);
            const chunk_registry cr { data_dir, chunk_registry::mode::store };
            auto &sched = cr.sched();
            alignas(mutex::padding) mutex::unique_lock::mutex_type all_mutex {};
            part_info all {};
            storage::parse_parallel<part_info>(cr, 1024,
                [&](auto &part, const auto &blk) {
                    ++part.num_blocks;
                    blk.foreach_tx([&](const auto &tx) {
                        ++part.num_txs;
                        tx.foreach_redeemer([&](const auto &r) {
                            ++part.num_redeemers;
                        });
                        tx.foreach_witness([&](const auto wtyp, const auto &wit) {
                            switch (wtyp) {
                                case 0:
                                case 2:
                                    if (blk.era() >= 2) {
                                        tx.foreach_set(wit, [&](const auto &, const auto) {
                                            ++part.num_vkey;
                                        });
                                    } else {
                                        ++part.num_vkey;
                                    }
                                    break;
                                case 1:
                                    if (blk.era() >= 2) {
                                        tx.foreach_set(wit, [&](const auto &, const auto) {
                                            ++part.num_native;
                                        });
                                    } else {
                                        ++part.num_native;
                                    }
                                    break;
                                default:
                                    break;
                            }
                        });
                        tx.foreach_script([&](const auto &s) {
                            part.scripts[s.type()].emplace(s.hash());
                        });
                        tx.foreach_output([&](const auto &txo) {
                            if (txo.script_ref) {
                                const auto s = script_info::from_cbor(txo.script_ref->tag().second->buf());
                                part.scripts[s.type()].emplace(s.hash());
                            }
                        });
                    });
                },
                [&](auto, const auto &) {
                    return part_info {};
                },
                [&](auto &&part, const auto, const auto &) {
                    mutex::scoped_lock lk { all_mutex };
                    all += part;
                },
                "count-witnesses"
            );
            set<script_hash> plutus_scripts {};
            for (const auto &[typ, srcs]: all.scripts) {
                if (typ != script_type::native) {
                    for (const auto &h: srcs)
                        plutus_scripts.emplace(h);
                }
                logger::info("  {}: {}", typ, srcs.size());
            }
            logger::info("blocks: {} txs: {} redeemers: {} native: {} vkey: {} scripts: {}",
                all.num_blocks, all.num_txs, all.num_redeemers, all.num_native, all.num_vkey, plutus_scripts.size());
        }
    private:
        struct part_info {
            size_t num_blocks = 0;
            size_t num_txs = 0;
            size_t num_redeemers = 0;
            size_t num_native = 0;
            size_t num_vkey = 0;
            map<script_type, set<script_hash>> scripts;

            part_info &operator+=(const part_info &o) {
                num_blocks += o.num_blocks;
                num_txs += o.num_txs;
                num_redeemers += o.num_redeemers;
                num_native += o.num_native;
                num_vkey += o.num_vkey;
                for (const auto &[typ, o_srcs]: o.scripts) {
                    auto &srcs = scripts[typ];
                    for (const auto &s: o_srcs)
                        srcs.emplace(s);
                }
                return *this;
            }
        };
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}
