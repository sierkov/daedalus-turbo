/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_VALIDATE_TX_VKEYS_INFO_HPP
#define DAEDALUS_TURBO_CLI_VALIDATE_TX_VKEYS_INFO_HPP

#include <map>
#include <dt/cardano.hpp>
#include <dt/cli.hpp>
#include <dt/chunk-registry.hpp>

namespace daedalus_turbo::cli::validate_tx_vkeys {
    struct cmd: command {
        const command_info &info() const override
        {
            static const command_info i { "validate-tx-vkeys", "<data-dir>", "validate transaction vkey witnesses" };
            return i;
        }

        void run(const arguments &args) const override
        {
            if (args.size() != 1) _throw_usage();
            const auto &data_dir = args.at(0);
            scheduler sched {};
            chunk_registry cr { sched, data_dir };
            cr.init_state();
            info_map all_infos {};
            size_t num_parsed = 0;
            sched.on_result("parse-chunk", [&](const std::any &res) {
                ++num_parsed;
                if (res.type() == typeid(scheduled_task_error))
                    return;
                const auto &chunk_infos = std::any_cast<info_map>(res);
                for (const auto &[era, info]: chunk_infos) {
                    auto &era_info = all_infos[era];
                    era_info += info;
                }
                progress::get().update("parse", num_parsed, cr.num_chunks());
            });
            for (const auto &[last_byte_offset, info]: cr.chunks()) {
                auto chunk_path = cr.full_path(info.rel_path());
                sched.submit("parse-chunk", 100, [chunk_path] {
                    auto chunk = file::read(chunk_path);
                    cbor_parser parser { chunk };
                    cbor_value block_tuple {};
                    info_map infos {};
                    while (!parser.eof()) {
                        parser.read(block_tuple);
                        auto blk = cardano::make_block(block_tuple, block_tuple.data - chunk.data());
                        if (blk->era() >= 2) {
                            auto &info = infos[blk->era()];
                            info.num_blocks++;
                            info.num_txs += blk->tx_count();
                            blk->foreach_tx([&](const auto &tx) {
                                auto ok = tx.vkey_witness_ok();
                                info.num_txwits_vkey += ok.total;
                                info.num_txwits_vkey_ok += ok.ok;
                            });
                        }
                    }
                    return infos;
                });
            }
            sched.process(true);
            item_info total {};
            for (const auto &[era, info]: all_infos) {
                std::cout << fmt::format("era: {} {}\n", era, info.to_string());
                total += info;
            }
            std::cout << fmt::format("totals: {}\n", total.to_string());
        }
    private:
        struct item_info {
            uint64_t num_blocks = 0;
            uint64_t num_txs = 0;
            uint64_t num_txwits = 0;
            uint64_t num_txwits_vkey = 0;
            uint64_t num_txwits_vkey_ok = 0;

            item_info &operator+=(const auto &v)
            {
                num_blocks += v.num_blocks;
                num_txs += v.num_txs;
                num_txwits_vkey += v.num_txwits_vkey;
                num_txwits_vkey_ok += v.num_txwits_vkey_ok;
                return *this;
            }

            std::string to_string() const
            {
                return fmt::format("blocks: {} txs: {} txwits_vkey: {} valid_txwits_vkey: {} ({:0.3f}%)",
                    num_blocks, num_txs, num_txwits_vkey,
                    num_txwits_vkey_ok, static_cast<double>(100 * num_txwits_vkey_ok) / num_txwits_vkey);
            }
        };
        using info_map = std::map<uint64_t, item_info>;
    };   
}

#endif // !DAEDALUS_TURBO_CLI_VALIDATE_TX_VKEYS_INFO_HPP