/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/cli.hpp>
#include <dt/history.hpp>

namespace daedalus_turbo::cli::tx_info {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "tx-info";
            cmd.desc = "show information about a transaction";
            cmd.args.expect({ "<data-dir>", "<tx-hash>" });
        }

        void run(const arguments &args) const override
        {
            const std::string &data_dir = args.at(0);
            const auto tx_hash = bytes_from_hex(args.at(1));
            chunk_registry cr { data_dir, chunk_registry::mode::index };
            reconstructor r { cr };
            auto tx_info = r.find_tx(tx_hash);
            if (!tx_info)
                throw error(fmt::format("unknown transaction hash {}", tx_hash.span()));
            cardano::mocks::block block { tx_info.block_info, tx_info.tx_raw, tx_info.offset, cardano::config::get() };
            const auto tx = cardano::make_tx(tx_info.tx_raw, block);
            std::cout << fmt::format("{}\n", *tx);
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}