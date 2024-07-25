/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/cli.hpp>
#include <dt/publisher.hpp>

namespace daedalus_turbo::cli::publisher {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "publisher";
            cmd.desc = "run continuous import and publishing of Cardano blockchain data";
            cmd.args.expect({ "<node-path>", "<www-path>" });
            cmd.opts.try_emplace("once", "run the publishing cycle only once");
            cmd.opts.try_emplace("zstd-max-level", "do not validate or index data", "3");
        }

        void run(const arguments &args, const options &opts) const override
        {
            const auto &node_path = args.at(0);
            const auto &www_path = args.at(1);
            bool repeat = true;
            if (const auto opt_it = opts.find("once"); opt_it != opts.end())
                repeat = false;
            size_t zstd_max_level = 3;
            if (const auto opt_it = opts.find("zstd-max-level"); opt_it != opts.end() && opt_it->second)
                zstd_max_level = std::stoull(*opt_it->second);
            chunk_registry cr { www_path, chunk_registry::mode::store };
            const auto sk = ed25519::skey::from_hex(file::read("etc/publisher-secret.txt").span().string_view());
            daedalus_turbo::publisher p { cr, node_path, sk, zstd_max_level };
            const std::chrono::seconds update_interval { 2 };
            for (;;) {
                const auto next_run = std::chrono::system_clock::now() + update_interval;
                p.publish();
                if (!repeat)
                    break;
                if (const auto now = std::chrono::system_clock::now(); now < next_run)
                    std::this_thread::sleep_for(next_run - now);
            }
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}