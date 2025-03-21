/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/cli.hpp>
#include <dt/http-api.hpp>

namespace daedalus_turbo::cli::http_api {
    using namespace daedalus_turbo::http_api;

    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "http-api";
            cmd.desc = "start the HTTP API server";
            cmd.args.expect({ "<data-dir>" });
            cmd.opts.try_emplace("ip", "an IP address at which to listen for incoming connections", "127.0.0.1");
            cmd.opts.try_emplace("port", "a TCP port at which to listen for incoming connections", "55556");
            cmd.opts.try_emplace("ignore-requirements", "skip the hardware requirements check");
        }

        void run(const arguments &args, const options &opts) const override
        {
            const auto &data_dir = args.at(0);
            const auto ip = opts.at("ip").value();
            const uint16_t port = std::stoul(opts.at("port").value());
            const bool ignore_requirements = opts.contains("ignore-requirements");
            logger::info("HTTP API listens at the address {}:{}", ip, port);
            server s { data_dir, ignore_requirements };
            s.serve(ip, port);
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}