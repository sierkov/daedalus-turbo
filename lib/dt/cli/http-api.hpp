/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_HTTP_API_HPP
#define DAEDALUS_TURBO_CLI_HTTP_API_HPP

#include <dt/cli.hpp>
#include <dt/http-api.hpp>

namespace daedalus_turbo::cli::http_api {
    using namespace daedalus_turbo::http_api;

    struct cmd: command {
        const command_info &info() const override
        {
            static const command_info i { "http-api", "<data-dir> [--ip=<ip>] [--port=<port>] [--source=<turbo-host>]", "start the HTTP API server at 127.0.0.1:55556 by default" };
            return i;
        }

        void run(const arguments &args) const override
        {
            if (args.size() < 1) _throw_usage();
            const auto &data_dir = args.at(0);
            std::string ip { "127.0.0.1" };
            uint16_t port = 55556;
            if (args.size() > 1) {
                static std::string_view p_ip { "--ip=" };
                static std::string_view p_port { "--port=" };
                for (const auto &arg: std::ranges::subrange(args.begin() + 1, args.end())) {
                    if (arg.substr(0, p_ip.size()) == p_ip) {
                        ip = arg.substr(p_ip.size());
                    } else if (arg.substr(0, p_port.size()) == p_port) {
                        port = std::stoul(arg.substr(p_port.size()));
                    } else {
                        throw error("unsupported option: {}", arg);
                    }
                }
            }
            std::cerr << fmt::format("HTTP API listen address {}:{}\n", ip, port);
            server s { data_dir };
            s.serve(ip, port);
        }
    };
}

#endif // !DAEDALUS_TURBO_CLI_HTTP_API_HPP