/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cli.hpp>
#ifndef _WIN32
#   include <sys/resource.h>
#endif

namespace daedalus_turbo::cli {
    int run(const int argc, const char **argv, const command::command_list &command_list)
    {
        std::set_terminate([]() {
            std::cerr << "std::terminate called; terminating\n";
            std::abort();
        });
        std::ios_base::sync_with_stdio(false);
        std::map<std::string, command_meta> commands {};
#ifndef _WIN32
        {
            static constexpr size_t stack_size = 32 << 20;
            struct rlimit rl;
            if (getrlimit(RLIMIT_STACK, &rl) != 0) [[unlikely]]
                throw error_sys("getrlimit RLIMIT_STACK failed!");
            if (rl.rlim_cur < stack_size) {
                rl.rlim_cur = stack_size;
                if (setrlimit(RLIMIT_STACK, &rl) != 0) [[unlikely]]
                    throw error_sys("setrlimit RLIMIT_STACK failed!");
            }
            logger::info("stack size: {} MB", rl.rlim_cur >> 20);
        }
#endif
        for (const auto &cmd: command_list) {
            command_meta meta { *cmd.get() };
            cmd->configure(meta.cfg);
            meta.cfg.opts.emplace("config-dir", "a directory with Cardano configuration files");
            if (const auto [it, created] = commands.try_emplace(meta.cfg.name, std::move(meta)); !created) [[unlikely]]
                        throw error("multiple definitions for {}", meta.cfg.name);
        }
        if (argc < 2) {
            std::cerr << "Usage: <command> [<arg> ...], where <command> is one of:\n" ;
            for (const auto &[name, cmd]: commands)
                std::cerr << fmt::format("    {} {}\n", cmd.cfg.name, cmd.cfg.make_usage());
            return 1;
        }

        const std::string cmd { argv[1] };
        logger::debug("run {}", cmd);
        const auto cmd_it = commands.find(cmd);
        if (cmd_it == commands.end()) {
            logger::error("Unknown command {}", cmd);
            return 1;
        }

        arguments args {};
        for (int i = 2; i < argc; ++i)
            args.emplace_back(argv[i]);
        try {
            const auto &meta = cmd_it->second;
            timer t { fmt::format("run {}", cmd), logger::level::info };
            const auto pr = meta.cmd.parse(meta.cfg, args);
            meta.cmd.run(pr.args, pr.opts);
        } catch (const std::exception &ex) {
            logger::error("{}: {}", cmd, ex.what());
            return 1;
        } catch (...) {
            logger::error("unrecognized exception at caught at main!");
            return 1;
        }
        return 0;
    }

    int run(const int argc, const char **argv)
    {
        return run(argc, argv, command::registry());
    }
}