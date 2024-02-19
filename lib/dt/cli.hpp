/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_HPP
#define DAEDALUS_TURBO_CLI_HPP

#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <dt/logger.hpp>
#include <dt/timer.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::cli {
    using arguments = std::vector<std::string>;

    struct command_info {
        std::string name {};
        std::string usage {};
        std::string descr {};
    };

    struct command {
        virtual ~command() {};
        virtual void run(const arguments &) const =0;
        virtual const command_info &info() const =0;
    protected:
        void _throw_usage(const command_info &i) const
        {
            throw error("Usage: {} {}", i.name, i.usage);
        }

        void _throw_usage() const
        {
            _throw_usage(info());
        }
    };

    template<typename ... Ptrs>
    auto make_command_list(Ptrs&& ... ptrs)
    {
        std::vector<std::unique_ptr<command>> vec;
        (vec.emplace_back( std::forward<Ptrs>(ptrs) ), ...);
        return vec;
    }

    inline int run(int argc, char **argv, const std::vector<std::unique_ptr<command>> &command_list)
    {
        std::ios_base::sync_with_stdio(false);
        std::map<std::string_view, const cli::command *> commands {};
        for (const auto &cmd: command_list) commands.emplace(cmd->info().name, cmd.get());
        if (argc < 2) {
            std::cerr << "Usage: <command> [<arg> ...], where <command> is one of:\n" ;
            for (const auto &[name, cmd]: commands) {
                const auto info = cmd->info();
                std::cerr << "    " << name << " " << info.usage << " - " << info.descr << '\n';
            }
            return 1;
        }
        
        const std::string_view cmd { argv[1] };
        logger::debug("run {}", cmd);
        const auto cmd_it = commands.find(cmd);
        if (cmd_it == commands.end()) {
            logger::error("Unknown command {}", cmd);
            return 1;
        }

        cli::arguments args {};
        for (int i = 2; i < argc; ++i)
            args.emplace_back(argv[i]);
        try {
            timer t { fmt::format("run {}", cmd) };
            cmd_it->second->run(args);
        } catch (const std::exception &ex) {
            logger::error("{}: {}", cmd, ex.what());
            return 1;
        } catch (...) {
            logger::error("unrecognized exception at caught at main!");
            return 1;
        }
        return 0;
    }
}

#endif // !#define DAEDALUS_TURBO_CLI_HPP