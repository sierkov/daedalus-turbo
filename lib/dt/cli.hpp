/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_HPP
#define DAEDALUS_TURBO_CLI_HPP

#include <iostream>
#include <memory>
#include <string>
#include <dt/config.hpp>
#include <dt/logger.hpp>
#include <dt/requirements.hpp>
#include <dt/timer.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::cli {
    using arguments = vector<std::string>;
    using options = map<std::string, std::optional<std::string>>;

    struct command_info {
        std::string name {};
        std::string usage {};
        std::string descr {};
    };

    using option_validator = std::function<std::optional<std::string>(const std::optional<std::string> &)>;

    struct option_config {
        std::string desc {};
        std::optional<std::string> default_value {};
        std::optional<option_validator> validator {};
    };
    using option_config_map = map<std::string, option_config>;

    struct argument_config {
        std::optional<size_t> min {};
        std::optional<size_t> max {};
        std::vector<std::string> names {};

        void expect(const std::initializer_list<std::string> &args)
        {
            names = args;
            size_t req = 0;
            size_t opt = 0;
            for (const auto &a: args) {
                if (a.at(0) == '[')
                    ++opt;
                else
                    ++req;
            }
            min = req;
            max = req + opt;
        }
    };

    struct config {
        std::string name {};
        std::string desc {};
        argument_config args {};
        option_config_map opts {};
        std::optional<std::string> usage {};

        std::string make_usage() const
        {
            if (usage)
                return fmt::format("{} - {}", *usage, desc);
            std::string arg_info {};
            if (!args.names.empty()) {
                for (const auto &name: args.names)
                    arg_info += fmt::format(" {}", name);
            }
            const std::string opt_info { opts.empty() ? "" : "[options]" };
            return fmt::format("{}{} - {}", opt_info, arg_info, desc);
        }
    };

    struct parse_result {
        arguments args {};
        options opts {};
    };

    struct command {
        using command_list = std::vector<std::shared_ptr<command>>;

        static command_list &registry()
        {
            static command_list l {};
            return l;
        }

        static std::shared_ptr<command> reg(std::shared_ptr<command> cmd)
        {
            registry().emplace_back(cmd);
            return cmd;
        }

        virtual ~command() =default;

        virtual const command_info &info() const
        {
            throw error("not implemented");
        }

        virtual void run(const arguments &) const
        {
            throw error("not implemented!");
        }

        virtual void run(const arguments &args, const options &) const
        {
            run(args);
        }

        virtual void configure(config &meta) const
        {
            const auto &inf = info();
            meta.name = inf.name;
            meta.desc = inf.descr;
            meta.usage = inf.usage;
        }

        parse_result parse(const config &cfg, const arguments &args) const
        {
            parse_result pr {};
            for (const auto &arg: args) {
                if (arg.substr(0, 2) == "--") {
                    std::string name = arg.substr(2);
                    std::optional<std::string> val {};
                    if (const auto eq_pos = arg.find('=', 2); eq_pos != arg.npos) {
                        val = arg.substr(eq_pos + 1);
                        name = arg.substr(2, eq_pos - 2);
                    }
                    const auto cfg_it = cfg.opts.find(name);
                    if (cfg_it == cfg.opts.end())
                        throw error("unknown option '--{}'", name);
                    const auto [opt_it, opt_created] = pr.opts.try_emplace(name, std::move(val));
                    if (!opt_created)
                        throw error("duplicate option specification '{}'", arg);
                } else {
                    pr.args.emplace_back(arg);
                }
            }
            for (const auto &[name, cfg]: cfg.opts) {
                if (cfg.default_value && !pr.opts.contains(name))
                    pr.opts.emplace(name, *cfg.default_value);
                // creates an empty value if not initialized
                if (const auto &val_it = pr.opts.find(name); cfg.validator && val_it != pr.opts.end()) {
                    if (const auto val_err = (*cfg.validator)(val_it->second); val_err)
                        throw error("value {} is invalid for '--{}': {}", val_it->second, name, *val_err);
                }
            }
            if (cfg.args.min && pr.args.size() < *cfg.args.min)
                _throw_usage(cfg);
            if (cfg.args.max && pr.args.size() > *cfg.args.max)
                _throw_usage(cfg);
            if (const auto opt_it = pr.opts.find("config-dir"); opt_it != pr.opts.end() && opt_it->second)
                configs_dir::set_default_path(*opt_it->second);
            return pr;
        }
    protected:
        void _throw_usage(const config &cmd) const
        {
            std::string usage = fmt::format("usage: {}", cmd.make_usage());
            if (!cmd.opts.empty()) {
                usage += fmt::format("\n{} supports the following options:", cmd.name);
                for (const auto &[name, cfg]: cmd.opts) {
                    if (cfg.default_value)
                        usage += fmt::format("\n    --{} ({} by default) - {}", name, *cfg.default_value, cfg.desc);
                    else
                        usage += fmt::format("\n    --{} - {}", name, cfg.desc);
                }
            }
            throw error(usage);
        }

        void _throw_usage() const
        {
            config cmd {};
            configure(cmd);
            _throw_usage(cmd);
        }
    };

    struct command_meta {
        const command &cmd;
        config cfg {};
    };

    inline int run(const int argc, const char **argv, const command::command_list &command_list)
    {
        std::ios_base::sync_with_stdio(false);
        std::map<std::string, command_meta> commands {};
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

    inline int run(const int argc, const char **argv)
    {
        return run(argc, argv, command::registry());
    }
}

#endif // !#define DAEDALUS_TURBO_CLI_HPP