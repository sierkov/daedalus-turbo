/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cli.hpp>
#include <dt/plutus/flat.hpp>
#include <dt/plutus/machine.hpp>
#include <dt/plutus/uplc.hpp>

namespace daedalus_turbo::cli::plutus_eval {
    using namespace daedalus_turbo::plutus;

    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "plutus-eval";
            cmd.desc = "evaluate a Plutus script and print its result and costs";
            cmd.args.expect({ "<script-path>" });
            cmd.opts.try_emplace("format", "a script format: uplc or flat", "uplc");
        }

        void run(const arguments &args, const options &opts) const override
        {
            const auto &path = args.at(0);
            const auto &format = opts.at("format");
            if (format == "uplc")
                return _eval<uplc::script>(path);
            if (format == "flat")
                return _eval<flat::script>(path);
            throw error("unsupported script format: {}", format);
        }
    private:
        template<typename S>
        static void _eval(const std::string &path)
        {
            S script { file::read(path) };
            machine m { script.version() };
            const auto [res, costs] = m.evaluate(script.program());
            std::cout << fmt::format("res: {} costs: {}\n", res, costs);
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}