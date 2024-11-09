/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/config.hpp>
#include <dt/cli.hpp>
#include <dt/plutus/flat.hpp>
#include <dt/plutus/machine.hpp>
#include <dt/plutus/uplc.hpp>

namespace daedalus_turbo::cli::plutus_eval {
    using namespace cardano;
    using namespace daedalus_turbo::plutus;

    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "plutus-eval";
            cmd.desc = "evaluate a Plutus script and print its result and costs";
            cmd.args.expect({ "<script-path>" });
            cmd.opts.try_emplace("format", "a script format: uplc or flat", "uplc");
            cmd.opts.try_emplace("plutus-version", "v1, v2, or v3", "v3");
        }

        void run(const arguments &args, const options &opts) const override
        {
            const plutus_cost_models cost_mdls {
                plutus_cost_model::from_json(cardano::config::get().plutus_all_cost_models.v1.value(), json::load(install_path("etc/plutus/2023-02-14.json")).at("PlutusV1")),
                plutus_cost_model::from_json(cardano::config::get().plutus_all_cost_models.v2.value(), json::load(install_path("etc/plutus/2023-02-14.json")).at("PlutusV2"))
            };
            const auto parsed_costs = costs::parse(cost_mdls);
            const auto &path = args.at(0);
            const auto &format = opts.at("format").value();
            const auto &version = opts.at("plutus-version").value();
            const auto &model = _cost_model_for_version(parsed_costs, version);
            if (format == "uplc")
                return _eval<uplc::script>(path, model);
            if (format == "flat")
                return _eval<flat::script>(path, model);
            throw error("unsupported script format: {}", format);
        }
    private:
        static const costs::parsed_model &_cost_model_for_version(const costs::parsed_models &model, const std::string &version)
        {
            if (version == "v1")
                return model.v1.value();
            if (version == "v2")
                return model.v2.value();
            if (version == "v3")
                return model.v3.value();
            throw error("unsupported plutus version: {}", version);
        }

        template<typename S>
        static void _eval(const std::string &path, const costs::parsed_model &model)
        {
            allocator alloc {};
            S script { alloc, file::read(path) };
            machine m { alloc, model };
            const auto [res, costs] = m.evaluate(script.program());
            logger::info("costs: {}", costs);
            logger::info("result: {}", res);
        }
    };
    static auto instance = command::reg(std::make_shared<cmd>());
}