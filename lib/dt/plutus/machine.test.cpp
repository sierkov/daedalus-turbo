/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/plutus/machine.hpp>
#include <dt/plutus/uplc.hpp>
#include <dt/scheduler.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::plutus;

namespace {
    struct script_info {
        std::string version;
        term_ptr expr = nullptr;
        cardano::ex_units cost {};

        bool operator==(const script_info &o) const
        {
            return version == o.version
                && static_cast<bool>(expr) == static_cast<bool>(o.expr)
                && (!expr || *expr == *o.expr)
                && cost == o.cost;
        }
    };
    using parse_res = std::variant<script_info, std::string>;
}

namespace fmt {
    template<>
    struct formatter<parse_res>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            switch (v.index()) {
                case 0: {
                    const auto &s = std::get<script_info>(v);
                    return fmt::format_to(ctx.out(), "(program {} {}) (cost: {})", s.version, s.expr, s.cost);
                }
                case 1: return fmt::format_to(ctx.out(), "{}", std::get<std::string>(v));
                default: throw error("unsupported script_info index: {}", v.index());
            }
        }
    };
}

namespace {
    cardano::ex_units parse_budget(const std::string &path)
    {
        cardano::ex_units budget {};
        const std::string text { file::read(path).str() };
        if (!text.starts_with("({cpu: ")) [[unlikely]]
            throw error("unsupported budget format: {}", text);
        const auto eol_pos = text.find('\n');
        if (eol_pos == std::string::npos) [[unlikely]]
            throw error("unsupported budget format: {}", text);
        budget.steps = std::stoull(text.substr(7, eol_pos - 7));
        const auto line2 = text.substr(eol_pos + 1);
        if (!line2.starts_with("| mem: ")) [[unlikely]]
            throw error("unsupported budget format: {}", text);
        const auto rbr_pos = line2.find('}');
        if (rbr_pos == std::string::npos) [[unlikely]]
            throw error("unsupported budget format: {}", text);
        budget.mem = std::stoull(line2.substr(7, rbr_pos - 7));
        return budget;
    }

    parse_res parse_script(const std::string &path, const std::function<std::string(const std::string &)> &on_error)
    {
        try {
            uplc::script s { file::read(path) };
            return script_info { s.version(), s.program() };
        } catch (...) {
            return on_error(path);
        }
    }

    machine::result run_script(const std::string &path, const optional_budget &budget={})
    {
        const uplc::script s { file::read(path) };
        machine m { s.version(), budget };
        return m.evaluate(s.program());
    }

    void test_script(const std::filesystem::path &path, const optional_budget &budget={}, const std::source_location &loc=std::source_location::current())
    {
        const auto exp_path = fmt::format("{}.uplc.expected", (path.parent_path() / path.stem()).string());
        auto exp_res = parse_script(exp_path, [](const auto &p) { return std::string { file::read(p).str() }; });
        if (std::holds_alternative<script_info>(exp_res)) {
            auto &si = std::get<script_info>(exp_res);
            si.cost = parse_budget(fmt::format("{}.uplc.budget.expected", (path.parent_path() / path.stem()).string()));
        }
        auto res = parse_script(path.string(), [](const auto &) { return "parse error"; });
        std::optional<std::string> eval_err {};
        if (std::holds_alternative<script_info>(res)) {
            try {
                auto &si = std::get<script_info>(res);
                machine m { {}, budget };
                auto [res, cost] = m.evaluate(si.expr);
                si.expr = std::move(res);
                si.cost = std::move(cost);
            } catch (const std::exception &ex) {
                res = "evaluation failure";
                eval_err.emplace(ex.what());
            } catch (...) {
                res = "evaluation failure";
                eval_err.emplace("unknown error");
            }
        }
        test_same(path.string(), exp_res, res, loc);
    }

    void test_script_dir(const std::string &script_dir, const optional_budget &budget={})
    {
        vector<std::string> paths {};
        for (auto &entry: std::filesystem::recursive_directory_iterator(script_dir)) {
            if (entry.is_regular_file() && entry.path().extension().string() == ".uplc")
                paths.emplace_back(entry.path().string());
        }
        std::sort(paths.begin(), paths.end());
        for (const auto &path: paths)
            test_script(path, budget);
    }
}

suite plutus_machine_suite = [] {
    "plutus::machine"_test = [] {
        "budget"_test = [] {
            const auto [res, cost] = run_script("./data/plutus/conformance/example/factorial/factorial.uplc");
            test_same(50026, cost.mem);
            test_same(14104357, cost.steps);
            // fails with a low cpu budget
            expect(throws([] { run_script("./data/plutus/conformance/example/factorial/factorial.uplc", cardano::ex_units { 50026, 14104356 }); }));
            // fails with a low mem budget
            expect(throws([] { run_script("./data/plutus/conformance/example/factorial/factorial.uplc", cardano::ex_units { 50025, 14104357 }); }));
            // succeeds with a high-enough budget
            expect(nothrow([] { run_script("./data/plutus/conformance/example/factorial/factorial.uplc", cardano::ex_units { 50026, 14104357 }); }));
        };
        "conformance"_test = [] {
            test_script_dir("./data/plutus/conformance/term");
            test_script_dir("./data/plutus/conformance/builtin");
            test_script_dir("./data/plutus/conformance/example");
        };
    };
};