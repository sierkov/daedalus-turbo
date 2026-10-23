/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2024-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <limits>
#include <turbo/common/test.hpp>
#include <turbo/plutus/context.hpp>

using namespace turbo;
using namespace turbo::cardano;
using namespace turbo::plutus;

suite plutus_context_suite = [] {
    "plutus::context"_test = [] {
        "validated purpose bindings survive ownership transfer and freeze with the context"_test = [] {
            storage::block_info block {};
            block.era = 7;
            script_hash policy {};
            policy[0] = 1;
            cbor::encoder body {}, witnesses {};
            body.map(4).uint(0).array(0).uint(1).array(0).uint(2).uint(0);
            body.uint(9).map(1).bytes(policy).map(1).bytes(uint8_vector {}).uint(1);
            witnesses.map(0);
            context ctx { std::move(body.cbor()), std::move(witnesses.cbor()), block };
            ctx.protocol_ver({ 11, 0 });
            ctx.set_inputs({}, {});
            const redeemer_id pointer { redeemer_tag::mint, 0 };
            expect(ctx.redeemer_script(pointer) == policy); // independent body resolution
            flat_map<redeemer_id, script_hash> bindings {};
            bindings.emplace(pointer, policy);
            ctx.set_script_purposes(std::move(bindings));
            bindings.clear();
            expect(ctx.redeemer_script(pointer) == policy);
            expect(throws([&] { ctx.redeemer_script({ redeemer_tag::mint, 1 }); }));
            ctx.prepare();
            expect(throws([&] { ctx.set_script_purposes({}); }));
        };
        "withdrawal redeemer indices follow ledger account order"_test = [] {
            const auto key0 = reward_id_t::from_hex<reward_id_t>("E0" + std::string(56, '0'));
            const auto script0 = reward_id_t::from_hex<reward_id_t>("F0" + std::string(56, 'F'));
            const auto script1 = reward_id_t::from_hex<reward_id_t>("F1" + std::string(56, '2'));
            storage::block_info block {};
            block.era = 7;
            cbor::encoder body {}, witnesses {};
            body.map(4).uint(0).array(0).uint(1).array(0).uint(2).uint(0);
            body.uint(5).map(3);
            for (const auto &account: { script1, key0, script0 })
                body.bytes(account).uint(1);
            witnesses.map(0);
            context ctx { std::move(body.cbor()), std::move(witnesses.cbor()), block };
            expect(ctx.redeemer_script({ redeemer_tag::reward, 0 }) == script_hash { script0.hash() });
            // The network-0 key occupies index 1, before the network-1 script.
            expect(ctx.redeemer_script({ redeemer_tag::reward, 2 }) == script_hash { script1.hash() });
        };
        "total redeemer budget"_test = [] {
            const context::redeemer_map redeemers {
                { redeemer_id { redeemer_tag::spend, 0 },
                    tx_redeemer { redeemer_tag::spend, 0, {}, ex_units { 4, 7 } } },
                { redeemer_id { redeemer_tag::mint, 0 },
                    tx_redeemer { redeemer_tag::mint, 0, {}, ex_units { 6, 13 } } }
            };
            expect_equal(ex_units { 10, 20 }, context::validate_redeemer_budgets(redeemers, { 10, 20 }));
            expect(throws([&] { context::validate_redeemer_budgets(redeemers, { 9, 20 }); }));
            expect(throws([&] { context::validate_redeemer_budgets(redeemers, { 10, 19 }); }));
        };
        "total redeemer budget cannot overflow"_test = [] {
            const auto max = std::numeric_limits<uint64_t>::max();
            const context::redeemer_map redeemers {
                { redeemer_id { redeemer_tag::spend, 0 },
                    tx_redeemer { redeemer_tag::spend, 0, {}, ex_units { max, max } } },
                { redeemer_id { redeemer_tag::mint, 0 },
                    tx_redeemer { redeemer_tag::mint, 0, {}, ex_units { 1, 1 } } }
            };
            expect(throws([&] { context::validate_redeemer_budgets(redeemers, { max, max }); }));
        };
        "stored context validation"_test = [] {
            stored_tx_context stored_ctx {};
            expect_equal(stored_tx_context::current_format_version, stored_ctx.format_version);
            expect(throws([&] { stored_ctx.validate_format(); }));
            stored_ctx.protocol_ver = { 10, 2 };
            expect(nothrow([&] { stored_ctx.validate_format(); }));
            --stored_ctx.format_version;
            expect(throws([&] { stored_ctx.validate_format(); }));
        };
    };
};
