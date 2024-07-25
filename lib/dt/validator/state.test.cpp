/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/validator/state.hpp>
#include <dt/test.hpp>

namespace {
    using namespace daedalus_turbo;

    static void update_params(validator::state &st, const uint64_t slot, const cardano::param_update &update)
    {
        const cardano::slot slot_obj { slot, cardano::config::get() };
        for (const auto &[deleg_id, meta]: cardano::config::get().shelley_delegates) {
            st.propose_update(slot, { .pool_id=deleg_id, .epoch=slot_obj.epoch(), .update=update });
        }
    }
}

suite validator_state_suite = [] {
    "validator::state"_test = [] {
        "empty"_test = [] {
            validator::state st {};
            expect(st.epoch() == 0_ull);
            expect(st.end_offset() == 0_ull);
            expect(st.pool_stake_dist().empty());
        };
        "finish_epoch"_test = [] {
            validator::state st {};
            test_same(st.params().protocol_ver.major, 0);
            update_params(st, cardano::slot { 1, cardano::config::get() }, { .protocol_ver=cardano::protocol_version { 2, 0 } });
            test_same(st.treasury(), 0);
            test_same(st.reserves(), 0);
            st.start_epoch();
            st.process_block(20000, 2, 0, 0);
            cardano::config::get().shelley_start_slot(0);
            test_same(st.treasury(), 0);
            test_same(st.reserves(), 13887515255000000ULL);
            test_same(st.params().protocol_ver.major, 2);
            test_same(st.treasury(), 0);
            st.process_block(40000, 2, 400000, 0);
            st.compute_rewards_if_ready();
            st.start_epoch();
            test_same(st.treasury(), 8332509153000ULL);
            st.start_epoch();
            test_same(st.epoch(), 2);
        };
        "clear"_test = [] {
            file::tmp tmp_state { "validator-state-test" };
            validator::state st {};
            update_params(st, cardano::slot { 1, cardano::config::get() }, { .protocol_ver=cardano::protocol_version { 8, 0 } });
            st.start_epoch();
            st.reserves(10'000'000'000'000'000ULL);
            st.start_epoch();
            st.clear();
            validator::state st2 {};
            expect(st == st2);
        };
        "save and load"_test = [] {
            file::tmp tmp_state { "validator-state-test" };
            validator::state st {};
            update_params(st, 1, { .protocol_ver=cardano::protocol_version { 8, 0 } });
            st.start_epoch();
            st.reserves(10'000'000'000'000'000ULL);
            st.start_epoch();
            st.save(tmp_state.path());
            validator::state st2 {};
            st2.load(tmp_state.path());
            expect(st == st2);
        };
        "save_node and load_node"_test = [] {

        };
        "register_pool"_test = [] {
            validator::state st {};
            update_params(st, 1, { .protocol_ver=cardano::protocol_version { 8, 0 } });
            st.start_epoch();
            const auto pool_id = cardano::key_hash::from_hex("00000000000000000000000000000000000000000000000000000000");
            st.register_pool(cardano::pool_reg {
                .pool_id=pool_id,
                .cost=200'000'000
            });
            expect(st.pool_params().contains(pool_id));
            expect(st.pool_params().at(pool_id).cost == 200'000'000);
            expect(st.pool_params_future().empty());
            st.register_pool(cardano::pool_reg {
                .pool_id=pool_id,
                .cost=300'000'000
            });
            expect(!st.pool_params_future().empty());
            expect(st.pool_params().at(pool_id).cost == 200'000'000);
            expect(st.pool_params_future().at(pool_id).cost == 300'000'000);
            expect(st.pool_params_mark().empty());
            st.start_epoch();
            expect(st.pool_params().at(pool_id).cost == 300'000'000);
            expect(st.pool_params_mark().at(pool_id).cost == 200'000'000);
            expect(st.pool_params_future().empty());
        };
        "track_eras"_test = [] {
            validator::state st {};
            expect(nothrow([&] { st.track_era(0, 22); }));
            expect(st.eras().empty());
            expect(nothrow([&] { st.track_era(1, 22); }));
            expect(throws([&] { st.track_era(1, 20); }));
            expect(nothrow([&] { st.track_era(1, 40); }));
            expect(nothrow([&] { st.track_era(2, 100); }));
            expect(throws([&] { st.track_era(2, 99); }));
            expect(throws([&] { st.track_era(3, 99); }));
            expect(nothrow([&] { st.track_era(3, 432101); }));
            expect(throws([&] { st.track_era(2, 102); }));
            const auto eras = st.eras();
            expect(eras.size() == 3) << eras.size();
            expect(eras.at(0) == 22) << eras.at(0);
            expect(eras.at(1) == 100) << eras.at(1);
            expect(eras.at(2) == 432100) << eras.at(2);
        };
    };
};
