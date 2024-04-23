/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

//#include <dt/validator/state.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
//using namespace daedalus_turbo::validator;

suite validator_state_suite = [] {
    "validator::state"_test = [] {
        /*"empty"_test = [] {
            state st {};
            expect(st.epoch() == 0_ull);
            expect(st.end_offset() == 0_ull);
            expect(st.stake_dist().empty());
            expect(st.pbft_pools().empty());
        };
        "finish_epoch"_test = [] {
            state st {};
            expect(st.params().protocol_ver.major == 1_ull);
            st.propose_update(1, cardano::param_update { .protocol_ver=cardano::protocol_version { 8, 0 } });
            expect(st.treasury() == 0_ull);
            st.start_epoch();
            expect(st.reserves() == 0_ull);
            st.reserves(10'000'000'000'000'000ULL);
            expect(st.reserves() == 10'000'000'000'000'000_ull);
            expect(st.params().protocol_ver.major == 8_ull);
            st.finish_epoch();
            expect(st.treasury() == 0_ull);
            st.start_epoch();
            expect(st.treasury() == 6000000000000_ull);
        };*/
    };
};
