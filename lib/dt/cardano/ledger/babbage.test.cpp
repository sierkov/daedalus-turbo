/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/ledger/babbage.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace cardano;
using namespace ledger;

suite cardano_ledger_babbage_vrf_state_suite = [] {
    "cardano::ledger::babbage::vrf_state"_test = [] {
        "max_epoch_slot"_test = [] {
            ledger::babbage::vrf_state st { ledger::shelley::vrf_state {} };
            test_same(432000 - 129600, st.max_epoch_slot());
        };
        "cbor load/save"_test = [] {
            ledger::babbage::vrf_state st { ledger::shelley::vrf_state {} };
            const auto exp_cbor = file::read(install_path("data/ledger/babbage-vrf-state.cbor"));
            st.from_cbor(cbor::parse(exp_cbor));
            const auto act_cbor = st.cbor();
            test_same(exp_cbor.size(), act_cbor.size());
            test_same(exp_cbor, act_cbor);
        };
    };
};