/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/ledger/conway.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace cardano;
using namespace ledger;

suite cardano_ledger_conway_vrf_state_suite = [] {
    "cardano::ledger::conway::vrf_state"_test = [] {
        "max_epoch_slot"_test = [] {
            ledger::conway::vrf_state st { ledger::babbage::vrf_state { ledger::shelley::vrf_state {} } };
            test_same(432000 - 172800, st.max_epoch_slot());
        };
        "cbor load/save"_test = [] {
            ledger::conway::vrf_state st { ledger::babbage::vrf_state { ledger::shelley::vrf_state {} } };
            const auto exp_cbor = file::read(install_path("data/ledger/conway-vrf-state.cbor"));
            st.from_cbor(cbor::parse(exp_cbor));
            const auto act_cbor = st.cbor();
            test_same(exp_cbor.size(), act_cbor.size());
            test_same(exp_cbor, act_cbor);
        };
    };
};