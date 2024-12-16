/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/ledger/conway.hpp>
#include <dt/cardano/ledger/state.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace cardano;
using namespace ledger::conway;

suite cardano_ledger_conway_suite = [] {
    "cardano::ledger::conway::state"_test = [] {
        "reg/unreg drep"_test = [] {
            state st {};
            const credential_t id { blake2b<key_hash>(std::string_view { "0" }), false };
            expect(!st.has_drep(id));
            st.process_cert(reg_drep_cert { id }, cert_loc_t { 0, 0, 1 });
            expect(st.has_drep(id));
            st.process_cert(unreg_drep_cert {id }, cert_loc_t { 1, 0, 0 });
            expect(!st.has_drep(id));
        };
        "reg/unreg stake"_test = [] {
            state st {};
            const stake_ident id { blake2b<key_hash>(std::string_view { "0" }), false };
            expect(!st.has_stake(id));
            st.process_cert(reg_cert { id }, cert_loc_t { 0, 0, 1 });
            expect(st.has_stake(id));
            st.process_cert(unreg_cert { id }, cert_loc_t { 1, 0, 0 });
            expect(!st.has_drep(id));
        };
        "update_committee"_test = [] {
            state st {};
            expect(st.committee().has_value());
            if (const auto &cc = st.committee(); cc) {
                test_same(7, cc->members.size());
                test_same(rational_u64 { 2, 3 }, cc->threshold);
            }
            {
                const stake_ident return_addr { blake2b<key_hash>(std::string_view { "A" }), false };
                const gov_action_id_t gid { blake2b<tx_hash>(std::string_view { "A" }), 0 };
                proposal_procedure_t pp {};
                pp.return_addr = return_addr;
                {
                    gov_action_t::update_committee_t c_upd {};
                    c_upd.members_to_remove.emplace(credential_t { script_hash::from_hex("df0e83bde65416dade5b1f97e7f115cc1ff999550ad968850783fe50"), true });
                    c_upd.new_threshold = { 5, 6 };
                    pp.action = gov_action_t { std::move(c_upd) };
                }
                const proposal_t p { gid, std::move(pp) };
                st.process_proposal(p, cert_loc_t { 0, 0, 0 });
            }
            expect(st.committee().has_value());
            if (const auto &cc = st.committee(); cc) {
                test_same(7, cc->members.size());
                test_same(rational_u64 { 2, 3 }, cc->threshold);
            }
        };
        "parameter update"_test = [] {
            state st {};
            gov_action_id_t gid {};
            gid.tx_id = blake2b<tx_hash>(std::string_view { "A" });
            proposal_t p {};
            p.id = gid;
            const cert_loc_t p_loc { 0, 0, 0 };
            st.process_proposal(p, p_loc);
            {
                const auto &ga_st = st.gov_action(gid);
                test_same(0, ga_st.drep_votes.size());
            }

            const credential_t drep_id { blake2b<key_hash>(std::string_view { "B" }), false };
            voter_t voter {};
            voter.type = voter_t::drep_key;
            voter.hash = drep_id.hash;
            const cert_loc_t v_loc { 1, 0, 0 };
            const voting_procedure_t vote_proc { vote_t::yes, optional_t<anchor_t> {} };
            const vote_info_t vp { voter, gid, vote_proc };
            expect(throws([&] { st.process_vote(vp, v_loc); }));

            st.process_cert(reg_drep_cert { drep_id }, cert_loc_t { 0, 0, 1 });
            expect(nothrow([&] { st.process_vote(vp, v_loc); }));
            {
                const auto &ga_st = st.gov_action(gid);
                test_same(1, ga_st.drep_votes.size());
            }
            const auto ga_lifetime = st.params().gov_action_lifetime;
            test_same(6, ga_lifetime);
            st.process_block(100, 1); // needed so that start_epoch accepts progress
            for (size_t e = 0; e < ga_lifetime; ++e) {
                st.start_epoch({});
                expect(st.has_gov_action(gid));
            }
            st.start_epoch({});
            expect(!st.has_gov_action(gid));
        };
    };
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