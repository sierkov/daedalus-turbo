/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_LEDGER_CONWAY_HPP
#define DAEDALUS_TURBO_CARDANO_LEDGER_CONWAY_HPP

#include <dt/cardano/conway.hpp>
#include <dt/cardano/ledger/babbage.hpp>

namespace daedalus_turbo::cardano::ledger::conway {
    using namespace cardano::conway;

    struct vrf_state: babbage::vrf_state {
        vrf_state(babbage::vrf_state &&);
    };

    struct drep_info_t {
        uint64_t deposited = 0;
        optional_t<anchor_t> anchor {};
        uint64_t expire_epoch = 0;
        set_t<credential_t> delegs {};

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.deposited, self.anchor, self.expire_epoch, self.delegs);
        }

        static uint64_t compute_expire_epoch(const protocol_params &pp, uint64_t current_epoch);
        void to_cbor(cbor::encoder &) const;
    };

    struct gov_action_state_t {
        proposal_procedure_t proposal {};
        uint64_t proposed_in = 0;
        uint64_t expires_after = 0;
        map<credential_t, voting_procedure_t> committee_votes {};
        map<credential_t, voting_procedure_t> drep_votes {};
        map<pool_hash, voting_procedure_t> pool_votes {};

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.proposal, self.proposed_in, self.expires_after,
                self.committee_votes, self.drep_votes, self.pool_votes);
        }

        void to_cbor(cbor::encoder &, const gov_action_id_t &) const;
    };

    struct committee_t {
        struct new_t {};
        struct resigned_t {};
        using hot_key_t = std::variant<new_t, resigned_t, credential_t>;
        using member_map = map<credential_t, uint64_t>;
        using member_key_map = map<credential_t, hot_key_t>;

        member_map members {};
        rational_u64 threshold { 2, 3 };

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.members, self.threshold);
        }

        static committee_t from_json(const json::value &);
        void to_cbor(cbor::encoder &) const;
    };

    struct enact_state_t {
        optional_t<committee_t> committee {};
        constitution_t constitution {};
        protocol_params params {};
        protocol_params prev_params {};
        uint64_t treasury = 0;
        stake_distribution withdrawals {};
        gov_action_id_list prev_param_update_gids {};
        gov_action_id_list prev_hard_fork_gids {};
        gov_action_id_list prev_committee_gids {};
        gov_action_id_list prev_constitution_gids {};

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.committee, self.constitution,
                self.params, self.prev_params, self.treasury, self.withdrawals,
                self.prev_param_update_gids, self.prev_hard_fork_gids,
                self.prev_committee_gids, self.prev_constitution_gids);
        }
    };

    using proposal_map = map<gov_action_id_t, gov_action_state_t>;
    using proposal_map_copy = map<gov_action_id_t, gov_action_state_t>;
    using gov_action_item_t = std::pair<gov_action_id_t, gov_action_state_t>;
    using proposal_list = vector<gov_action_item_t>;
    using drep_distr_t = map<drep_t, uint64_t>;
    using drep_info_map = map<credential_t, drep_info_t>;
    using drep_info_map_copy = static_map<credential_t, drep_info_t>;

    struct pulsing_data_t {
        proposal_map_copy proposals {};
        drep_info_map_copy drep_state {};
        drep_distr_t drep_voting_power {};
        pool_stake_distribution pool_voting_power {};
        bool drep_state_updated = false;

        void to_zpp(parallel_serializer &) const;
        void from_zpp(parallel_decoder &);
    };

    struct state: babbage::state {
        state();
        state(babbage::state &&);
        void from_zpp(parallel_decoder &) override;
        void to_zpp(parallel_serializer &) const override;
        using babbage::state::process_cert;
        void start_epoch(std::optional<uint64_t> new_epoch) override;
        bool has_drep(const credential_t &id) const override;
        void process_cert(const cert_any_t &, const cert_loc_t &loc) override;
        virtual void process_cert(const reg_cert &, const cert_loc_t &);
        virtual void process_cert(const unreg_cert &, const cert_loc_t &);
        virtual void process_cert(const vote_deleg_cert &, const cert_loc_t &);
        virtual void process_cert(const stake_vote_deleg_cert &, const cert_loc_t &);
        virtual void process_cert(const stake_reg_deleg_cert &, const cert_loc_t &);
        virtual void process_cert(const vote_reg_deleg_cert &, const cert_loc_t &);
        virtual void process_cert(const stake_vote_reg_deleg_cert &, const cert_loc_t &);
        virtual void process_cert(const auth_committee_hot_cert &, const cert_loc_t &);
        virtual void process_cert(const resign_committee_cold_cert &, const cert_loc_t &);
        virtual void process_cert(const reg_drep_cert &, const cert_loc_t &);
        virtual void process_cert(const unreg_drep_cert &, const cert_loc_t &);
        virtual void process_cert(const update_drep_cert &, const cert_loc_t &);
        virtual void process_proposal(const proposal_t &, const cert_loc_t &);
        virtual void process_vote(const vote_info_t &, const cert_loc_t &);

        virtual bool has_gov_action(const gov_action_id_t &) const;
        virtual const gov_action_state_t &gov_action(const gov_action_id_t &) const;
        virtual const optional_t<committee_t> &committee() const;
    protected:
        enum class default_vote_t {
            abstain, no_confidence, no
        };

        struct voting_threshold_t {
            enum type_t { no_voting_threshold, no_voting_allowed, threshold };
            type_t typ { no_voting_allowed };
            std::optional<rational_u64> val {};
        };

        struct ratify_state_t {
            enact_state_t new_state {};
            proposal_list enacted {};
            set<gov_action_id_t> expired {};
            bool delayed = false;

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.new_state, self.enacted, self.expired, self.delayed);
            }
        };

        enact_state_t _enact_state {};
        ratify_state_t _ratify_state {};
        pulsing_data_t _pulsing_data {};
        committee_t::member_key_map _committee_hot_keys {};
        drep_info_map _drep_state {};
        uint64_t _num_dormant_epochs = 0;
        proposal_map _proposals {};
        uint64_t _donations = 0;
        std::optional<uint64_t> _conway_start_epoch {};

        // previously public method
        virtual void delegate_vote(const stake_ident &, const drep_t &, const cert_loc_t &);

        void _add_encode_task(parallel_serializer &, const encode_cbor_func &) const override;
        void _apply_conway_params(protocol_params &p) const;
        void _donations_to_cbor(cbor::encoder &) const override;
        void _params_to_cbor(cbor::encoder &enc, const protocol_params &params) const override;
        void _protocol_state_to_cbor(cbor::encoder &) const override;
        void _stake_distrib_to_cbor(cbor::encoder &) const override;
        void _stake_pointers_to_cbor(cbor::encoder &) const override;
        void _process_block_updates(block_update_list &&) override;
        void _process_timed_update(tx_out_ref_list &, timed_update_t &&) override;
        void _tick(uint64_t slot) override;

        // governance: Ratify related internal methods

        // supporting methods

        static bool _check_threshold(const voting_threshold_t &t, const rational_u64 &r);
        rational_u64 _param_update_threshold(const param_update_t &upd, const drep_voting_thresholds_t &t) const;
        voting_threshold_t _pool_voting_threshold(const gov_action_t &ga) const;
        voting_threshold_t _drep_voting_threshold(const gov_action_t &ga) const;
        default_vote_t _pool_default_vote(const pool_hash &) const;

        drep_distr_t _compute_drep_voting_power() const;
        pool_stake_distribution _compute_pool_voting_power() const;

        bool _committee_accepted(const enact_state_t &st, const gov_action_state_t &ga) const;
        bool _dreps_accepted(const gov_action_state_t &ga) const;
        bool _pools_accepted(const gov_action_state_t &ga) const;
        bool _accepted_by_everyone(const enact_state_t &st, const gov_action_state_t &gas) const;

        // state modifying methods

        void _transfer_treasury_withdrawals(const stake_distribution &rewards);
        void _enact(enact_state_t &st, const gov_action_id_t &gid, const gov_action_t &ga);
        void _finalize_gov_actions();
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::cardano::ledger::conway::vrf_state>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", static_cast<const daedalus_turbo::cardano::ledger::babbage::vrf_state &>(v));
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::ledger::conway::anchor_t>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "url: {} hash: {}", v.url, v.hash);
        }
    };

    template<typename T>
    struct formatter<daedalus_turbo::cardano::ledger::conway::optional_t<T>>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            if (v)
                return fmt::format_to(ctx.out(), "{}", *v);
            return fmt::format_to(ctx.out(), "std::nullopt_t");
        }
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_LEDGER_CONWAY_HPP