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
        optional_anchor_t anchor {};
        uint64_t epoch_inactive = 0;

        void to_cbor(cbor::encoder &) const;
    };

    struct state: babbage::state {
        state(babbage::state &&);
        void from_zpp(parallel_decoder &) override;
        void to_zpp(parallel_serializer &) const override;
        using babbage::state::process_cert;
        void start_epoch(std::optional<uint64_t> new_epoch) override;
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
        virtual void delegate_vote(const stake_ident &, const drep_t &);
        virtual void process_proposal(const proposal_t &, const cert_loc_t &);
        virtual void process_vote(const vote_info_t &, const cert_loc_t &);
    protected:
        struct gov_action_state_t {
            uint64_t deposit = 0;
            stake_ident stake_id {};
            gov_action_t action {};
            anchor_t anchor {};
            uint64_t epoch_created = 0;
            uint64_t epoch_expires = 0;
            std::optional<gov_action_id_t> prev_action_id {};
            map<voter_t, voting_procedure_t> votes {};

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.deposit, self.stake_id, self.action, self.anchor,
                    self.epoch_created, self.epoch_expires, self.prev_action_id,
                    self.votes);
            }

            void to_cbor(cbor::encoder &, const gov_action_id_t &) const;
        };

        struct constitution_t {
            anchor_t anchor {};
            script_hash script {};

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.anchor, self.script);
            }

            constitution_t() =default;
            constitution_t(const json::value &);
            void to_cbor(cbor::encoder &) const;
        };

        struct committee_t {
            struct new_t {};
            struct resigned_t {};

            using hot_key_t = std::variant<new_t, resigned_t, credential_t>;

            map<credential_t, uint64_t> members {};
            rational_u64 threshold { 2, 3 };
            map<credential_t, hot_key_t> hot_keys {};

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.members, self.threshold, self.hot_keys);
            }

            committee_t() =default;
            committee_t(const json::value &);
            void to_cbor(cbor::encoder &) const;
        };

        constitution_t _constitution {};
        committee_t _committee {};
        map<credential_t, drep_info_t> _dreps {};
        map<drep_t, uint64_t> _drep_stake {};
        map<gov_action_id_t, gov_action_state_t> _gov_actions {};
        uint64_t _donations = 0;
        std::optional<uint64_t> _conway_start_epoch {};

        void _add_encode_task(parallel_serializer &, const encode_cbor_func &) const override;
        void _apply_conway_params(protocol_params &p) const;
        void _apply_param_update(const cardano::param_update &update) override;
        void _donations_to_cbor(cbor::encoder &) const override;
        void _params_to_cbor(cbor::encoder &enc, const protocol_params &params) const override;
        void _protocol_state_to_cbor(cbor::encoder &) const override;
        void _stake_distrib_to_cbor(cbor::encoder &) const override;
        void _stake_pointers_to_cbor(cbor::encoder &) const override;
        void _process_block_updates(block_update_list &&) override;
        void _process_timed_update(tx_out_ref_list &, timed_update_t &&) override;
        virtual void _calc_gov_action_votes();
        virtual void _finalize_gov_actions();
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

    template<>
    struct formatter<daedalus_turbo::cardano::ledger::conway::optional_anchor_t>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            if (v)
                return fmt::format_to(ctx.out(), "{}", *v);
            return fmt::format_to(ctx.out(), "std::nullopt_t");
        }
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_LEDGER_CONWAY_HPP