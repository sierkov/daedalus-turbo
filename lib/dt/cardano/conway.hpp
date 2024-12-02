/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_CONWAY_HPP
#define DAEDALUS_TURBO_CARDANO_CONWAY_HPP

#include <dt/cardano/shelley.hpp>
#include <dt/cardano/babbage.hpp>

namespace daedalus_turbo::cardano::conway {
    struct anchor_t {
        std::string url;
        datum_hash hash;

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.url, self.hash);
        }

        anchor_t() =default;
        anchor_t(const cbor::value &);
        anchor_t(const json::value &);
        void to_cbor(cbor::encoder &) const;
    };

    template<typename T>
    struct optional_t: std::optional<T> {
        optional_t() =default;

        optional_t(const cbor::value &v)
        {
            if (!v.is_null())
                std::optional<T>::emplace(v);
        }

        void to_cbor(cbor::encoder &enc) const
        {
            if (std::optional<T>::has_value()) {
                std::optional<T>::value().to_cbor(enc);
            } else {
                enc.array(0);
            }
        }

        optional_t &operator=(const std::optional<T>::value_type &v)
        {
            std::optional<T>::emplace(v);
            return *this;
        }

        optional_t &operator=(const std::nullopt_t)
        {
            std::optional<T>::reset();
            return *this;
        }
    };

    typedef uint32_t epoch_interval;

    struct positive_coin_t {
        positive_coin_t(const uint64_t coin): _coin { coin }
        {
            if (!_coin) [[unlikely]]
                throw error("positive_coin_t cannot be 0!");
        }

        operator uint64_t() const noexcept
        {
            return _coin;
        }
    private:
        uint64_t _coin;
    };

    struct non_negative_interval {
        uint64_t start;
        uint64_t end;
    };

    struct param_update_t {
        std::optional<uint64_t> min_fee_a {}; // 0
        std::optional<uint64_t> min_fee_b {}; // 1
        std::optional<uint32_t> max_block_body_size {}; // 2
        std::optional<uint32_t> max_transaction_size {}; // 3
        std::optional<uint16_t> max_block_header_size {}; // 4
        std::optional<uint64_t> key_deposit {}; // 5
        std::optional<uint64_t> pool_deposit {}; // 6
        std::optional<uint32_t> e_max {}; // 7
        std::optional<uint64_t> n_opt {}; // 8
        std::optional<rational_u64> pool_pledge_influence {}; // 9
        std::optional<rational_u64> expansion_rate {}; // 10
        std::optional<rational_u64> treasury_growth_rate {}; // 11
        std::optional<uint64_t> min_pool_cost {}; // 16
        std::optional<uint64_t> lovelace_per_utxo_byte {}; // 17
        std::optional<cardano::plutus_cost_models> plutus_cost_models {}; // 18
        std::optional<cardano::ex_unit_prices> ex_unit_prices {}; // 19
        std::optional<ex_units> max_tx_ex_units {}; // 20
        std::optional<ex_units> max_block_ex_units {}; // 21
        std::optional<uint64_t> max_value_size {}; // 22
        std::optional<uint64_t> max_collateral_pct {}; // 23
        std::optional<uint64_t> max_collateral_inputs {}; // 24
        std::optional<pool_voting_thresholds_t> pool_voting_thresholds {}; // 25
        std::optional<drep_voting_thresholds_t> drep_voting_thresholds {}; // 26
        std::optional<uint16_t> comittee_min_size {}; // 27
        std::optional<uint32_t> comittee_max_term_length {}; // 28
        std::optional<uint32_t> gov_action_lifetime {}; // 29
        std::optional<uint64_t> gov_action_deposit {}; // 30
        std::optional<uint64_t> drep_deposit {}; // 31
        std::optional<uint32_t> drep_activity {}; // 32
        std::optional<uint64_t> min_fee_ref_script_cost_per_byte {}; // 33

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.pool_voting_thresholds, self.drep_voting_thresholds);
        }

        param_update_t() =default;
        param_update_t(const cbor::value &);
    };

    struct gov_action_id_t {
        tx_hash tx_id {};
        uint16_t idx = 0;

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.tx_id, self.idx);
        }

        gov_action_id_t() =default; // necessary for zpp serialization to work
        gov_action_id_t(buffer, uint64_t);
        gov_action_id_t(const cbor::value &v);
        void to_cbor(cbor::encoder &) const;

        bool operator<(const gov_action_id_t &o) const noexcept
        {
            if (const int cmp = memcmp(tx_id.data(), o.tx_id.data(), tx_id.size()); cmp != 0)
                return cmp < 0;
            return idx < o.idx;
        }
    };

    struct gov_action_t {
        struct parameter_change_t {
            optional_t<gov_action_id_t> prev_action_id {};
            param_update_t update {};
            optional_t<script_hash> policy_id {};

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.prev_action_id, self.update, self.policy_id);
            }

            parameter_change_t() =default; // Necessary for ZPP serialization to work
            parameter_change_t(const cbor::value &v);
        };

        struct hard_fork_init_t {
        };

        struct treasury_withdrawals_t {
        };

        struct no_confidence_t {
        };

        struct update_committee_t {
        };

        struct new_constitution_t {
        };

        struct info_action_t {
        };

        using value_type = std::variant<parameter_change_t, hard_fork_init_t, treasury_withdrawals_t,
            no_confidence_t, update_committee_t, new_constitution_t, info_action_t>;

        value_type val { info_action_t {} };

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.val);
        }

        gov_action_t() =default; // necessary for zpp serialization to work
        gov_action_t(const cbor::value &);
        void to_cbor(cbor::encoder &) const;
    };

    enum class vote_t: uint8_t {
        no = 0,
        yes = 1,
        abstain = 2
    };

    struct voting_procedure_t {
        vote_t vote {};
        optional_t<anchor_t> anchor {};

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.vote, self.anchor);
        }

        voting_procedure_t() =default; // necessary for zpp serialization to work
        voting_procedure_t(const cbor::value &);
        void to_cbor(cbor::encoder &) const;
    };

    struct voter_t {
        enum type_t {
            const_comm_key = 0,
            const_comm_script = 1,
            drep_key = 2,
            drep_script = 3,
            pool_key = 4
        };
        type_t type {};
        key_hash hash {};

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.type, self.hash);
        }

        voter_t(const type_t t, const buffer b): type { t }, hash { b }
        {
        }

        voter_t() =default; // necessary for zpp serialization to work
        voter_t(const cbor::value &v);

        bool operator<(const voter_t &o) const noexcept
        {
            if (type != o.type)
                return type < o.type;
            return hash < o.hash;
        }
    };

    struct proposal_t {
        stake_ident stake_id {};
        uint64_t deposit = 0;
        gov_action_id_t action_id {};
        gov_action_t action {};
        anchor_t anchor {};

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.stake_id, self.deposit, self.action_id, self.action, self.anchor);
        }

        proposal_t() =default; // necessary for zpp serialization to work
        proposal_t(const gov_action_id_t &, const cbor::value &v);
    };

    struct reg_cert {
        stake_ident stake_id {};
        uint64_t deposit = 0;
    };

    struct unreg_cert {
        stake_ident stake_id {};
        uint64_t deposit = 0;
    };

    struct vote_deleg_cert {
        stake_ident stake_id {};
        drep_t drep {};
    };

    struct stake_vote_deleg_cert {
        stake_ident stake_id {};
        pool_hash pool_id {};
        drep_t drep {};
    };

    struct stake_reg_deleg_cert {
        stake_ident stake_id {};
        pool_hash pool_id {};
        uint64_t deposit = 0;
    };

    struct vote_reg_deleg_cert {
        stake_ident stake_id {};
        drep_t drep {};
        uint64_t deposit = 0;
    };

    struct stake_vote_reg_deleg_cert {
        stake_ident stake_id {};
        pool_hash pool_id {};
        drep_t drep {};
        uint64_t deposit = 0;
    };

    struct auth_committee_hot_cert {
        credential_t cold_id {};
        credential_t hot_id {};
    };

    struct resign_committee_cold_cert {
        credential_t cold_id {};
        optional_t<anchor_t> anchor {};
    };

    struct reg_drep_cert {
        credential_t drep_id {};
        uint64_t deposit = 0;
        optional_t<anchor_t> anchor {};
    };

    struct unreg_drep_cert {
        credential_t drep_id {};
        uint64_t deposit = 0;
    };

    struct update_drep_cert {
        credential_t drep_id {};
        optional_t<anchor_t> anchor {};
    };

    using shelley::stake_reg_cert;
    using shelley::stake_dereg_cert;
    using shelley::stake_deleg_cert;
    using shelley::pool_reg_cert;
    using shelley::pool_retire_cert;

    struct cert_t {
        using value_type = std::variant<
            stake_reg_cert, stake_dereg_cert, stake_deleg_cert, pool_reg_cert, pool_retire_cert,
            reg_cert, unreg_cert, vote_deleg_cert, stake_vote_deleg_cert, stake_reg_deleg_cert, vote_reg_deleg_cert,
            stake_vote_reg_deleg_cert, auth_committee_hot_cert, resign_committee_cold_cert,
            reg_drep_cert, unreg_drep_cert, update_drep_cert
        >;
        value_type val;

        cert_t() =delete;
        cert_t(const cbor::value &);
        const credential_t &cred() const;
    };

    struct block: babbage::block {
        using babbage::block::block;
        void foreach_tx(const std::function<void(const tx &)> &observer) const override;
        void foreach_invalid_tx(const std::function<void(const tx &)> &observer) const override;
    };

    struct vote_info_t {
        voter_t voter {};
        gov_action_id_t action_id {};
        voting_procedure_t voting_procedure {};

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.voter, self.action_id, self.voting_procedure);
        }
    };

    typedef std::function<void(vote_info_t &&)> vote_observer_t;
    typedef std::function<void(proposal_t &&)> proposal_observer_t;

    struct tx: babbage::tx {
        using babbage::tx::tx;
        void foreach_redeemer(const std::function<void(const tx_redeemer &)> &) const override;
        void foreach_set(const cbor_value &set_raw, const std::function<void(const cbor_value &, size_t)> &observer) const override;
        virtual void foreach_vote(const vote_observer_t &) const;
        virtual void foreach_proposal(const proposal_observer_t &) const;
        virtual std::optional<uint64_t> current_treasury() const;
        uint64_t donation() const override;
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::cardano::conway::positive_coin_t>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::cardano::conway::positive_coin_t &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", daedalus_turbo::cardano::amount { v });
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::conway::gov_action_id_t>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::cardano::conway::gov_action_id_t &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}#{}", v.tx_id, v.idx);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::conway::voter_t::type_t>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::cardano::conway::voter_t::type_t &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using type_t = daedalus_turbo::cardano::conway::voter_t::type_t;
            switch (v) {
                case type_t::const_comm_key: return fmt::format_to(ctx.out(), "committee_key");
                case type_t::const_comm_script: return fmt::format_to(ctx.out(), "committee_script");
                case type_t::drep_key: return fmt::format_to(ctx.out(), "drep_key");
                case type_t::drep_script: return fmt::format_to(ctx.out(), "drep_script");
                case type_t::pool_key: return fmt::format_to(ctx.out(), "pool_key");
                default: throw daedalus_turbo::error("unsupported voter_t::type_t value: {}", static_cast<int>(v));
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::conway::voter_t>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::cardano::conway::voter_t &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}: {}", v.type, v.hash);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::conway::vote_t>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::cardano::conway::vote_t &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using daedalus_turbo::cardano::conway::vote_t;
            switch (v) {
                case vote_t::yes: return fmt::format_to(ctx.out(), "yes");
                case vote_t::no: return fmt::format_to(ctx.out(), "no");
                case vote_t::abstain: return fmt::format_to(ctx.out(), "abstain");
                default: throw daedalus_turbo::error("unsupported vote_t value: {}", static_cast<int>(v));
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::conway::voting_procedure_t>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::cardano::conway::voting_procedure_t &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{} anchor: {}", v.vote, v.anchor);
        }
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_CONWAY_HPP