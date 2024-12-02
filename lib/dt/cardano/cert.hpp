/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_CERT_HPP
#define DAEDALUS_TURBO_CARDANO_CERT_HPP

#include <dt/config.hpp>
#include <dt/cardano/types.hpp>
#include <dt/cardano/shelley.hpp>
#include <dt/cardano/conway.hpp>

namespace daedalus_turbo::cardano {
    using shelley::stake_reg_cert;
    using shelley::stake_dereg_cert;
    using shelley::stake_deleg_cert;
    using shelley::pool_reg_cert;
    using shelley::pool_retire_cert;
    using shelley::genesis_deleg_cert;
    using shelley::instant_reward_cert;
    using conway::reg_cert;
    using conway::unreg_cert;
    using conway::vote_deleg_cert;
    using conway::stake_vote_deleg_cert;
    using conway::stake_reg_deleg_cert;
    using conway::vote_reg_deleg_cert;
    using conway::stake_vote_reg_deleg_cert;
    using conway::auth_committee_hot_cert;
    using conway::resign_committee_cold_cert;
    using conway::reg_drep_cert;
    using conway::unreg_drep_cert;
    using conway::update_drep_cert;

    struct cert_any_t {
        using value_type = std::variant<
            stake_reg_cert, stake_dereg_cert, stake_deleg_cert,
            pool_reg_cert, pool_retire_cert,
            genesis_deleg_cert, instant_reward_cert,
            reg_cert, unreg_cert, vote_deleg_cert,
            stake_vote_deleg_cert, stake_reg_deleg_cert, vote_reg_deleg_cert,
            stake_vote_reg_deleg_cert, auth_committee_hot_cert, resign_committee_cold_cert,
            reg_drep_cert, unreg_drep_cert, update_drep_cert
        >;
        value_type val;

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.val);
        }

        static value_type from_cbor(const cbor::value &v);

        cert_any_t() =delete;
        cert_any_t(value_type &&);
        cert_any_t(const cbor::value &);
        std::optional<credential_t> signing_cred() const;
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_CERT_HPP