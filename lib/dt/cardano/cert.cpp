/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/cert.hpp>

namespace daedalus_turbo::cardano {
    cert_any_t::value_type cert_any_t::from_cbor(const cbor::value &v)
    {
        using conway::optional_anchor_t;
        const auto &cert = v.array();
        switch (const auto typ = cert.at(0).uint(); typ) {
            case 0: return stake_reg_cert { credential_t::from_cbor(cert.at(1)) };
            case 1: return stake_dereg_cert { credential_t::from_cbor(cert.at(1)) };
            case 2: return stake_deleg_cert {
                credential_t::from_cbor(cert.at(1)),
                pool_hash::from_cbor(cert.at(2))
            };
            case 3: return pool_reg_cert::from_cbor(v);
            case 4: return pool_retire_cert::from_cbor(v);
            case 5: return genesis_deleg_cert { v };
            case 6: return instant_reward_cert { v };
            case 7: return reg_cert {
                credential_t::from_cbor(cert.at(1)),
                cert.at(2).uint()
            };
            case 8: return unreg_cert {
                credential_t::from_cbor(cert.at(1)),
                cert.at(2).uint()
            };
            case 9: return vote_deleg_cert {
                credential_t::from_cbor(cert.at(1)),
                drep_t::from_cbor(cert.at(2))
            };
            case 10: return stake_vote_deleg_cert {
                credential_t::from_cbor(cert.at(1)),
                pool_hash::from_cbor(cert.at(2)),
                drep_t::from_cbor(cert.at(3))
            };
            case 11: return stake_reg_deleg_cert {
                credential_t::from_cbor(cert.at(1)),
                pool_hash::from_cbor(cert.at(2)),
                cert.at(3).uint()
            };
            case 12: return vote_reg_deleg_cert {
                credential_t::from_cbor(cert.at(1)),
                drep_t::from_cbor(cert.at(2)),
                cert.at(3).uint()
            };
            case 13: return stake_vote_reg_deleg_cert {
                credential_t::from_cbor(cert.at(1)),
                pool_hash::from_cbor(cert.at(2)),
                drep_t::from_cbor(cert.at(3)),
                cert.at(4).uint()
            };
            case 14: return auth_committee_hot_cert {
                credential_t::from_cbor(cert.at(1)),
                credential_t::from_cbor(cert.at(2))
            };
            case 15: return resign_committee_cold_cert {
                credential_t::from_cbor(cert.at(1)),
                optional_anchor_t::from_cbor(cert.at(2))
            };
            case 16: return reg_drep_cert {
                credential_t::from_cbor(cert.at(1)),
                cert.at(2).uint(),
                optional_anchor_t::from_cbor(cert.at(3))
            };
            case 17: return unreg_drep_cert {
                credential_t::from_cbor(cert.at(1)),
                cert.at(2).uint()
            };
            case 18: return update_drep_cert {
                credential_t::from_cbor(cert.at(1)),
                optional_anchor_t::from_cbor(cert.at(2))
            };
            default:
                throw error(fmt::format("unsupported cert type: {}", typ));
        }
    }

    cert_any_t::cert_any_t(value_type &&v): val { std::move(v) }
    {
    }

    cert_any_t::cert_any_t(const cbor::value &v): val { from_cbor(v) }
    {
    }

    std::optional<credential_t> cert_any_t::signing_cred() const
    {
        std::optional<credential_t> cred {};
        std::visit([&](const auto &c) {
            using T = std::decay_t<decltype(c)>;
            if constexpr (std::is_same_v<T, auth_committee_hot_cert>
                    || std::is_same_v<T, resign_committee_cold_cert>) {
                cred.emplace(c.cold_id);
            } else if constexpr (std::is_same_v<T, reg_drep_cert>
                   || std::is_same_v<T, unreg_drep_cert>
                   || std::is_same_v<T, update_drep_cert>) {
                cred.emplace(c.drep_id);
            } else if constexpr (std::is_same_v<T, pool_reg_cert>
                    || std::is_same_v<T, pool_retire_cert>) {
                cred.emplace(c.pool_id, false);
            } else if constexpr (std::is_same_v<T, genesis_deleg_cert>) {
                cred.emplace(c.hash, false);
            } else if constexpr (std::is_same_v<T, stake_reg_cert>) {
                // nothing - stake registration does not require certification
            } else if constexpr (std::is_same_v<T, instant_reward_cert>) {
                // nothing here - a quorum of genesis signers is checked in a different way
            } else {
                cred.emplace(c.stake_id);
            }
        }, val);
        return cred;
    }
}
