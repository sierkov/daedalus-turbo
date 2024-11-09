/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/common.hpp>

namespace daedalus_turbo::cardano {
    redeemer_tag redeemer_tag_from_cbor(const cbor::value &v)
    {
        switch (const auto typ = v.uint(); typ) {
            case 0: return redeemer_tag::spend;
            case 1: return redeemer_tag::mint;
            case 2: return redeemer_tag::cert;
            case 3: return redeemer_tag::reward;
            case 4: return redeemer_tag::vote;
            case 5: return redeemer_tag::propose;
            default: throw error("unsupported redeemer tag: {}", typ);
        }
    }

    pool_params pool_params::from_cbor(const cbor::array &cert, const size_t base_idx)
    {
        const address reward_addr { cert.at(base_idx + 5).buf() };
        pool_params params {};
        params.vrf_vkey = cert.at(base_idx + 1).buf();
        params.pledge = cert.at(base_idx + 2).uint();
        params.cost = cert.at(base_idx + 3).uint();
        params.margin = rational_u64 {
                cert.at(base_idx + 4).tag().second->array().at(0).uint(),
                cert.at(base_idx + 4).tag().second->array().at(1).uint(),
            };
        params.reward_id = reward_addr.stake_id();
        params.reward_network = reward_addr.network();
        {
            const auto &owners_raw = cert.at(base_idx + 6);
            const auto &owners = (owners_raw.type == CBOR_TAG ? *owners_raw.tag().second : owners_raw).array();
            for (const auto &addr: owners)
                params.owners.emplace(stake_ident { addr.buf(), false });
        }
        for (const auto &relay: cert.at(base_idx + 7).array()) {
            const auto &r_items = relay.array();
            switch (r_items.at(0).uint()) {
                case 0: {
                    relay_addr ra {};
                    if (r_items.at(1).type != CBOR_SIMPLE_NULL)
                        ra.port.emplace(static_cast<uint16_t>(r_items.at(1).uint()));
                    if (r_items.at(2).type != CBOR_SIMPLE_NULL)
                        ra.ipv4.emplace(r_items.at(2).buf());
                    if (r_items.at(3).type != CBOR_SIMPLE_NULL)
                        ra.ipv6.emplace(r_items.at(3).buf());
                    params.relays.emplace_back(std::move(ra));
                    break;
                } case 1: {
                    relay_host rh { .host=std::string { r_items.at(2).text() }};
                    if (r_items.at(1).type != CBOR_SIMPLE_NULL)
                        rh.port.emplace(static_cast<uint16_t>(r_items.at(1).uint()));
                    params.relays.emplace_back(std::move(rh));
                    break;
                } case 2: {
                    params.relays.emplace_back(relay_dns { std::string { r_items.at(1).text() } });
                    break;
                }
                default:
                    throw error("unsupported relay value: {}", relay);
            }
        }
        if (cert.at(base_idx + 8).type != CBOR_SIMPLE_NULL)
            params.metadata.emplace(std::string { cert.at(base_idx + 8).at(0).text() }, cert.at(base_idx + 8).at(1).buf());
        return params;
    }

    pool_params::pool_params(const cbor::value &v):
        pool_params { from_cbor(v.array()) }
    {
    }

    void pool_params::to_cbor(cbor::encoder &enc, const pool_hash &pool_id) const
    {
        enc.array(9);
        enc.bytes(pool_id);
        enc.bytes(vrf_vkey);
        enc.uint(pledge);
        enc.uint(cost);
        enc.rational(margin);
        uint8_vector reward_addr {};
        reward_addr << ((reward_id.script ? 0xF0 : 0xE0) | (reward_network & 0xF)) << reward_id.hash;
        enc.bytes(reward_addr);
        enc.set(owners.size(), [&] {
            for (const auto &stake_id: owners)
                enc.bytes(stake_id.hash);
        });
        enc.array_compact(relays.size(), [&] {
            for (const auto &relay: relays) {
                switch (relay.index()) {
                    case 0: {
                        const auto &ra = std::get<cardano::relay_addr>(relay);
                        enc.array(4).uint(0);
                        if (ra.port)
                            enc.uint(*ra.port);
                        else
                            enc.s_null();
                        if (ra.ipv4)
                            enc.bytes(*ra.ipv4);
                        else
                            enc.s_null();
                        if (ra.ipv6)
                            enc.bytes(*ra.ipv6);
                        else
                            enc.s_null();
                        break;
                    }
                    case 1: {
                        const auto &rh = std::get<cardano::relay_host>(relay);
                        enc.array(3).uint(1);
                        if (rh.port)
                            enc.uint(*rh.port);
                        else
                            enc.s_null();
                        enc.text(rh.host);
                        break;
                    }
                    case 2: {
                        const auto &rd = std::get<cardano::relay_dns>(relay);
                        enc.array(2).uint(2).text(rd.name);
                        break;
                    }
                    default:
                        throw error("unsupported relay variant index: {}", relay.index());
                }
            }
        });
        if (metadata)
            enc.array(2).text(metadata->url).bytes(metadata->hash);
        else
            enc.s_null();
    }

    void tx::foreach_set(const cbor_value &set_raw, const std::function<void(const cbor_value &, size_t)> &observer) const
    {
        set<buffer> unique {};
        for (const auto &v: set_raw.array()) {
            const auto prev_size = unique.size();
            if (const auto [it, created] = unique.emplace(v.raw_span()); created)
                observer(v, prev_size);
        }
    }
}
