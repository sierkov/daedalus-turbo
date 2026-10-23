/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <algorithm>
#include <turbo/cardano/ledger/shelley.hpp>
#include <turbo/cardano/ledger/node-output.hpp>

namespace turbo::cardano::ledger::shelley {
    void state::_params_to_cbor(era_encoder &enc, const protocol_params &params, const node_format format) const
    {
        enc.array(format == node_format::v11_1_3 ? 17 : 18);
        enc.uint(params.min_fee_a);
        enc.uint(params.min_fee_b);
        enc.uint(params.max_block_body_size);
        enc.uint(params.max_transaction_size);
        enc.uint(params.max_block_header_size);
        enc.uint(params.key_deposit);
        enc.uint(params.pool_deposit);
        enc.uint(params.e_max);
        enc.uint(params.n_opt);
        params.pool_pledge_influence.to_cbor(enc);
        params.expansion_rate.to_cbor(enc);
        params.treasury_growth_rate.to_cbor(enc);
        params.decentralization.to_cbor(enc);
        if (!params.extra_entropy)
            enc.array(1).uint(0);
        else
            enc.array(2).uint(1).bytes(*params.extra_entropy);
        if (format == node_format::v11_1_3)
            enc.array(2);
        enc.uint(params.protocol_ver.major);
        enc.uint(params.protocol_ver.minor);
        enc.uint(params.min_utxo_value);
        enc.uint(params.min_pool_cost);
    }

    size_t state::_param_to_cbor(era_encoder &enc, const size_t idx, const std::optional<rational_u64> &val)
    {
        if (val) {
            enc.uint(idx);
            val->to_cbor(enc);
            return 1;
        }
        return 0;
    }

    size_t state::_param_update_common_to_cbor(era_encoder &enc, const param_update &upd)
    {
        size_t cnt = 0;
        cnt += _param_to_cbor(enc, 0, upd.min_fee_a);
        cnt += _param_to_cbor(enc, 1, upd.min_fee_b);
        cnt += _param_to_cbor(enc, 2, upd.max_block_body_size);
        cnt += _param_to_cbor(enc, 3, upd.max_transaction_size);
        cnt += _param_to_cbor(enc, 4, upd.max_block_header_size);
        cnt += _param_to_cbor(enc, 5, upd.key_deposit);
        cnt += _param_to_cbor(enc, 6, upd.pool_deposit);
        cnt += _param_to_cbor(enc, 7, upd.e_max);
        cnt += _param_to_cbor(enc, 8, upd.n_opt);
        cnt += _param_to_cbor(enc, 9, upd.pool_pledge_influence);
        cnt += _param_to_cbor(enc, 10, upd.expansion_rate);
        cnt += _param_to_cbor(enc, 11, upd.treasury_growth_rate);
        cnt += _param_to_cbor(enc, 12, upd.decentralization);
        if (upd.extra_entropy) {
            ++cnt;
            enc.uint(13);
            if (*upd.extra_entropy) {
                enc.array(2);
                enc.uint(1);
                enc.bytes(*(*upd.extra_entropy));
            } else {
                enc.array(1);
                enc.uint(0);
            }
        }
        if (upd.protocol_ver) {
            ++cnt;
            enc.uint(14);
            enc.array(2).uint(upd.protocol_ver->major).uint(upd.protocol_ver->minor);
        }
        return cnt;
    }

    void state::_param_update_to_cbor(era_encoder &enc, const param_update &upd) const
    {
        auto my_enc { enc };
        size_t cnt = _param_update_common_to_cbor(my_enc, upd);
        cnt += _param_to_cbor(my_enc, 15, upd.min_utxo_value);
        enc.map(cnt);
        enc << my_enc;
    }

    void state::_node_save_snapshots(cbor_encoder &ser, const node_format format) const
    {
        const std::vector<std::reference_wrapper<const ledger_copy>> snaps { _mark, _set, _go };
        _add_encode_task(ser, [snaps] (auto &enc) {
            enc.array(snaps.size() + 1);
        });
        for (size_t idx = 0; idx < snaps.size(); ++idx) {
            const auto &snap = snaps.at(idx).get();
            _add_encode_task(ser, [this, &snap, idx, format] (auto &enc) {
                if (format == node_format::v11_1_3) {
                    // ActiveStake combines each nonzero stake with its delegation.
                    enc.array(2);
                    auto stakes { enc };
                    size_t num_stakes = 0;
                    uint64_t total_stake = 0;
                    struct pool_totals { uint64_t stake = 0; size_t delegators = 0; };
                    std::map<pool_hash, pool_totals> totals;
                    for (const auto &[stake_id, acc]: _accounts) {
                        if (const auto &deleg = acc.deleg_copy(idx); deleg) {
                            const auto stake = acc.stake_copy(idx);
                            auto &pool = totals[*deleg];
                            pool.stake += stake;
                            ++pool.delegators;
                            total_stake += stake;
                            if (stake) {
                                ++num_stakes;
                                stake_id.to_cbor(stakes);
                                stakes.array(2).uint(stake).bytes(*deleg);
                            }
                        }
                    }
                    enc.map_compact(num_stakes, [&] { enc << stakes; });
                    enc.map_compact(snap.pool_params.size(), [&] {
                        for (const auto &[pool_id, info]: snap.pool_params) {
                            const auto &p = info.params;
                            const auto it = totals.find(pool_id);
                            const auto pool = it != totals.end() ? it->second : pool_totals {};
                            set_t<key_hash> owners;
                            uint64_t owners_stake = 0;
                            for (const auto &owner: p.owners) {
                                const auto acc = _accounts.find(stake_ident { owner, false });
                                if (acc != _accounts.end() && acc->second.deleg_copy(idx) == pool_id) {
                                    owners.insert(owner);
                                    owners_stake += acc->second.stake_copy(idx);
                                }
                            }
                            enc.bytes(pool_id).array(10).uint(pool.stake);
                            rational_u64 ratio { pool.stake, std::max(uint64_t { 1 }, total_stake) };
                            ratio.normalize();
                            if (enc.era() >= era_t::conway)
                                ratio.to_cbor(enc);
                            else
                                enc.array(2).uint(ratio.numerator).uint(ratio.denominator);
                            owners.to_cbor(enc);
                            enc.uint(owners_stake).bytes(p.vrf_vkey).uint(p.pledge).uint(p.cost);
                            p.margin.to_cbor(enc);
                            enc.uint(pool.delegators);
                            static_cast<stake_ident>(p.reward_id).to_cbor(enc);
                        }
                    });
                    return;
                }
                enc.array(3);
                // Only the stake of delegated stake_ids is of interest
                size_t num_delegs = 0;
                auto delegations { enc }, stakes { enc };
                for (const auto &[stake_id, acc]: _accounts) {
                    const auto &deleg = acc.deleg_copy(idx);
                    if (deleg) {
                        ++num_delegs;
                        stake_id.to_cbor(stakes);
                        stakes.uint(acc.stake_copy(idx));
                        stake_id.to_cbor(delegations);
                        delegations.bytes(*deleg);
                    }
                }
                enc.map_compact(num_delegs, [&] {
                    enc << stakes;
                });
                enc.map_compact(num_delegs, [&] {
                    enc << delegations;
                });
                enc.map_compact(snap.pool_params.size(), [&] {
                    for (const auto &[pool_id, params]: snap.pool_params) {
                        enc.bytes(pool_id);
                        params.params.to_cbor(enc, pool_id);
                    }
                });
            });
        }
        _add_encode_task(ser, [this] (auto &enc) {
            enc.uint(_delta_fees);
        });
    }

    void state::_delegation_gov_to_cbor(era_encoder &enc) const
    {
        enc.array(3).map(0).map(0).uint(0);
    }

    void state::_account_to_cbor(const account_info &acc, era_encoder &enc, const node_format format) const
    {
        enc.array(4);
        if (format == node_format::v11_1_3) {
            acc.ptr->to_cbor(enc);
            enc.uint(acc.reward).uint(acc.deposit);
            if (acc.deleg)
                enc.bytes(*acc.deleg);
            else
                enc.s_null();
            return;
        }
        enc.array(1).array(2).uint(acc.reward).uint(acc.deposit);
        enc.array(1);
        acc.ptr->to_cbor(enc);
        acc.deleg.to_cbor(enc);
        acc.vote_deleg.to_cbor(enc);
    }

    void state::_stake_pointer_stake_to_cbor(era_encoder &enc) const
    {
        enc.map_compact(_ptr_to_stake.size(), [&] {
            for (const auto &[ptr, stake_id]: _ptr_to_stake) {
                ptr.to_cbor(enc);
                stake_id.to_cbor(enc);
            }
        });
    }

    void state::_node_save_ledger_delegation(cbor_encoder &ser, const node_format format) const
    {
        _add_encode_task(ser, [this, format] (auto &enc) {
            // Node 11 removed the placeholder VState from pre-Conway eras.
            if (format == node_format::v11_1_3 && enc.era() < era_t::conway) {
                enc.array(2);
            } else {
                enc.array(3);
                _delegation_gov_to_cbor(enc);
            }
            // poolState
            enc.array(4);
            // The wire layout follows the node version, not the historical protocol.
            if (format == node_format::v11_1_3 || _params.protocol_ver.major >= 11) {
                enc.map_compact(_pool_vrf_key_hashes.size(), [&] {
                    for (const auto &[vrf, occurrences]: _pool_vrf_key_hashes) {
                        enc.bytes(vrf);
                        enc.uint(occurrences);
                    }
                });
                const auto encode_pool_states = [this, &enc, format](const pool_info_map &pools) {
                    enc.map_compact(pools.size(), [&] {
                        for (const auto &[pool_id, info]: pools) {
                            const auto &p = info.params;
                            enc.bytes(pool_id);
                            enc.array(10);
                            enc.bytes(p.vrf_vkey);
                            enc.uint(p.pledge);
                            enc.uint(p.cost);
                            p.margin.to_cbor(enc);
                            static_cast<stake_ident>(p.reward_id).to_cbor(enc);
                            p.owners.to_cbor(enc);
                            p.relays.to_cbor(enc);
                            // StakePoolState uses StrictMaybe; PoolParams uses null.
                            if (format == node_format::v11_1_3) {
                                enc.array(p.metadata ? 1 : 0);
                                if (p.metadata)
                                    p.metadata->to_cbor(enc);
                            } else {
                                p.metadata.to_cbor(enc);
                            }
                            enc.uint(_pool_deposits.at(pool_id));
                            set_t<stake_ident> delegators {};
                            if (const auto it = _active_inv_delegs.find(pool_id); it != _active_inv_delegs.end())
                                delegators.insert(it->second.begin(), it->second.end());
                            delegators.to_cbor(enc);
                        }
                    });
                };
                encode_pool_states(_active_pool_params);
                enc.map_compact(_future_pool_params.size(), [&] {
                    for (const auto &[pool_id, info]: _future_pool_params) {
                        enc.bytes(pool_id);
                        info.params.to_cbor(enc, pool_id);
                    }
                });
                enc.map_compact(_pools_retiring.size(), [&] {
                    for (const auto &[pool_id, epoch]: _pools_retiring) {
                        enc.bytes(pool_id);
                        enc.uint(epoch);
                    }
                });
            } else {
                enc.map_compact(_active_pool_params.size(), [&] {
                    for (const auto &[pool_id, info]: _active_pool_params) {
                        enc.bytes(pool_id);
                        info.params.to_cbor(enc, pool_id);
                    }
                });
                enc.map_compact(_future_pool_params.size(), [&] {
                    for (const auto &[pool_id, info]: _future_pool_params) {
                        enc.bytes(pool_id);
                        info.params.to_cbor(enc, pool_id);
                    }
                });
                enc.map_compact(_pools_retiring.size(), [&] {
                    for (const auto &[pool_id, epoch]: _pools_retiring) {
                        enc.bytes(pool_id);
                        enc.uint(epoch);
                    }
                });
                enc.map_compact(_pool_deposits.size(), [&] {
                    for (const auto &[pool_id, coin]: _pool_deposits) {
                        enc.bytes(pool_id);
                        enc.uint(coin);
                    }
                });
            }

        });
        _add_encode_task(ser, [this, format] (auto &enc) {
            // delegationState
            enc.array(4);
            if (format == node_format::legacy || enc.era() < era_t::conway)
                enc.array(2);
            auto registrations { enc };
            size_t num_creds = 0;
            for (const auto &[stake_id, acc]: _accounts) {
                if (acc.ptr) {
                    ++num_creds;
                    stake_id.to_cbor(registrations);
                    _account_to_cbor(acc, registrations, format);
                }
            }
            enc.map_compact(num_creds, [&] {
                enc << registrations;
            });
        });
        _add_encode_task(ser, [this, format] (auto &enc) {
            if (format == node_format::legacy || enc.era() < era_t::conway)
                _stake_pointer_stake_to_cbor(enc);
        });
        _add_encode_task(ser, [this] (auto &enc) {
            map_to_cbor(enc, _future_shelley_delegs);
            enc.map_compact(_shelley_delegs.size(), [&] {
                for (const auto &[key_hash, info]: _shelley_delegs) {
                    enc.bytes(key_hash);
                    enc.array(2).bytes(info.delegate).bytes(info.vrf);
                }
            });
            // irwd
            enc.array(4);
            enc.map_compact(_instant_rewards_reserves.size(), [&] {
                for (const auto &[stake_id, coin]: _instant_rewards_reserves) {
                    stake_id.to_cbor(enc);
                    enc.uint(coin);
                }
            });
            enc.map_compact(_instant_rewards_treasury.size(), [&] {
                for (const auto &[stake_id, coin]: _instant_rewards_treasury) {
                    stake_id.to_cbor(enc);
                    enc.uint(coin);
                }
            });
            enc.uint(0);
            enc.uint(0);
        });
    }

    void state::_protocol_state_to_cbor(era_encoder &enc, const node_format format) const
    {
        enc.array(5);
        enc.map(_ppups.size());
        for (const auto &[gen_deleg_id, proposal]: _ppups) {
            enc.bytes(gen_deleg_id);
            _param_update_to_cbor(enc, proposal);
        }
        enc.map(_ppups_future.size());
        for (const auto &[gen_deleg_id, proposal]: _ppups_future) {
            enc.bytes(gen_deleg_id);
            _param_update_to_cbor(enc, proposal);
        }
        _params_to_cbor(enc, _params, format);
        _params_to_cbor(enc, _params_prev, format);
        // new in node 9+ - expected update next epoch?
        {
            const auto update = _prep_param_update();
            if (update) {
                enc.array(2);
                enc.uint(1);
                auto new_params = _params;
                new_params.apply(*update);
                _params_to_cbor(enc, new_params, format);
            } else {
                enc.array(1).uint(0);
            }
        }
    }

    void state::_stake_pointers_to_cbor(era_encoder &enc, const node_format format) const
    {
        stake_pointer_distribution normalized;
        if (format == node_format::v11_1_3) {
            // Several historical pointers can collapse to (0,0,0). Sum their
            // balances and restore map ordering without changing cached state.
            for (const auto &[ptr, coin]: _stake_pointers)
                normalized.add(node_snapshot::normalize_pointer(ptr), coin);
        }
        const auto &pointers = format == node_format::v11_1_3 ? normalized : _stake_pointers;
        enc.map_compact(pointers.size(), [&] {
            for (const auto &[ptr, coin]: pointers) {
                ptr.to_cbor(enc);
                enc.uint(coin);
            }
        });
    }

    void state::_donations_to_cbor(era_encoder &enc) const
    {
        enc.uint(0);
    }

    void state::_node_save_ledger_utxo(cbor_encoder &ser, const node_format format) const
    {
        _add_encode_task(ser, [](auto &enc) {
            enc.array(6);
            enc.map();
        });
        for (size_t pi = 0; format == node_format::legacy && pi < _utxo.num_parts; ++pi) {
            _add_encode_task(ser, [this, pi](auto &enc) {
                const auto &part = _utxo.partition(pi);
                for (const auto &[txo_id, txo_data]: part) {
                    enc.array(2)
                        .bytes(txo_id.hash)
                        .uint(txo_id.idx);
                    txo_data.to_cbor(enc);
                }
            });
        }
        _add_encode_task(ser, [this, format] (auto &enc) {
            enc.s_break();
            enc.uint(_deposited);
            enc.uint(_fees_utxo);
            _protocol_state_to_cbor(enc, format);
        });
        _add_encode_task(ser, [this, format] (auto &enc) {
            // Node 11 Conway InstantStake contains only the credential map.
            if (format == node_format::legacy || enc.era() < era_t::conway)
                enc.array(2);
            auto stakes { enc };
            size_t num_accounts = 0;
            for (const auto &[stake_id, acc]: _accounts) {
                if (acc.stake) {
                    ++num_accounts;
                    stake_id.to_cbor(stakes);
                    stakes.uint(acc.stake);
                }
            }
            enc.map_compact(num_accounts, [&] {
                enc << stakes;
            });
        });
        _add_encode_task(ser, [this, format] (auto &enc) {
            if (format == node_format::legacy || enc.era() < era_t::conway)
                _stake_pointers_to_cbor(enc, format);
            _donations_to_cbor(enc);
        });
    }

    void state::_node_save_ledger(cbor_encoder &ser, const node_format format) const
    {
        _add_encode_task(ser, [](auto &enc) {
            enc.array(2);
        });
        _node_save_ledger_delegation(ser, format);
        _node_save_ledger_utxo(ser, format);
    }

    void state::_node_save_state_before(cbor_encoder &ser, const node_format format) const
    {
        _add_encode_task(ser, [this] (auto &enc) {
            enc.array(4);
            // esAccountState
            enc.array(2).uint(_treasury).uint(_reserves);
        });
        // esLState
        _node_save_ledger(ser, format);
        // esSnapshots
        _node_save_snapshots(ser, format);
        // esNonmyopic
        _add_encode_task(ser, [this] (auto &enc) {
            enc.array(2);
            enc.map_compact(_nonmyopic.size(), [&] {
                for (const auto &[pool_id, lks]: _nonmyopic) {
                    enc.bytes(pool_id);
                    enc.array_compact(lks.size(), [&] {
                        for (const auto l: lks)
                            enc.float32(l);
                    });
                }
            });
            enc.uint(_nonmyopic_reward_pot);
        });
    }

    void state::to_cbor(cbor_encoder &ser, const node_format format) const
    {
        if (_params.protocol_ver.major >= 2 && !_rewards_ready
                && _epoch_slot > _cfg.shelley_randomness_stabilization_window)
            throw error("complete reward computation before encoding the ledger state");
        _add_encode_task(ser, [this](auto &enc) {
            enc.array(7);
            enc.uint(_epoch);
            for (const auto &blocks: { _blocks_before, _blocks_current }) {
                enc.map_compact(blocks.size(), [&] {
                    for (const auto &[pool_id, num_blocks]: blocks) {
                        enc.bytes(pool_id);
                        enc.uint(num_blocks);
                    }
                });
            }
        });

        // stateBefore
        _node_save_state_before(ser, format);
        // possibleUpdate
        if (_rewards_ready) {
            _add_encode_task(ser, [this](auto &enc) {
                enc.array(1).array(2).uint(1).array(5);
                enc.uint(_delta_treasury);
                enc.uint(_delta_reserves);
            });
            _add_encode_task(ser, [this](auto &enc) {
                enc.map_compact(_potential_rewards.size(), [&] {
                    for (const auto &[stake_id, rewards]: _potential_rewards) {
                        stake_id.to_cbor(enc);
                        rewards.to_cbor(enc);
                    }
                });
            });
            _add_encode_task(ser, [this](auto &enc) {
                enc.uint(_delta_fees);
                enc.array(2);
                enc.map_compact(_nonmyopic_next.size(), [&] {
                    for (const auto &[pool_id, lks]: _nonmyopic_next) {
                        enc.bytes(pool_id);
                        enc.array_compact(lks.size(), [&] {
                            for (const auto l: lks)
                                enc.float32(l);
                        });
                    }
                });
                enc.uint(_reward_pot);
            });
        } else {
            _add_encode_task(ser, [](auto &enc) {
                enc.array(0);
            });
        }
        _add_encode_task(ser, [this, format](auto &enc) {
            if (format == node_format::v11_1_3) {
                enc.array(2);
                map_to_cbor(enc, _operating_stake_dist);
                enc.uint(std::max(uint64_t { 1 }, _operating_stake_dist.total_stake));
            } else {
                _operating_stake_dist.to_cbor(enc);
            }
        });
        _add_encode_task(ser, [this, format](auto &enc) {
            // Unclaimed redeem outputs cannot be spent in Shelley. Node 11 keeps
            // them here until the Allegra transition removes them from the UTxO.
            if (format == node_format::v11_1_3 && enc.era() == era_t::shelley) {
                enc.map();
                for (const auto &[ref, output]: _utxo) {
                    const address addr { output.address_raw };
                    if (addr.is_byron() && addr.byron().type() == 2) {
                        enc.array(2).bytes(ref.hash).uint(ref.idx);
                        output.to_cbor(enc);
                    }
                }
                enc.s_break();
            } else {
                enc.s_null();
            }
        });
        _add_encode_task(ser, [this](auto &enc) {
           enc.uint(_blocks_past_voting_deadline);
        });
    }
}
