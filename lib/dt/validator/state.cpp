/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/validator/state.hpp>
#include <dt/zpp.hpp>
#include <dt/util.hpp>

// Disable a windows macro
#ifdef small
#   undef small
#endif

namespace daedalus_turbo::validator {
    void state::load(const std::string &path)
    {
        zpp::load(*this, path);
    }

    void state::save(const std::string &path)
    {
        uint8_vector small {}, mark {}, set {}, go {}, active {}, rewards {};
        static const std::string task_group { "ledger-state:save-state-snapshot" };
        _sched.wait_for_count(task_group, 6, [&] {
            _sched.submit_void(task_group, 1000, [&] {
                timer t { fmt::format("serializing small for snapshot {}", path), logger::level::trace };
                typename ::zpp::bits::out out { small };
                out(_epoch, _end_offset, _delta_treasury, _delta_reserves, _reserves, _treasury, _fees_next_reward,
                    _epoch_accounts, _instant_rewards_reserves, _instant_rewards_treasury, _reward_pool_params,
                    _blocks_current, _blocks_before, _params, _params_prev, _ppups, _ppups_future).or_throw();
            });
            _sched.submit_void(task_group, 1000, [&] {
                timer t { fmt::format("serializing mark for snapshot {}", path), logger::level::trace };
                typename ::zpp::bits::out out { mark };
                out(_mark).or_throw();
            });
            _sched.submit_void(task_group, 1000, [&] {
                timer t { fmt::format("serializing set for snapshot {}", path), logger::level::trace };
                typename ::zpp::bits::out out { set };
                out(_set).or_throw();
            });
            _sched.submit_void(task_group, 1000, [&] {
                timer t { fmt::format("serializing go for snapshot {}", path), logger::level::trace };
                typename ::zpp::bits::out out { go };
                out(_go).or_throw();
            });
            _sched.submit_void(task_group, 1000, [&] {
                timer t { fmt::format("serializing active for snapshot {}", path), logger::level::trace };
                typename ::zpp::bits::out out { active };
                out(_active_stake_dist, _active_pool_dist, _active_pool_params, _active_delegs,
                    _active_inv_delegs, _pools_retiring).or_throw();
            });
            _sched.submit_void(task_group, 1000, [&] {
                timer t { fmt::format("serializing rewards for snapshot {}", path), logger::level::trace };
                typename ::zpp::bits::out out { rewards };
                out(_rewards, _reward_pulsing_snapshot, _reward_pulsing_start, _potential_rewards,
                    _ptr_to_stake, _stake_to_ptr).or_throw();
            });
        });
        timer t { fmt::format("writing serialized data to {}", path), logger::level::trace };
        file::write_stream ws { path };
        ws.write(small);
        ws.write(mark);
        ws.write(set);
        ws.write(go);
        ws.write(active);
        ws.write(rewards);
    }
}