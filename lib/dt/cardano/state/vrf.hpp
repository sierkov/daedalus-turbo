/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_STATE_VRF_HPP
#define DAEDALUS_TURBO_CARDANO_STATE_VRF_HPP

#include <dt/cardano/common.hpp>
#include <dt/container.hpp>
#include <dt/index/vrf.hpp>
#include <dt/vrf.hpp>

namespace daedalus_turbo::cardano::state {
    struct vrf {
        using pool_update_map = map<pool_hash, uint64_t>;

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self._nonce_epoch, self._nonce_lab, self._nonce_next_epoch, self._lab_prev_hash,
                self._prev_epoch_lab_prev_hash, self._slot_last, self._kes_counters);
        }

        explicit vrf(const config &cfg=config::get())
            : _nonce_genesis { cfg.shelley_genesis_hash }, _max_epoch_slot { cfg.shelley_epoch_length - cfg.shelley_stability_window }
        {
            logger::debug("VRF state created nonce_genesis: {} max_epoch_slot: {}", _nonce_genesis, _max_epoch_slot);
        }

        bool operator==(const vrf &o) const
        {
            return _nonce_epoch == o._nonce_epoch && _nonce_lab == o._nonce_lab && _nonce_next_epoch == o._nonce_next_epoch
                && _lab_prev_hash == o._lab_prev_hash && _prev_epoch_lab_prev_hash == o._prev_epoch_lab_prev_hash
                && _slot_last == o._slot_last && _kes_counters == o._kes_counters;
        }

        void set(const vrf_nonce &nonce_epoch, const vrf_nonce &nonce_lab, const vrf_nonce &nonce_next_epoch,
            const vrf_nonce &lab_prev_hash, const std::optional<vrf_nonce> &prev_lab_prev_hash,
            const uint64_t last_slot, pool_update_map &&kes_counters)
        {
            _nonce_epoch = nonce_epoch;
            _nonce_lab = nonce_lab;
            _nonce_next_epoch = nonce_next_epoch;
            _lab_prev_hash = lab_prev_hash;
            _prev_epoch_lab_prev_hash = prev_lab_prev_hash;
            _slot_last = last_slot;
            _kes_counters = std::move(kes_counters);
        }

        void load(const std::string &path);
        void save(const std::string &path) const;

        void process_updates(const vector<index::vrf::item> &updates, const cardano::config &cfg)
        {
            blake2b_256_hash nonce_block {};
            for (const auto &item: updates) {
                if (item.slot < _slot_last)
                    throw error("got block with a slot number {} when last seed slot is : {}", item.slot, _slot_last);
                if (item.era < 6) {
                    blake2b(nonce_block, item.nonce_result);
                } else {
                    nonce_block = vrf_nonce_value(item.leader_result);
                }
                const auto item_slot = cardano::slot { item.slot, cfg };
                _nonce_lab = vrf_nonce_accumulate(_nonce_lab, nonce_block);
                if (item_slot.epoch_slot() < _max_epoch_slot)
                    _nonce_next_epoch = _nonce_lab;
                //logger::debug("VRF update slot: {} new nonce_lab: {} nonce_next_epoch: {}", item_slot, _nonce_lab, _nonce_next_epoch);
                _lab_prev_hash = item.prev_hash;
                _slot_last = item.slot;
                auto [kes_it, kes_created] = _kes_counters.try_emplace(item.pool_id, item.kes_counter);
                if (!kes_created) {
                    if (item.kes_counter > kes_it->second)
                        kes_it->second = item.kes_counter;
                    else if (item.kes_counter < kes_it->second)
                        throw error("slot: {} out of order KES counter {} < {} for pool: {}", item_slot, item.kes_counter, kes_it->second, item.pool_id);
                }
            }
        }

        void finish_epoch(const nonce &extra_entropy)
        {
            const auto prev_epoch_nonce = _nonce_epoch;
            if (_prev_epoch_lab_prev_hash) {
                if (extra_entropy) {
                    _nonce_epoch = vrf_nonce_accumulate(vrf_nonce_accumulate(_nonce_next_epoch, *_prev_epoch_lab_prev_hash), extra_entropy.value());
                } else {
                    _nonce_epoch = vrf_nonce_accumulate(_nonce_next_epoch, *_prev_epoch_lab_prev_hash);
                }
            } else {
                _nonce_epoch = _nonce_next_epoch;
            }
            logger::debug("VRF finish_epoch last_slot: {} prev nonce_epoch: {} new nonce_epoch: {} prev_lab_prev_hash: {} extra_entropy: {}",
                _slot_last, prev_epoch_nonce, _nonce_epoch, _prev_epoch_lab_prev_hash, extra_entropy);
            _nonce_next_epoch = _nonce_lab;
            _prev_epoch_lab_prev_hash = _lab_prev_hash;
        }

        const pool_update_map &kes_counters() const
        {
            return _kes_counters;
        }

        const vrf_nonce &nonce_epoch() const
        {
            return _nonce_epoch;
        }

        const vrf_nonce &nonce_lab() const
        {
            return _nonce_lab;
        }

        const vrf_nonce &nonce_next_epoch() const
        {
            return _nonce_next_epoch;
        }

        const vrf_nonce &uc_leader() const
        {
            return _nonce_uc_leader;
        }

        const vrf_nonce &uc_nonce() const
        {
            return _nonce_uc_nonce;
        }

        const vrf_nonce &lab_prev_hash() const
        {
            return _lab_prev_hash;
        }

        const std::optional<vrf_nonce> &prev_epoch_lab_prev_hash() const
        {
            return _prev_epoch_lab_prev_hash;
        }

        uint64_t last_slot() const
        {
            return _slot_last;
        }

        void clear()
        {
            _nonce_epoch = _nonce_genesis;
            _nonce_lab = _nonce_genesis;
            _nonce_next_epoch = _nonce_genesis;
            _lab_prev_hash = vrf_nonce {};
            _prev_epoch_lab_prev_hash.reset();
            _slot_last = 0;
            _kes_counters.clear();
        }
    private:
        friend fmt::formatter<daedalus_turbo::cardano::state::vrf>;

        const vrf_nonce _nonce_uc_nonce = vrf_nonce::from_hex("81e47a19e6b29b0a65b9591762ce5143ed30d0261e5d24a3201752506b20f15c");
        const vrf_nonce _nonce_uc_leader = vrf_nonce::from_hex("12dd0a6a7d0e222a97926da03adb5a7768d31cc7c5c2bd6828e14a7d25fa3a60");
        const vrf_nonce _nonce_genesis;
        const uint64_t _max_epoch_slot;
        vrf_nonce _nonce_epoch { _nonce_genesis };
        vrf_nonce _nonce_lab { _nonce_genesis };
        vrf_nonce _nonce_next_epoch { _nonce_genesis };
        vrf_nonce _lab_prev_hash {};
        std::optional<vrf_nonce> _prev_epoch_lab_prev_hash {};
        uint64_t _slot_last = 0;
        pool_update_map _kes_counters {};
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::cardano::state::vrf>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "nonce_epoch: {} nonce_lab: {} nonce_next_epoch: {} lab_prev_hash: {} prev_epoch_lab_prev_hash: {} slot_last: {}",
                v._nonce_epoch, v._nonce_lab, v._nonce_next_epoch, v._lab_prev_hash, v._prev_epoch_lab_prev_hash, v._slot_last);
        }
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_STATE_VRF_HPP