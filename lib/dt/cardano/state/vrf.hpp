/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_STATE_VRF_HPP
#define DAEDALUS_TURBO_CARDANO_STATE_VRF_HPP

#include <zpp_bits.h>
#include <dt/cardano/common.hpp>
#include <dt/container.hpp>
#include <dt/index/vrf.hpp>
#include <dt/vrf.hpp>

namespace daedalus_turbo::cardano::state {
    struct vrf {
        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(
                self._nonce_epoch,
                self._nonce_lab,
                self._nonce_next_epoch,
                self._lab_prev_hash,
                self._prev_epoch_lab_prev_hash,
                self._epoch_last,
                self._epoch_transition,
                self._slot_last,
                self._epoch_updates
            );
        }

        void load(const std::string &path)
        {
            auto zpp_data = file::read(path);
            zpp::bits::in in { zpp_data };
            in(*this).or_throw();
        }

        void save(const std::string &path) const
        {
            uint8_vector zpp_data {};
            zpp::bits::out out { zpp_data };
            out(*this).or_throw();
            file::write(path, zpp_data);
        }

        void process_updates(const vector<index::vrf::item> &updates)
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
                auto nonce_lab_new = vrf_nonce_accumulate(_nonce_lab, nonce_block);
                auto nonce_next_epoch_new = item.slot.epoch_slot() < 302400 ? nonce_lab_new : _nonce_next_epoch;
                _nonce_lab = nonce_lab_new;
                _nonce_next_epoch = nonce_next_epoch_new;
                _lab_prev_hash = item.prev_hash;
                _slot_last = item.slot;
                _epoch_last = item.slot.epoch();
                _epoch_updates++;
            }
        }

        void finish_epoch(const cardano::nonce &extra_entropy)
        {
            auto prev_epoch_nonce = _nonce_epoch;
            if (_epoch_transition++ >= 1) {
                if (extra_entropy) {
                    _nonce_epoch = vrf_nonce_accumulate(vrf_nonce_accumulate(_nonce_next_epoch, _prev_epoch_lab_prev_hash), extra_entropy.value());
                } else {
                    _nonce_epoch = vrf_nonce_accumulate(_nonce_next_epoch, _prev_epoch_lab_prev_hash);
                }
            } else {
                _nonce_epoch = _nonce_next_epoch;
            }
            logger::debug("epoch: {} epoch_nonce: {} next_epoch_nonce: {} extra_entropy: {}",
                _epoch_last, prev_epoch_nonce, _nonce_epoch, extra_entropy);
            _nonce_next_epoch = _nonce_lab;
            _prev_epoch_lab_prev_hash = _lab_prev_hash;
            _epoch_updates = 0;
        }

        size_t epoch_updates() const
        {
            return _epoch_updates; 
        }

        const cardano::vrf_nonce &epoch_nonce() const
        {
            return _nonce_epoch;
        }

        const cardano::vrf_nonce &uc_leader() const
        {
            return _nonce_uc_leader;
        }

        const cardano::vrf_nonce &uc_nonce() const
        {
            return _nonce_uc_nonce;
        }

        void clear()
        {
            _nonce_epoch = _nonce_genesis;
            _nonce_lab = _nonce_genesis;
            _nonce_next_epoch = _nonce_genesis;
            _lab_prev_hash = cardano::vrf_nonce {};
            _prev_epoch_lab_prev_hash = cardano::vrf_nonce {};
            _epoch_last = 0;
            _epoch_transition = 0;
            _slot_last = 0;
            _epoch_updates = 0;
        }
    private:
        const cardano::vrf_nonce _nonce_uc_nonce { cardano::vrf_nonce::from_hex("81e47a19e6b29b0a65b9591762ce5143ed30d0261e5d24a3201752506b20f15c") };
        const cardano::vrf_nonce _nonce_uc_leader { cardano::vrf_nonce::from_hex("12dd0a6a7d0e222a97926da03adb5a7768d31cc7c5c2bd6828e14a7d25fa3a60") };
        const cardano::vrf_nonce _nonce_genesis { cardano::vrf_nonce::from_hex("1a3be38bcbb7911969283716ad7aa550250226b76a61fc51cc9a9a35d9276d81") };
        cardano::vrf_nonce _nonce_epoch { _nonce_genesis };
        cardano::vrf_nonce _nonce_lab { _nonce_genesis };
        cardano::vrf_nonce _nonce_next_epoch { _nonce_genesis };
        cardano::vrf_nonce _lab_prev_hash {};
        cardano::vrf_nonce _prev_epoch_lab_prev_hash {};
        uint64_t _epoch_last = 0;
        uint64_t _epoch_transition = 0;
        uint64_t _slot_last = 0;
        size_t _epoch_updates = 0;
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_STATE_VRF_HPP