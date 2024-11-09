/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/alonzo.hpp>
#include <dt/cardano/shelley.hpp>
#include <dt/cardano/ledger/state.hpp>
#include <dt/cardano/ledger/babbage.hpp>
#include <dt/cardano/ledger/conway.hpp>
#include <dt/cardano/ledger/updates.hpp>
#include <dt/cbor/encoder.hpp>
#include <dt/progress.hpp>
#include <dt/timer.hpp>
#include <dt/util.hpp>
#include <dt/zpp.hpp>

// Disable a windows macro
#ifdef small
#   undef small
#endif

namespace daedalus_turbo::cardano::ledger {
    state::state(const cardano::config &cfg, scheduler &sched):
        _cfg { cfg }, _sched { sched },
        _state { std::make_unique<shelley::state>(_cfg, _sched) },
        _vrf_state { std::make_unique<shelley::vrf_state>(_cfg) }
    {
    }

    point state::deserialize_node(const buffer data)
    {
        cbor_parser_large p { data };
        cbor_value item {};
        p.read(item);
        const auto &eras = item.at(1).at(0).array();
        for (const auto &era: eras) {
            _eras.emplace_back(era.at(0).at(1).uint());
        }
        if (_eras.empty()) [[unlikely]]
            throw error("eras cannot be empty!");
        const point tip {
            eras.back().at(1).at(1).at(0).at(0).at(2).buf(),
            eras.back().at(1).at(1).at(0).at(0).at(0).uint(),
            eras.back().at(1).at(1).at(0).at(0).at(1).uint()
        };
        _transition_era(0, _eras.size());
        _state->from_cbor(eras.back().at(1).at(1));
        _vrf_state->from_cbor(item.at(1).at(1).at(1).array().back().at(1));
        return tip;
    }

    point state::load_node(const std::string &path)
    {
        const auto buf = file::read(path);
        return deserialize_node(buf);
    }

    void state::_serialize_node_state(parallel_serializer &ser, const point &tip) const
    {
        ser.add([&] {
            cbor::encoder enc {};
            enc.array(_eras.size());
            for (size_t era = 0; era < _eras.size(); ++era) {
                enc.array(2);
                slot { _eras[era], _cfg }.to_cbor(enc);
                if (era + 1 < _eras.size()) {
                    slot { _eras[era + 1], _cfg }.to_cbor(enc);
                } else {
                    enc.array(2)
                        .uint(2)
                        .array(3)
                            .array(1).array(3).uint(tip.slot).uint(tip.height).bytes(tip.hash);
                }
            }
            return std::move(enc.cbor());
        });
        _state->to_cbor(ser);
    }

    void state::_serialize_node_vrf_state(parallel_serializer &ser, const point &tip) const
    {
        ser.add([this, tip] {
            cbor::encoder enc {};
            enc.array(2);
            if (!_eras.empty()) {
                enc.array(1)
                    .array(2)
                        .uint(_eras.size() - 1)
                        .array(3)
                            .uint(tip.slot)
                            .bytes(tip.hash)
                            .uint(tip.height);
            } else {
                enc.array(0);
            }
            enc.array(_eras.size());
            for (size_t era = 0; era < _eras.size(); ++era) {
                enc.array(2);
                slot { _eras[era], _cfg }.to_cbor(enc);
                if (era + 1 < _eras.size()) {
                    slot { _eras[era + 1], _cfg }.to_cbor(enc);
                }
            }
            return std::move(enc.cbor());
        });
        _vrf_state->to_cbor(ser);
    }

    parallel_serializer state::serialize_node(const point &tip, const int prio) const
    {
        timer t { "serialize the state into the Cardano Node format", logger::level::info };
        parallel_serializer ser {};
        ser.add([] {
            cbor::encoder enc {};
            enc.array(2); // versioned encoding tuple
            enc.uint(1); // version number
            enc.array(2);
            return std::move(enc.cbor());
        });
        _serialize_node_state(ser, tip);
        _serialize_node_vrf_state(ser, tip);
        ser.run(_sched, "ledger-export", prio, true);
        return ser;
    }

    void state::save_node(const std::string &path, const point &tip, const int prio) const
    {
        const auto ser = serialize_node(tip, prio);
        timer t { "write the serialized node state to a file", logger::level::info };
        ser.save(path, false);
        progress::get().update("ledger-export", 1, 1);
    }

    void state::load_zpp(const std::string &path)
    {
        parallel_decoder dec { path };
        zpp::deserialize(_subchains, dec.at(0));
        dec.add([&](const auto) {
            // do nothing as the field has been already decoded above
        });
        zpp::deserialize(_eras, dec.at(1));
        dec.add([&](const auto) {
            // do nothing as the field has been already decoded above
        });
        _transition_era(0, _eras.size());
        _state->from_zpp(dec);
        _vrf_state->from_zpp(dec);
        dec.run(_sched, "parallel_decoder::run", 1000);
        // Reserve snapshots can be saved to disk before the validation is fully finished.
        // However, they will be renamed into their proper names only when they become valid.
        // Thus, if we load a snapshot we need to merge the subchains.
        for (auto &[offset, sc]: _subchains) {
            if (!sc)
                sc.valid_blocks = sc.num_blocks;
        }
        _subchains.merge_valid();
        if (end_offset() != valid_end_offset())
            throw error("validator state from {} is in inconsistent state valid_end_offset: {} vs end_offset: {}",
                path, valid_end_offset(), end_offset());
    }

    void state::save_zpp(const std::string &path)
    {
        parallel_serializer ser {};
        ser.add([&] {
            return zpp::serialize(_subchains);
        });
        ser.add([&] {
            return zpp::serialize(_eras);
        });
        _state->to_zpp(ser);
        _vrf_state->to_zpp(ser);
        ser.run(_sched, "ledger-state:save-state-snapshot");
        ser.save(path, true);
    }

    void state::clear()
    {
        _subchains.clear();
        _eras.clear();
        _state = std::make_unique<shelley::state>(_cfg, _sched);
        _vrf_state = std::make_unique<shelley::vrf_state>(_cfg);
    }

    bool state::operator==(const state &o) const
    {
        return _subchains == o._subchains
            && _eras == o._eras
            && *_state == *o._state
            && *_vrf_state == *o._vrf_state;
    }

    void state::track_era(const uint64_t era, const uint64_t slot)
    {
        if (era > 0) {
            if (!_eras.empty() && slot < _eras.back())
                throw error("era blocks have reported out of order slot {} came after {}", slot, _eras.back());
            if (era > _eras.size()) {
                const auto era_start_slot = !_eras.empty() && era > 2 ? slot - (slot - _eras.back()) % _cfg.shelley_epoch_length : slot;
                while (era > _eras.size()) {
                    _eras.emplace_back(era_start_slot);
                }
            } else if (era < _eras.size()) {
                throw error("a block of era {} came in era {}", era, _eras.size());
            }
        }
    }

    void state::_transition_era(const uint64_t from_era, const uint64_t to_era)
    {
        logger::debug("transition_era from: {} to: {}", from_era, to_era);
        // Protocol versions may be upgraded in large increments.
        // The loop insures that all the necessary internal transitions still happen
        for (size_t new_era = from_era + 1; new_era <= to_era; ++new_era) {
            switch (new_era) {
                case 1:
                case 2:
                case 3:
                case 4:
                    break;
                case 5:
                    _state = std::make_unique<alonzo::state>(std::move(*_state));
                    _vrf_state = std::make_unique<alonzo::vrf_state>(std::move(*_vrf_state));
                    break;
                case 6:
                    _state = std::make_unique<babbage::state>(std::move(dynamic_cast<alonzo::state &>(*_state)));
                    _vrf_state = std::make_unique<babbage::vrf_state>(std::move(dynamic_cast<alonzo::vrf_state &>(*_vrf_state)));
                    break;
                case 7:
                    _state = std::make_unique<conway::state>(std::move(dynamic_cast<babbage::state &>(*_state)));
                    _vrf_state = std::make_unique<conway::vrf_state>(std::move(dynamic_cast<babbage::vrf_state &>(*_vrf_state)));
                    break;
                default: throw error("unsupported era: {}", new_era);
            }
        }
    }

    void state::start_epoch(const std::optional<uint64_t> new_epoch)
    {
        const auto prev_pv = _state->_params.protocol_ver;
        _state->start_epoch(new_epoch);
        if (!_vrf_state->kes_counters().empty())
            _vrf_state->finish_epoch(_state->_params.extra_entropy);
        const auto new_pv = _state->_params.protocol_ver;
        if (new_pv != prev_pv) {
            if (new_pv < prev_pv) [[unlikely]]
                throw error("protocol downgrades are not supported: went from {} to {}", prev_pv, new_pv);
            _transition_era(prev_pv.era(), new_pv.era());
            const auto tip_slot = slot::from_epoch(_state->_epoch, _state->_epoch_slot, _cfg);
            track_era(new_pv.era(), tip_slot);
        }
    }

    void state::process_updates(updates_t &&updates)
    {
        for (const auto &u: updates.blocks)
            track_era(u.era, u.slot);
        _state->process_updates(std::move(updates));
    }
}