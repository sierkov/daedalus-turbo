/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <turbo/cardano/ledger/state.hpp>
#include <turbo/common/timer.hpp>

namespace turbo::cardano::ledger {
    void state::_serialize_node_state(cbor_encoder &ser, const point &tip, const node_format format) const
    {
        ser.add([this, tip, format](auto enc) {
            enc.array(_eras.size());
            for (size_t era = 0; era < _eras.size(); ++era) {
                enc.array(2);
                slot { _eras[era], _cfg }.to_cbor(enc);
                if (era + 1 < _eras.size()) {
                    slot { _eras[era + 1], _cfg }.to_cbor(enc);
                } else {
                    enc.array(2)
                        .uint(2)
                        .array(format == node_format::v11_1_3 ? 4 : 3)
                            .array(1).array(3).uint(tip.slot).uint(tip.height).bytes(tip.hash);
                }
            }
            return std::move(enc.cbor());
        });
        _state->to_cbor(ser, format);
        if (format == node_format::v11_1_3) {
            // Latest Peras certificate round: absent in Shelley through Conway.
            ser.add([](auto enc) { enc.array(0); return std::move(enc.cbor()); });
        }
    }

    void state::_serialize_node_vrf_state(cbor_encoder &ser, const point &tip, const node_format format) const
    {
        ser.add([this, tip](auto enc) {
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
        _vrf_state->to_cbor(ser, format);
    }

    cbor_encoder state::to_cbor(const point &tip, const int prio, const node_format format)
    {
        if (format == node_format::v11_1_3 && (_eras.size() < 2 || _eras.size() > 7))
            throw error("Node 11.1.3 export supports Shelley through Conway only");
        _state->complete_pulsers();
        timer t { "serialize the state into the Cardano Node format", logger::level::info };
        cbor_encoder ser { [&] { return era_encoder { era_from_number(_eras.size()) }; } };
        ser.add([](auto enc) {
            enc.array(2); // versioned encoding tuple
            enc.uint(1); // version number
            enc.array(2);
            return std::move(enc.cbor());
        });
        _serialize_node_state(ser, tip, format);
        _serialize_node_vrf_state(ser, tip, format);
        ser.run(_sched, "ledger-export", prio, true);
        return ser;
    }
}
