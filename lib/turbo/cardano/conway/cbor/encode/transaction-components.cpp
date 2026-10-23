/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <turbo/cardano/conway/transaction.hpp>

namespace turbo::cardano::conway {
    void value_t::to_cbor(era_encoder &enc) const
    {
        if (value.assets.empty()) {
            enc.uint(value.coin);
        } else {
            enc.array(2).uint(value.coin);
            value.assets.to_cbor(enc);
        }
    }

    void mint_t::to_cbor(era_encoder &enc) const
    {
        enc.map_compact(size(), [&] {
            for (const auto &[policy, assets]: *this) {
                enc.bytes(policy);
                enc.map_compact(assets.size(), [&] {
                    for (const auto &[name, amount]: assets) {
                        name.to_cbor(enc);
                        if (amount >= 0)
                            enc.uint(numeric_cast<uint64_t>(amount));
                        else
                            enc.nint(numeric_cast<uint64_t>(-(amount + 1)));
                    }
                });
            }
        });
    }

    void script_t::to_cbor(era_encoder &enc) const
    {
        enc.array(2).uint(static_cast<uint8_t>(value.type()));
        if (value.type() == script_type::native) {
            enc.raw_cbor(value.script());
        } else {
            enc.bytes(value.script());
        }
    }

    void cost_models_t::to_cbor(era_encoder &enc) const
    {
        value.to_cbor(enc);
    }

    void transaction_output_t::to_cbor(era_encoder &enc) const
    {
        value.to_cbor(enc);
    }

    void transaction_outputs_t::to_cbor(era_encoder &enc) const
    {
        enc.array_compact(value.size(), [&] {
            for (const auto &output: value)
                output.to_cbor(enc);
        });
    }
}
