/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <turbo/cardano/conway/transaction.hpp>

namespace turbo::cardano::conway {
    void transaction_t::to_cbor(era_encoder &enc) const
    {
        enc.array(4);
        body.to_cbor(enc);
        witnesses.to_cbor(enc);
        enc.boolean(valid);
        if (auxiliary_data)
            auxiliary_data->to_cbor(enc);
        else
            enc.s_null();
    }

    void tx::body_to_cbor(era_encoder &enc) const
    {
        enc.raw_cbor(raw());
    }

    void tx::witnesses_to_cbor(era_encoder &enc) const
    {
        enc.raw_cbor(witness_raw());
    }
}
