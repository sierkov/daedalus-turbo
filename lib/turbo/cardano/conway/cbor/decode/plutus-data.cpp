/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <turbo/cardano/conway/transaction.hpp>
#include <turbo/plutus/types-core.hpp>

namespace turbo::cardano::conway {
    plutus_data_t plutus_data_t::from_cbor(cbor::zero2::value &v)
    {
        plutus::data::validate_cbor(v);
        return plutus_data_t { v.data_raw() };
    }
}
