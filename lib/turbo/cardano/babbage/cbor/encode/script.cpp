/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <turbo/cardano/common/types.hpp>

namespace turbo::cardano {
    void script_info::to_cbor(era_encoder &enc) const
    {
        enc.tag(24);
        era_encoder nested { enc };
        nested.array(2).uint(static_cast<uint8_t>(type()));
        if (type() == script_type::native)
            nested.raw_cbor(script());
        else
            nested.bytes(script());
        enc.bytes(nested.cbor());
    }
}
