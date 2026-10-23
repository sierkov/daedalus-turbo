/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <turbo/cardano/common/types.hpp>

namespace turbo::cardano {
    void datum_option_t::to_cbor(era_encoder &enc) const
    {
        enc.array(2);
        if (const auto *hash = std::get_if<datum_hash>(&val))
            enc.uint(0).bytes(*hash);
        else
            enc.uint(1).tag(24).bytes(std::get<uint8_vector>(val));
    }
}
