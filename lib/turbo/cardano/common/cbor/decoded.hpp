#pragma once
/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <turbo/cardano/common/types/base.hpp>

namespace turbo::cardano {
    // A validated wire value. The input storage must outlive this object and its copies.
    // Semantic fields are read-only. To edit, copy value() and encode that T directly.
    // This adds no owned byte storage; T retains its existing ownership semantics.
    template<typename T>
    struct decoded_cbor_t {
        static decoded_cbor_t from_cbor(cbor::zero2::value &v) {
            return {v};
        }

        [[nodiscard]] const T &value() const {
            return _value;
        }

        [[nodiscard]] buffer original_cbor() const {
            return _original;
        }

        void to_cbor(era_encoder &enc) const {
            enc.raw_cbor(_original);
        }
    private:
        decoded_cbor_t(cbor::zero2::value &v):
            _value{T::from_cbor(v)},
            _original{v.data_raw()}
        {
        }

        T _value;
        buffer _original;
    };
}
