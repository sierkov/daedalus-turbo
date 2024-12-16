/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SERIALIZABLE_HPP
#define DAEDALUS_TURBO_SERIALIZABLE_HPP

#include <dt/cbor/encoder.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/error.hpp>
#include <dt/format.hpp>

namespace daedalus_turbo {
    /*
     * Tries to provide sensible defaults for data structures that need to be serialized in multiple formats:
     * 1) CBOR - Cardano on-chain encoding
     * 2) JSON - Cardano configs and HTTP API
     * 3) ZPP - Fast serialization of C++ objects
     * 4) Text - fmt::format support
     */

    struct serializable {
        template<typename T>
        struct item {
            std::string_view name;
            T &val;
        };

        static constexpr auto serialize_any(auto &archive, auto &self)
        {
            throw error("static serialize method must be implemented by subclasses of serializable!");
        }

        static auto serialize(auto &archive, auto &self)
        {
            throw error("static serialize method must be implemented by subclasses of serializable!");
        }



        void to_cbor(cbor::encoder &enc) const;
        json::value as_json() const;
        std::string as_string() const;
    };
}

namespace fmt {
    template<size_t SZ>
    struct formatter<daedalus_turbo::array<uint8_t, SZ>>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out())
        {
            return fmt::format_to(ctx.out(), "{}", std::span(v));
        }
    };

    template<size_t SZ>
    struct formatter<daedalus_turbo::secure_array<uint8_t, SZ>>: formatter<daedalus_turbo::array<uint8_t, SZ>> {
    };
}

#endif //DAEDALUS_TURBO_SERIALIZABLE_HPP