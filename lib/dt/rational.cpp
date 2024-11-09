/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cbor.hpp>
#include <dt/cbor/encoder.hpp>
#include <dt/json.hpp>
#include <dt/rational.hpp>

namespace daedalus_turbo {
    rational_u64::rational_u64(const uint64_t n, const uint64_t d):
        numerator { n }, denominator { d }
    {
    }

    rational_u64::rational_u64(double d)
    {
        double num = d;
        denominator = 1;
        while (std::fabs(num - static_cast<uint64_t>(num)) > 1e-6) {
            if (denominator >= 1'000'000'000)
                throw error("an unsupported value for a conversion to rational: {}", d);
            num *= 10;
            denominator *= 10;
        }
        numerator = static_cast<uint64_t>(num);
        const auto div = std::gcd(numerator, denominator);
        if (div != 0) {
            numerator /= div;
            denominator /= div;
        }
    }

    rational_u64::rational_u64(const cbor::array &r):
        numerator { r.at(0).uint() }, denominator { r.at(1).uint() }
    {
    }

    rational_u64::rational_u64(const cbor::value &v): rational_u64 { v.tag().second->array() }
    {
    }

    static rational_u64 from_json(const json::value &v)
    {
        if (v.is_object())
            return { json::value_to<uint64_t>(v.at("numerator")), json::value_to<uint64_t>(v.at("denominator")) };
        return { json::value_to<double>(v) };
    }

    rational_u64::rational_u64(const json::value &v): rational_u64 { from_json(v) }
    {
    }

    void rational_u64::to_cbor(cbor::encoder &enc) const
    {
        enc.rational(*this);
    }
}
