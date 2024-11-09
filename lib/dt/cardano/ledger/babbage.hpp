/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_LEDGER_BABBAGE_HPP
#define DAEDALUS_TURBO_CARDANO_LEDGER_BABBAGE_HPP

#include <dt/cardano/ledger/alonzo.hpp>

namespace daedalus_turbo::cardano::ledger::babbage {
    struct vrf_state: alonzo::vrf_state {
        vrf_state(alonzo::vrf_state &&);
        void from_cbor(const cbor::value &v) override;
        void to_cbor(parallel_serializer &) const override;
    };

    struct state: alonzo::state {
        state(alonzo::state &&);
    protected:
        void _apply_babbage_params(protocol_params &p) const;
        void _apply_param_update(const param_update &update) override;
        void _parse_protocol_params(protocol_params &params, const cbor_value &values) const override;
        void _params_to_cbor(cbor::encoder &enc, const protocol_params &params) const override;
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::cardano::ledger::babbage::vrf_state>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", static_cast<const daedalus_turbo::cardano::ledger::alonzo::vrf_state &>(v));
        }
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_LEDGER_BABBAGE_HPP