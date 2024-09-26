/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_CONTEXT_HPP
#define DAEDALUS_TURBO_PLUTUS_CONTEXT_HPP

#include <dt/cardano/common.hpp>
#include <dt/plutus/types.hpp>

namespace daedalus_turbo::plutus {
    struct mint_info {
        buffer policy_id;
        const cbor::map &assets;
    };
    using mint_info_list = vector<mint_info>;

    struct resolved_input {
        const cardano::tx_out_ref &ref;
        const cardano::tx_out_data &data;
    };
    using resolved_input_list = vector<resolved_input>;

    struct purpose {
        using spend = resolved_input;
        using mint = mint_info;
        using reward = cardano::stake_ident;
        using value_type = std::variant<spend, mint, reward>;
        value_type val;
    };

    struct context {
        context(const cardano::tx &, const resolved_input_list &, const mint_info_list &, const set<cardano::key_hash> &);
        term_ptr v1(const purpose &) const;
    private:
        const cardano::tx &_tx;
        const resolved_input_list &_inputs;
        const mint_info_list &_mints;
        const set<cardano::key_hash> &_signatories;
    };
}

#endif //DAEDALUS_TURBO_PLUTUS_CONTEXT_HPP