/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_LEDGER_UPDATES_HPP
#define DAEDALUS_TURBO_CARDANO_LEDGER_UPDATES_HPP

#include <dt/cardano/common/common.hpp>
#include <dt/cardano/ledger/types.hpp>
#include <dt/container.hpp>
#include <dt/index/block-fees.hpp>
#include <dt/index/timed-update.hpp>

namespace daedalus_turbo::cardano::ledger {
    struct block_update_list: vector<index::block_fees::item> {
        using vector::vector;
    };

    struct utxo_update_list: vector<txo_map> {
        using vector::vector;
    };

    struct timed_update_t: index::timed_update::item {
    };

    struct timed_update_list: vector<timed_update_t> {
        using vector::vector;
    };

    struct updates_t {
        block_update_list blocks {};
        utxo_update_list utxos {};
        timed_update_list timed {};
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_LEDGER_UPDATES_HPP