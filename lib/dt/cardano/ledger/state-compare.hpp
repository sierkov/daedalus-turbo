/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_LEDGER_STATE_COMPARE_HPP
#define DAEDALUS_TURBO_CARDANO_LEDGER_STATE_COMPARE_HPP

#include <dt/util.hpp>

namespace daedalus_turbo::cardano::ledger {
    using daedalus_turbo::buffer;
    extern bool compare_node_state(buffer buf1, buffer buf2);
}

#endif // !DAEDALUS_TURBO_CARDANO_LEDGER_STATE_COMPARE_HPP