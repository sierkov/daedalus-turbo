/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_CONWAY_HPP
#define DAEDALUS_TURBO_CARDANO_CONWAY_HPP

#include <dt/cardano/babbage.hpp>

namespace daedalus_turbo::cardano::conway {
    struct block: babbage::block {
        using babbage::block::block;
        void foreach_tx(const std::function<void(const tx &)> &observer) const override;
        void foreach_invalid_tx(const std::function<void(const tx &)> &observer) const override;
    };

    struct tx: babbage::tx {
        using babbage::tx::tx;
        void foreach_genesis_deleg(const std::function<void(const genesis_deleg &, size_t)> &) const override;
        void foreach_instant_reward(const std::function<void(const instant_reward &)> &) const override;
        void foreach_stake_reg(const stake_reg_observer &observer) const override;
        void foreach_stake_unreg(const stake_unreg_observer &observer) const override;
        void foreach_set(const cbor_value &set_raw, const std::function<void(const cbor_value &, size_t)> &observer) const override;
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_CONWAY_HPP