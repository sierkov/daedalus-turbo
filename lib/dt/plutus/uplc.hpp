/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_UPLC_HPP
#define DAEDALUS_TURBO_PLUTUS_UPLC_HPP

#include <dt/util.hpp>
#include <dt/plutus/types.hpp>

namespace daedalus_turbo::plutus::uplc {
    struct script {
        explicit script(uint8_vector &&bytes);
        script(script &&);
        ~script();
        version version() const;
        term_ptr program() const;
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif // !DAEDALUS_TURBO_PLUTUS_UPLC_HPP