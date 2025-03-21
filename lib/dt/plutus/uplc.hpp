/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_UPLC_HPP
#define DAEDALUS_TURBO_PLUTUS_UPLC_HPP

#include <dt/util.hpp>
#include <dt/plutus/types.hpp>

namespace daedalus_turbo::plutus::uplc {
    struct script {
        explicit script(allocator &alloc, write_vector &&bytes);
        script(script &&);
        ~script();
	    plutus::version version() const;
        term program() const;
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif // !DAEDALUS_TURBO_PLUTUS_UPLC_HPP
