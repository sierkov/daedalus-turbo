/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_FLAT_HPP
#define DAEDALUS_TURBO_PLUTUS_FLAT_HPP

#include <dt/util.hpp>
#include <dt/plutus/types.hpp>

namespace daedalus_turbo::plutus::flat {
    struct script {
        explicit script(allocator &alloc, const buffer bytes, bool cbor=true);
        explicit script(allocator &alloc, uint8_vector &&bytes, bool cbor=true);
        ~script();
	    plutus::version version() const;
        term program() const;
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::plutus::flat::script>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            return fmt::format_to(ctx.out(), "(program {} {})", v.version(), v.program());
        }
    };
}

#endif // !DAEDALUS_TURBO_PLUTUS_FLAT_HPP
