/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_TXWIT_VALIDATOR_HPP
#define DAEDALUS_TURBO_TXWIT_VALIDATOR_HPP

#include <dt/chunk-registry.hpp>

namespace daedalus_turbo::txwit {
    enum class witness_type { all, vkey, script, none };
    using error_handler_func = std::function<void(const std::string &)>;

    extern witness_type witness_type_from_str(std::string_view);

    extern cardano::optional_point validate(const chunk_registry &cr, const cardano::optional_point &from={},
          const cardano::optional_point &to={}, witness_type type=witness_type::all,
          const error_handler_func &error_handler=[](const std::string &what) {
              throw error("txwit: error: {}", what);
          });
}

#endif //DAEDALUS_TURBO_TXWIT_VALIDATOR_HPP