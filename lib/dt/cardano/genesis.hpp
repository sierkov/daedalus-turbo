/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_GENESIS_HPP
#define DAEDALUS_TURBO_CARDANO_GENESIS_HPP

#include <map>
#include <dt/blake2b.hpp>
#include <dt/json.hpp>

namespace daedalus_turbo::cardano::genesis {
    struct config {
        config(const std::string &path);
        const json::value &at(const std::string_view &name) const;
        const blake2b_256_hash &hash() const;
    private:
        uint8_vector _raw;
        json::object _parsed;
        blake2b_256_hash _hash;
    };

    struct configs {
        configs(const std::string &dir);
        const config &at(const std::string &);
    private:
        std::map<std::string, config> _configs {};
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_GENESIS_HPP