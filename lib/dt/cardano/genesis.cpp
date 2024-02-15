/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <filesystem>
#include <dt/cardano/genesis.hpp>

namespace daedalus_turbo::cardano::genesis {
    config::config(const std::string &path)
        : _raw { file::read(path) }, _parsed { json::parse(_raw).as_object() }, _hash { blake2b<blake2b_256_hash>(_raw) }
    {
    }

    const json::value &config::at(const std::string_view &name)
    {
        return _parsed.at(name);
    }
    
    const blake2b_256_hash &config::hash() const
    {
        return _hash;
    }

    configs::configs(const std::string &dir)
    {
        for (const auto &e: std::filesystem::directory_iterator(dir)) {
            if (!e.is_regular_file() || e.path().extension() != ".json")
                continue;
            const auto &stem = e.path().stem().string();
            if (stem.substr(0, 8) != "mainnet-" || stem.substr(stem.size() - 8) != "-genesis")
                continue;
            _configs.emplace(stem.substr(8, stem.size() - 16), e.path().string());
        }
    }
    
    const config &configs::at(const std::string &name)
    {
        return _configs.at(name);
    }
}