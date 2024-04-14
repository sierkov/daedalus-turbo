/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CONFIG_HPP
#define DAEDALUS_TURBO_CONFIG_HPP

#include <map>
#include <dt/json.hpp>

namespace daedalus_turbo {
    struct config {
        config(const std::string &path);
        const json::value &at(const std::string_view &name) const;
    private:
        uint8_vector _raw;
        json::object _parsed;
    };

    struct configs {
        static std::string default_path();
        static const configs &get();

        configs(const std::string &dir);
        const config &at(const std::string &) const;
    private:
        std::map<std::string, config> _configs {};
    };
}

#endif // !DAEDALUS_TURBO_CONFIG_HPP