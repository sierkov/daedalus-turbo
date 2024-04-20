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
        [[nodiscard]] const json::value &at(const std::string_view &name) const
        {
            return _at_impl(name);
        }
    private:
        virtual const json::value &_at_impl(const std::string_view &name) const =0;
    };

    // Used as a config mock
    struct config_json: config {
        explicit config_json(json::object &&json): _json { std::move(json) }
        {
        }
    private:
        const json::object _json;

        const json::value &_at_impl(const std::string_view &name) const override
        {
            return _json.at(name);
        }
    };

    struct config_file: config {
        explicit config_file(const std::string &path);
    private:
        uint8_vector _raw;
        json::object _parsed;

        const json::value &_at_impl(const std::string_view &name) const override;
    };

    struct configs {
        [[nodiscard]] const config &at(const std::string &name) const
        {
            return _at_impl(name);
        }
    private:
        virtual const config &_at_impl(const std::string &) const =0;
    };

    struct configs_mock: configs {
        using map_type = std::map<std::string, config_json>;

        explicit configs_mock() =default;

        explicit configs_mock(map_type &&map): _map { std::move(map) }
        {
        }
    private:
        const map_type _map;

        const config &_at_impl(const std::string &name) const override
        {
            return _map.at(name);
        }
    };

    struct configs_dir: configs {
        static std::string default_path();
        static const configs &get();

        explicit configs_dir(const std::string &dir);
    private:
        std::map<std::string, config_file> _configs {};

        const config &_at_impl(const std::string &) const override;
    };
}

#endif // !DAEDALUS_TURBO_CONFIG_HPP