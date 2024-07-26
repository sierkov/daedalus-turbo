/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <filesystem>
#include <dt/config.hpp>

namespace daedalus_turbo {
    config_file::config_file(const std::string &path)
            : _raw { file::read(path) }, _parsed { json::parse(_raw).as_object() }
    {
    }

    const json::value &config_file::_at_impl(const std::string_view &name) const
    {
        const auto it = _parsed.find(name);
        if (it == _parsed.end())
            throw error("configuration file does not have the element {}!", name);
        return it->value();
    }

    static std::optional<std::string> &_configs_default_path()
    {
        static std::optional<std::string> p {};
        return p;
    }

    void configs_dir::set_default_path(const std::optional<std::string> &p)
    {
        _configs_default_path() = p;
    }

    std::string configs_dir::default_path()
    {
        std::optional<std::string> path = _configs_default_path();
        if (const char *env_path = std::getenv("DT_ETC"); !path && env_path)
            path.emplace(env_path);
        if (!path)
            path.emplace("./etc/mainnet");
        logger::debug("Configuration directory: {}", *path);
        return *path;
    }

    const configs &configs_dir::get()
    {
        static configs_dir cfg { default_path() };
        return cfg;
    }

    configs_dir::configs_dir(const std::string &dir)
    {
        for (const auto &e: std::filesystem::directory_iterator(dir)) {
            if (!e.is_regular_file() || e.path().extension() != ".json")
                continue;
            _configs.emplace(e.path().stem().string(), e.path().string());
        }
    }

    const config &configs_dir::_at_impl(const std::string &name) const
    {
        const auto it = _configs.find(name);
        if (it == _configs.end())
            throw error("there is no config named {}!", name);
        return it->second;
    }
}
