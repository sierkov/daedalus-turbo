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
        return _parsed.at(name);
    }

    std::string configs_dir::default_path()
    {
        static const char *default_path = "./etc";
        const char *user_defined_path = std::getenv("DT_ETC");
        return user_defined_path != nullptr ? user_defined_path : default_path;
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
        return _configs.at(name);
    }
}