/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/file.hpp>

namespace daedalus_turbo::file {
    path_list files_with_ext(const std::string_view &dir, const std::string_view &ext)
    {
        path_list paths {};
        for (auto &entry: std::filesystem::recursive_directory_iterator(dir)) {
            if (entry.is_regular_file() && entry.path().extension().string() == ext)
                paths.emplace_back(entry.path());
        }
        std::sort(paths.begin(), paths.end());
        return paths;
    }

    path_list_str files_with_ext_str(const std::string_view &dir, const std::string_view &ext)
    {
        path_list_str paths {};
        for (auto &entry: std::filesystem::recursive_directory_iterator(dir)) {
            if (entry.is_regular_file() && entry.path().extension().string() == ext)
                paths.emplace_back(entry.path().string());
        }
        std::sort(paths.begin(), paths.end());
        return paths;
    }
}