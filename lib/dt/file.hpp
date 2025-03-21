/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_FILE_HPP
#define DAEDALUS_TURBO_FILE_HPP

#include <dt/common/file.hpp>
#include <dt/container.hpp>
#include <dt/zstd.hpp>

namespace daedalus_turbo::file {
    inline void read_auto(const std::string &path, uint8_vector &buffer) {
        static const std::string_view match { ".zstd" };
        if (path.ends_with(match)) {
            zstd::read(path, buffer);
        } else {
            read(path, buffer);
        }
    }

    inline uint8_vector read_auto(const std::string &path)
    {
        uint8_vector buf {};
        read_auto(path, buf);
        return buf;
    }

    using path_list = vector<std::filesystem::path>;
    extern path_list files_with_ext(const std::string_view &dir, const std::string_view &ext);
    using path_list_str = vector<std::string>;
    extern path_list_str files_with_ext_str(const std::string_view &dir, const std::string_view &ext);
}

#endif // !DAEDALUS_TURBO_FILE_HPP