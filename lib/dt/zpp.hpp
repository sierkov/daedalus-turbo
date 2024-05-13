/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ZPP_HPP
#define DAEDALUS_TURBO_ZPP_HPP

#include <zpp_bits.h>
#include <dt/file.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::zpp {
    template<typename T>
    void load(T &v, const std::string &path)
    {
        const auto zpp_data = file::read_raw(path);
        ::zpp::bits::in in { zpp_data };
        in(v).or_throw();
    }

    template<typename T>
    void save(const std::string &path, const T &v)
    {
        uint8_vector zpp_data {};
        ::zpp::bits::out out { zpp_data };
        out(v).or_throw();
        file::write(path, zpp_data);
    }
}

#endif // !DAEDALUS_TURBO_ZPP_HPP