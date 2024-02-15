/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_JSON_HPP
#define DAEDALUS_TURBO_JSON_HPP

#include <boost/json.hpp>
#include <dt/file.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::json {
    using namespace boost::json;

    inline json::value parse(const buffer &buf, json::storage_ptr sp={})
    {
        return boost::json::parse(boost::json::string_view { reinterpret_cast<const char *>(buf.data()), buf.size() }, sp);
    }

    inline json::value load(const std::string &path, json::storage_ptr sp={})
    {
        auto buf = file::read(path);
        return parse(buf, sp);
    }
}

#endif // !DAEDALUS_TURBO_JSON_HPP