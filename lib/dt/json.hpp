/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
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

    inline void save_pretty(std::ostream& os, json::value const &jv, std::string *indent = nullptr)
    {
        static constexpr size_t indent_step = 2;
        std::string indent_ {};
        if(!indent)
            indent = &indent_;
        switch (jv.kind()) {
            case json::kind::object: {
                os << "{\n";
                indent->append(indent_step, ' ');
                auto const &obj = jv.get_object();
                for (auto it = obj.begin(), last = std::prev(obj.end()); it != obj.end(); ++it) {
                    os << *indent << json::serialize(it->key()) << ": ";
                    save_pretty(os, it->value(), indent);
                    if (it != last)
                        os << ',';
                    os << '\n';
                }
                indent->resize(indent->size() - indent_step);
                os << *indent << "}";
                break;
            }
            case json::kind::array: {
                os << "[\n";
                indent->append(indent_step, ' ');
                auto const &arr = jv.get_array();
                for (auto it = arr.begin(), last = std::prev(arr.end()); it != arr.end(); ++it) {
                    os << *indent;
                    save_pretty(os, *it, indent);
                    if (it != last)
                        os << ',';
                    os << '\n';
                }
                indent->resize(indent->size() - indent_step);
                os << *indent << "]";
                break;
            }
            case json::kind::string:
                os << json::serialize(jv.get_string());
                break;
            case json::kind::uint64:
                os << jv.get_uint64();
                break;
            case json::kind::int64:
                os << jv.get_int64();
                break;
            case json::kind::double_:
                os << jv.get_double();
                break;
            case json::kind::bool_:
                if(jv.get_bool())
                    os << "true";
                else
                    os << "false";
                break;
            case json::kind::null:
                os << "null";
                break;
        }
    }

    inline void save_pretty(const std::string &path, const json::value &jv)
    {
        std::ostringstream os {};
        save_pretty(os, jv);
        file::write(path, os.str());
    }
}

#endif // !DAEDALUS_TURBO_JSON_HPP