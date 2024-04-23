/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_JSON_HPP
#define DAEDALUS_TURBO_JSON_HPP

#include <boost/json.hpp>
#include <dt/blake2b.hpp>
#include <dt/ed25519.hpp>
#include <dt/file.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::json {
    using namespace boost::json;

    inline json::value parse(const buffer &buf, json::storage_ptr sp={})
    {
        return boost::json::parse(buf.string_view(), sp);
    }

    inline json::value parse_signed(const buffer &buf, const buffer &vk, json::storage_ptr sp={})
    {
        auto j_signed = boost::json::parse(buf.string_view(), sp).as_object();
        if (!j_signed.contains("signature"))
            throw error("a signed json must contain signature!");
        const auto sig = ed25519::signature::from_hex(static_cast<std::string_view>(j_signed.at("signature").as_string()));
        j_signed.erase("signature");
        const auto content = json::serialize(j_signed);
        const auto hash = blake2b<blake2b_256_hash>(content);
        if (!ed25519::verify(sig, vk, hash))
            throw error("Verification of a signed JSON response has failed!");
        return j_signed;
    }

    inline json::value load(const std::string &path, json::storage_ptr sp={})
    {
        return parse(file::read(path), sp);
    }

    inline json::value load_signed(const std::string &path, const buffer &vk, json::storage_ptr sp={})
    {
        return parse_signed(file::read(path), vk, sp);
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
                const auto &obj = jv.get_object();
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
                const auto &arr = jv.get_array();
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

    inline void save_pretty_signed(const std::string &path, const json::object &jv, const buffer &sk)
    {
        const auto content = json::serialize(jv);
        const auto hash = blake2b<blake2b_256_hash>(content);
        ed25519::signature sig {};
        ed25519::sign(sig, hash, sk);
        json::object jv_copy(jv);
        jv_copy.emplace("signature", fmt::format("{}", sig));
        save_pretty(path, jv_copy);
    }
}

#endif // !DAEDALUS_TURBO_JSON_HPP