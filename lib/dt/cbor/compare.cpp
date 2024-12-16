/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cbor/compare.hpp>
#include <dt/cbor/zero2.hpp>
#include <dt/container.hpp>

namespace daedalus_turbo::cbor {
    using namespace zero2;

    struct path_t {
        vector<size_t> items {};

        void push(const size_t v)
        {
            items.emplace_back(v);
        }

        void pop()
        {
            items.pop_back();
        }

        std::string str() const
        {
            return fmt::format("{}", items);
        }
    };

    static bool compare_uint(const uint64_t v1, const uint64_t v2, path_t &path)
    {
        if (v1 != v2) [[unlikely]] {
            logger::warn("{}: expected: {} actual: {}", path.str(), v1, v2);
            return false;
        }
        return true;
    }

    static bool compare_nint(const uint64_t v1, const uint64_t v2, path_t &path)
    {
        if (v1 != v2) [[unlikely]] {
            logger::warn("{}: expected: -({} + 1) actual: -({} + 1)", path.str(), v1, v2);
            return false;
        }
        return true;
    }

    static bool compare_text(const value &v1, const value &v2, path_t &path)
    {
        if (v1.indefinite() != v2.indefinite()) [[unlikely]] {
            logger::warn("{}: expected: {} text actual {} text",
                path.str(), v1.indefinite() ? "chunked" : "normal", v2.indefinite() ? "chunked" : "normal");
            return false;
        }
        if (!v1.indefinite()) [[likely]] {
            if (v1.text() != v2.text()) [[unlikely]] {
                logger::warn("{}: expected: {} actual: {}", path.str(), v1.stringify(), v2.stringify());
                return false;
            }
        } else {
            std::string t1 {}, t2 {};
            v1.to_text(t1);
            v2.to_text(t2);
            if (t1 != t2) [[unlikely]] {
                logger::warn("{}: expected: T '{}' actual: T '{}'", path.str(), t1, t2);
                return false;
            }
        }
        return true;
    }

    static bool compare_bytes(const value &v1, const value &v2, path_t &path)
    {
        if (v1.indefinite() != v2.indefinite()) [[unlikely]] {
            logger::warn("{}: expected: {} text actual {} text",
                path.str(), v1.indefinite() ? "chunked" : "normal", v2.indefinite() ? "chunked" : "normal");
            return false;
        }
        if (!v1.indefinite()) [[likely]] {
            if (v1.bytes() != v2.bytes()) [[unlikely]] {
                logger::warn("{}: expected: {} actual: {}", path.str(), v1.stringify(), v2.stringify());
                return false;
            }
        } else {
            uint8_vector b1 {}, b2 {};
            v1.to_bytes(b1);
            v2.to_bytes(b2);
            if (b1 != b2) [[unlikely]] {
                logger::warn("{}: expected: B #{} actual: B #{}", path.str(), b1, b2);
                return false;
            }
        }
        return true;
    }

    static bool compare(const value &v1, const value &v2, path_t &path);

    static bool compare_array(const value &v1, const value &v2, path_t &path)
    {
        auto &it1 = v1.array();
        auto &it2 = v2.array();
        size_t i = 0;
        while (!it1.done() && !it2.done()) {
            path.push(i);
            if (!compare(it1.read(), it2.read(), path)) [[unlikely]]
                return false;
            path.pop();
            ++i;
        }
        struct it_info {
            std::string_view name;
            value::array_reader &it;
        };
        for (const auto &it: std::initializer_list<it_info> { { "missing", it1 }, { "extra", it2 } }) {
            size_t cnt = 0;
            while (!it.it.done()) {
                auto val = it.it.read();
                logger::debug("missing array item #{}: {}", cnt, val);
                ++cnt;
            }
            if (cnt) [[unlikely]] {
                logger::warn("{}: {} items: {}", path.str(), it.name, cnt);
                return false;
            }
        }
        return true;
    }

    static bool compare_map(const value &v1, const value &v2, path_t &path)
    {
        auto &it1 = v1.map();
        auto &it2 = v2.map();
        size_t i = 0;
        while (!it1.done() && !it2.done()) {
            auto k1 = it1.read_key();
            auto k2 = it2.read_key();
            path.push(i);
            if (!compare(k1, k2, path)) [[unlikely]]
                return false;
            auto v1 = it1.read_val(k1);
            auto v2 = it2.read_val(k2);
            if (!compare(v1, v2, path)) [[unlikely]]
                return false;
            path.pop();
            ++i;
        }
        struct it_info {
            std::string_view name;
            value::map_reader &it;
        };
        for (const auto &it: std::initializer_list<it_info> { { "missing", it1 }, { "extra", it2 } }) {
            size_t cnt = 0;
            while (!it.it.done()) {
                auto k = it.it.read_key();
                auto val = it.it.read_val(k);
                logger::debug("missing map item #{}: {}={}", cnt, k.clone().stringify(), val.stringify());
                ++cnt;
            }
            if (cnt) [[unlikely]] {
                logger::warn("{}: {} items: {}", path.str(), it.name, cnt);
                return false;
            }
        }
        return true;
    }

    static bool compare_tag(const value &v1, const value &v2, path_t &path)
    {
        auto &t1 = v1.tag();
        auto &t2 = v2.tag();
        if (t1.id() != t2.id()) [[unlikely]] {
            logger::warn("{}: expected id: {} actual id: {}", path.str(), t1.id(), t2.id());
            return false;
        }
        auto c1 = t1.read();
        auto c2 = t2.read();
        return compare(c1, c2, path);
    }

    static bool compare_simple(const value &v1, const value &v2, path_t &path)
    {
        if (v1.special() != v2.special()) [[unlikely]] {
            logger::warn("{}: expected simple: {} actual simple: {}",
                path.str(), static_cast<int>(v1.special()), static_cast<int>(v2.special()));
            return false;
        }
        return true;
    }

    static bool compare(const value &v1, const value &v2, path_t &path)
    {
        if (v1.type() != v2.type()) [[unlikely]] {
            logger::warn("{}: types do not match: expected: {} actual: {}", path.str(), v1.type(), v2.type());
            return false;
        }
        switch (const auto typ = v1.type(); typ) {
            case cbor::major_type::uint: return compare_uint(v1.uint(), v2.uint(), path);
            case cbor::major_type::nint: return compare_nint(v1.uint(), v2.uint(), path);
            case cbor::major_type::text: return compare_text(v1, v2, path);
            case cbor::major_type::bytes: return compare_bytes(v1, v2, path);
            case cbor::major_type::array: return compare_array(v1, v2, path);
            case cbor::major_type::map: return compare_map(v1, v2, path);
            case cbor::major_type::tag: return compare_tag(v1, v2, path);
            case cbor::major_type::simple: return compare_simple(v1, v2, path);
            default: throw error(fmt::format("can't compare cbor type: {}", typ));
        }
    }

    bool compare(const buffer &bytes1, const buffer &bytes2)
    {
        path_t path {};
        decoder it1 { bytes1 };
        decoder it2 { bytes2 };
        size_t i = 0;
        while (!it1.done() && !it2.done()) {
            path.push(i);
            if (!compare(it1.read(), it2.read(), path)) [[unlikely]]
                return false;
            path.pop();
            ++i;
        }
        struct it_info {
            std::string_view name;
            decoder &it;
        };
        for (const auto &it: std::initializer_list<it_info> { { "missing", it1 }, { "extra", it2 } }) {
            size_t cnt = 0;
            while (!it.it.done()) {
                ++cnt;
                it.it.read();
            }
            if (cnt) [[unlikely]] {
                logger::warn("{}: {} items: {}", path.str(), it.name, cnt);
                return false;
            }
        }
        return true;
    }
}