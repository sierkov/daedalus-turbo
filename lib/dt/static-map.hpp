/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_STATIC_MAP_HPP
#define DAEDALUS_TURBO_STATIC_MAP_HPP

#include <map>
#include <vector>
#include <unordered_map>
#include <zpp_bits.h>
#include <dt/logger.hpp>
#include <dt/partitioned-map.hpp>

namespace daedalus_turbo {
    template<typename K, typename V>
    struct static_map {
        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self._data);
        }

        using value_type = std::pair<K, V>;
        using storage_type = std::vector<value_type>;
        using const_iterator = storage_type::const_iterator;
        using iterator = storage_type::iterator;

        static_map()
        {
        }

        static_map(static_map<K, V> &&src)
            : _data { std::move(src._data) }
        {
        }

        static_map(const static_map<K, V> &src)
            : _data { src._data }
        {
        }

        static_map<K, V> &operator=(const std::map<K, V> &src)
        {
            _data.clear();
            _data.reserve(src.size());
            // relies on the fact that std::map keeps elements in a sorted order, so there no need to re-sort the data for binary search
            for (const auto &[k, v]: src)
                _data.emplace_back(k, v);
            return *this;
        }

        static_map<K, V> &operator=(const partitioned_map<K, V> &src)
        {
            _data.clear();
            _data.reserve(src.size());
            // relies on the fact that partitioned_map keeps elements in a sorted order, so there no need to re-sort the data for binary search
            for (size_t part_idx = 0; part_idx < src.num_parts; ++part_idx) {
                for (const auto &[k, v]: src.partition(part_idx))
                    _data.emplace_back(k, v);
            }
            return *this;
        }

        static_map<K, V> &operator=(const std::unordered_map<K, V> &src)
        {
            _data.clear();
            _data.reserve(src.size());
            for (const auto &[k, v]: src)
                _data.emplace_back(k, v);
            // must sort since unordered_map does not guarantee the order
            std::sort(_data.begin(), _data.end());
            return *this;
        }

        static_map<K, V> &operator=(static_map<K, V> &&src)
        {
            _data = std::move(src._data);
            return *this;
        }

        static_map<K, V> &operator=(const static_map<K, V> &src)
        {
            _data = src._data;
            return *this;
        }

        void clear()
        {
            _data.clear();
        }

        bool empty() const
        {
            return _data.empty();
        }

        size_t size() const
        {
            return _data.size();
        }

        bool contains(const K &k) const
        {
            return find(k) != end();
        }

        const V &at(const K &k) const
        {
            auto it = find(k);
            if (it == end())
                throw error("unknown key: {}", k);
            return it->second;
        }

        const V get(const K &k) const
        {
            V res {};
            auto it = find(k);
            if (it != end())
                res = it->second;
            return res;
        }

        const_iterator begin() const
        {
            return _data.begin();
        }

        const_iterator end() const
        {
            return _data.end();
        }

        const_iterator find(const K &k) const
        {
            auto it = std::lower_bound(_data.begin(), _data.end(), k, [&](const auto &el, const auto &val) { return el.first < val; });
            if (it != _data.end() && it->first == k)
                return it;
            return end();
        }
    private:
        storage_type _data {};
    };
}

#endif // !DAEDALUS_TURBO_STATIC_MAP_HPP