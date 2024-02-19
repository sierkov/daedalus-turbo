/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PARTITIONED_MAP_HPP
#define DAEDALUS_TURBO_PARTITIONED_MAP_HPP

#include <array>
#include <iterator>
#include <map>
#include <ranges>
#include <dt/error.hpp>

namespace daedalus_turbo {
    template<typename K, typename V>
    struct partitioned_map {
        static constexpr size_t num_parts = 256;

        using self_type = partitioned_map<K, V>;
        using partition_type = std::map<K, V>;
        using key_type = partition_type::key_type;
        using value_type = partition_type::value_type;
        using mapped_type = partition_type::mapped_type;
        using storage_type = std::array<partition_type, num_parts>;

        struct const_iterator {
            const_iterator(const self_type &ctr, size_t part_idx, partition_type::const_iterator part_it)
                : _container { &ctr }, _part_idx { part_idx }, _part_it { part_it }
            {
                _next_valid();
            }

            bool operator==(const auto &b) const
            {
                if (_container != b._container)
                    return false;
                if (_part_idx != b._part_idx)
                    return false;
                // special case for default initialized iterator
                if (_container == nullptr || _part_idx == num_parts)
                    return true;
                return _part_it == b._part_it;
            }

            const value_type &operator*()
            {
                return *_part_it;
            }

            const value_type *operator->()
            {
                return &operator*();
            }

            const_iterator &operator++() {
                if (_part_it == _container->partition(_part_idx).end())
                    throw error("attempt to iterate beyond the end of the container");
                ++_part_it;
                _next_valid();
                return *this;
            }
        private:
            friend self_type;
            const self_type *_container = nullptr;
            size_t _part_idx = num_parts;
            partition_type::const_iterator _part_it {};

            void _next_valid()
            {
                while (_part_it == _container->partition(_part_idx).end()) {
                    if (++_part_idx >= num_parts)
                        break;
                    _part_it = _container->partition(_part_idx).begin();
                }
                if (_part_idx >= num_parts) {
                    _part_idx = num_parts - 1;
                    _part_it = _container->partition(_part_idx).end();
                }
            }
        };

        struct iterator {
            iterator(self_type &ctr, size_t part_idx, partition_type::iterator part_it)
                : _container { &ctr }, _part_idx { part_idx }, _part_it { part_it }
            {
                _next_valid();
            }

            bool operator==(const auto &b) const
            {
                if (_container != b._container)
                    return false;
                if (_part_idx != b._part_idx)
                    return false;
                // special case for default initialized iterator
                if (_container == nullptr || _part_idx == num_parts)
                    return true;
                return _part_it == b._part_it;
            }

            value_type &operator*()
            {
                return *_part_it;
            }

            value_type *operator->()
            {
                return &operator*();
            }

            iterator &operator++() {
                if (_part_it == _container->partition(_part_idx).end())
                    throw error("attempt to iterate beyond the end of the container");
                ++_part_it;
                _next_valid();
                return *this;
            }
        private:
            friend self_type;
            self_type *_container = nullptr;
            size_t _part_idx = num_parts;
            partition_type::iterator _part_it {};

            void _next_valid()
            {
                while (_part_it == _container->partition(_part_idx).end()) {
                    if (++_part_idx >= num_parts)
                        break;
                    _part_it = _container->partition(_part_idx).begin();
                }
                if (_part_idx >= num_parts) {
                    _part_idx = num_parts - 1;
                    _part_it = _container->partition(_part_idx).end();
                }
            }
        };

        static inline size_t partition_idx(const auto &k)
        {
            static_assert(sizeof(K) > 1);
            return *reinterpret_cast<const uint8_t *>(&k);
        }

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self._parts);
        }

        partitioned_map()
        {
        }

        const const_iterator begin() const
        {
            return const_iterator { *this, 0, _parts[0].cbegin() };
        }

        iterator begin()
        {
            return iterator { *this, 0, _parts[0].begin() };
        }

        const_iterator end() const
        {
            return const_iterator { *this, num_parts - 1, _parts[num_parts - 1].cend() };;
        }

        iterator end()
        {
            return iterator { *this, num_parts - 1, _parts[num_parts - 1].end() };;
        }

        template<typename ...A>
        std::pair<iterator, bool> try_emplace(const K &k, A &&...args)
        {
            auto part_idx = partition_idx(k);
            auto [part_it, created] = _parts[part_idx].try_emplace(k, std::forward<A>(args)...);
            return std::make_pair(iterator { *this, part_idx, std::move(part_it) }, created);
        }

        iterator find(const K &k)
        {
            auto part_idx = partition_idx(k);
            auto &part = _parts[part_idx];
            auto part_it = part.find(k);
            if (part_it != part.end())
                return iterator { *this, part_idx, part_it };
            else
                return end();
        }

        iterator erase(const iterator it)
        {
            auto end_it = end();
            if (it != end_it) {
                auto &part = _parts[it._part_idx];
                return iterator { *this, it._part_idx, part.erase(it._part_it) };
            }
            return end_it;
        }

        iterator erase(const K &k)
        {
            return erase(find(k));
        }

        void clear()
        {
            for (auto &part: _parts)
                part.clear();
        }

        bool empty() const
        {
            return size() == 0;
        }

        size_t size() const
        {
            size_t sz = 0;
            for (const auto &part: _parts)
                sz += part.size();
            return sz;
        }

        bool contains(const K &k) const
        {
            auto &part = _parts[partition_idx(k)];
            return part.find(k) != part.end();
        }

        V &operator[](const K &k)
        {
            return _parts[partition_idx(k)][k];
        }

        const V &at(const K &k) const
        {
            auto &part = _parts[partition_idx(k)];
            auto it = part.find(k);
            if (it == part.end())
                throw error("unknown key: {}", k);
            return it->second;
        }

        const V get(const K &k) const
        {
            V res {};
            auto &part = _parts[partition_idx(k)];
            auto it = part.find(k);
            if (it != part.end())
                res = it->second;
            return res;
        }

        void partition(size_t part_idx, partition_type &&part)
        {
            _check_part_idx(part_idx);
            _parts[part_idx] = std::move(part);
        }

        partition_type &partition(size_t part_idx)
        {
            _check_part_idx(part_idx);
            return _parts[part_idx];
        }

        const partition_type &partition(size_t part_idx) const
        {
            _check_part_idx(part_idx);
            return _parts[part_idx];
        }
    private:
        static inline void _check_part_idx(size_t part_idx)
        {
            if (part_idx >= num_parts)
                throw error("partition idx is too big {}", part_idx);
        }

        storage_type _parts {};
    };
}

#endif // !DAEDALUS_TURBO_PARTITIONED_MAP_HPP