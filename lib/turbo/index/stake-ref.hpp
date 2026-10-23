#pragma once
/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <turbo/index/common.hpp>

namespace turbo::index::stake_ref {

    inline constexpr const char *script_index_name = "stake-ref-script";
    inline constexpr const char *key_index_name = "stake-ref-key";
    inline constexpr size_t num_parts = 256;

    struct reference {
        cardano::stake_ident id {};
        uint64_t offset = 0;
        cardano::tx_size size {};
        cardano::tx_out_idx out_idx {};
    };

    // The credential kind belongs to the stream, not each on-disk record.
    template<bool Script>
    struct item {
        static constexpr std::string_view index_format = Script ? "stake-ref/script" : "stake-ref/key";
        static constexpr size_t index_partitions = num_parts;

        cardano::key_hash hash {};
        uint64_t offset = 0;
        cardano::tx_size size {};
        cardano::tx_out_idx out_idx {};

        bool operator<(const item &b) const
        {
            const int cmp = memcmp(hash.data(), b.hash.data(), hash.size());
            if (cmp != 0) return cmp < 0;
            if (offset != b.offset) return offset < b.offset;
            return out_idx < b.out_idx;
        }

        bool index_less(const item &b) const
        {
            return hash < b.hash;
        }

        bool operator==(const item &b) const
        {
            return hash == b.hash;
        }

        reference as_reference() const { return { { hash, Script }, offset, size, out_idx }; }
    };

    template<bool Script>
    struct chunk_indexer: chunk_indexer_base {
        chunk_indexer(const std::string &path, size_t): _idx { path, num_parts } {}

        ~chunk_indexer() override
        {
            _idx.set_meta("max_offset", buffer::from(max_offset()));
        }

        void index_tx(const cardano::tx_base &tx) override
        {
            size_t out_idx = 0;
            tx.foreach_output([&](const auto &tx_out) {
                const auto addr = tx_out.addr();
                if (addr.has_stake_id()) {
                    const auto id = addr.stake_id();
                    if (id.script == Script)
                        _idx.emplace_part(id.hash[0], id.hash, tx.offset(), tx.size(), out_idx);
                }
                ++out_idx;
            });
        }
    private:
        sorting_writer<item<Script>> _idx;
    };

    template<bool Script>
    using indexer = indexer_offset<item<Script>, chunk_indexer<Script>>;

    // Queries use complete credentials. Full scans merge slices per partition,
    // visiting every script before any key without sorting the records again.
    struct reader {
        using value_type = reference;

        reader(const std::span<const std::string> scripts, const std::span<const std::string> keys)
            : _scripts { scripts }, _keys { keys },
                _script_data { _scripts.init_thread() }, _key_data { _keys.init_thread() } {}

        std::pair<size_t, reference> find(const reference &search)
        {
            _script = search.id.script;
            if (_script)
                return _find(_scripts, _script_data, item<true> { search.id.hash });
            return _find(_keys, _key_data, item<false> { search.id.hash });
        }

        // Only return the remaining matches from the latest find.
        bool read(reference &out)
        {
            if (!_remaining)
                return false;
            --_remaining;
            if (_script)
                return _read(_scripts, _script_data, out);
            return _read(_keys, _key_data, out);
        }

        void foreach(auto &&visit) const
        {
            _foreach(_scripts, visit);
            _foreach(_keys, visit);
        }

        size_t size() const { return _scripts.size() + _keys.size(); }
    private:
        reader_multi_mt<item<true>> _scripts;
        reader_multi_mt<item<false>> _keys;
        reader_multi_mt<item<true>>::thread_data _script_data;
        reader_multi_mt<item<false>>::thread_data _key_data;
        bool _script = true;
        size_t _remaining = 0;

        template<bool Script>
        std::pair<size_t, reference> _find(const reader_multi_mt<item<Script>> &stream, auto &data,
            const item<Script> &search)
        {
            _remaining = 0;
            const auto [count, first] = stream.find(search, data);
            _remaining = count ? count - 1 : 0;
            return { count, first.as_reference() };
        }

        template<bool Script>
        static bool _read(const reader_multi_mt<item<Script>> &stream, auto &data, reference &out)
        {
            item<Script> record {};
            if (!stream.read(record, data))
                throw error("stake reference index ended before all matches were read");
            out = record.as_reference();
            return true;
        }

        template<bool Script>
        static void _foreach(const reader_multi_mt<item<Script>> &stream, auto &visit)
        {
            item<Script> record {};
            for (size_t part = 0; part < num_parts; ++part) {
                // A scan needs only the current partition's decompression caches.
                auto data = stream.init_thread(part);
                while (stream.read_part(part, record, data))
                    visit(record.as_reference());
            }
        }
    };
}

namespace fmt {
    template<>
    struct formatter<turbo::index::stake_ref::reference>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "stake-ref::item(id: {}, offset: {}, size: {}, out_idx: {})",
                v.id, static_cast<uint64_t>(v.offset), static_cast<size_t>(v.size), static_cast<size_t>(v.out_idx));
        }
    };

    template<bool Script>
    struct formatter<turbo::index::stake_ref::item<Script>>: formatter<turbo::index::stake_ref::reference> {
        auto format(const auto &v, auto &ctx) const -> decltype(ctx.out())
        {
            return formatter<turbo::index::stake_ref::reference>::format(v.as_reference(), ctx);
        }
    };
}
