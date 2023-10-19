/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_COMMON_HPP
#define DAEDALUS_TURBO_CARDANO_COMMON_HPP

#include <ctime>
#include <functional>
#include <optional>
#include <span>
#include <dt/cardano/type.hpp>
#include <dt/cbor.hpp>
#include <dt/file.hpp>
#include <dt/format.hpp>
#include <dt/json.hpp>
#include <dt/util.hpp>
#include <dt/zstd.hpp>

namespace daedalus_turbo {
    struct __attribute__((packed)) stake_ident {
        cardano_hash_28 hash {};
        bool script { false };

        bool operator<(const auto &b) const {
            static_assert(sizeof(*this) == 29);
            return memcmp(this, &b, sizeof(*this)) < 0;
        }

        bool operator==(const auto &b) const {
            return memcmp(this, &b, sizeof(*this)) == 0;
        }

        bool operator!=(const auto &b) const {
            return !(*this == b);
        }

        inline json::value to_json() const
        {
            return json::object {
                { "hash", fmt::format("{}", hash.span()) },
                { "script", script }
            };
        }
    };

    inline std::ostream &operator<<(std::ostream &os, const stake_ident &v)
    {
        os << "stake_ident(hash: " << buffer(v.hash) << ", script: " << v.script << ')';
        return os;
    }

    struct __attribute__((packed)) pay_ident {
        enum class ident_type: uint8_t {
          SHELLEY_KEY, SHELLEY_SCRIPT, BYRON_KEY
        };

        cardano_hash_28 hash {};
        ident_type type {};

        bool operator<(const auto &b) const {
            static_assert(sizeof(*this) == 29);
            return memcmp(this, &b, sizeof(*this)) < 0;
        }

        bool operator==(const auto &b) const {
            return memcmp(this, &b, sizeof(*this)) == 0;
        }

        bool operator!=(const auto &b) const {
            return !(*this == b);
        }

        inline const char *type_name() const
        {
            switch (type) {
                case ident_type::SHELLEY_KEY:
                    return "shelley-key";
                case ident_type::SHELLEY_SCRIPT:
                    return "shelley-script";
                case ident_type::BYRON_KEY:
                    return "byron-key";
                default:
                    throw cardano_error("unknown indent_type: {}!", (int)type);
            }
        }

        inline json::value to_json() const
        {    
            return json::object {
                { "hash", fmt::format("{}", hash.span()) },
                { "type", type_name() }
            };
        }
    };
}

namespace daedalus_turbo::cardano {
    inline std::string asset_name(const buffer &policy_id, const buffer &asset_name)
    {
        return fmt::format("{} {}", buffer_readable { asset_name }, policy_id.span());
    }

    struct __attribute__((packed)) amount {
        uint64_t coins { 0 };

        operator uint64_t() const
        {
            return coins;
        }

        inline json::value to_json() const;
    };

    struct amount_pure: public amount {
        inline json::value to_json() const;
    };

    struct amount_asset: public amount {
        buffer policy_id {};
        std::string_view asset {};

        inline json::value to_json() const;
    };

    struct __attribute__((packed)) balance_change {
        int64_t change { 0 };

        operator int64_t() const
        {
            return change;
        }

        inline json::value to_json() const;
    };

    using multi_balance_change = std::map<std::string, int64_t>;

    struct multi_balance: public std::map<std::string, uint64_t> {
        using std::map<std::string, uint64_t>::map;

        inline json::object to_json() const;
    };
    
    struct __attribute__((packed)) slot {
        uint64_t _slot = 0;

        slot() =default;
        
        slot(uint64_t slot_): _slot { slot_ }
        {
        }

        auto &operator=(uint64_t slot_)
        {
            _slot = slot_;
            return *this;
        }

        operator uint64_t() const
        {
            return _slot;
        }

        uint64_t epoch() const
        {
            if (_slot <= 208 * 21600) {
                return _slot / 21600;
            } else {
                return 208 + (_slot - 208 * 21600) / 432000;
            }
        }

        uint64_t unixtime() const
        {
            if (_slot >= _shelley_begin_slot) {
                return _shelley_begin_ts + (_slot - _shelley_begin_slot);
            } else {
                return _shelley_begin_ts - (_shelley_begin_slot - _slot) * 20;
            }
        }

        std::string timestamp() const
        {
            std::time_t t = unixtime();
            std::tm* tm = std::gmtime(&t);
            std::stringstream ss {};
            ss << std::put_time(tm, "%Y-%m-%d %H:%M:%S");
            return ss.str();
        }

        std::string utc_month() const
        {
            return timestamp().substr(0, 7);
        }

        inline json::value to_json() const
        {
            return json::object {
                { "slot", _slot },
                { "epoch", epoch() },
                { "timestamp", timestamp() }
            };
        }
    private:
        static constexpr uint64_t _shelley_begin_ts = 1596051891;
        static constexpr uint64_t _shelley_begin_slot = 208 * 21600;
    };

    struct address {
        buffer data;
        uint8_t type = 0;

        address(const buffer &bytes): data { bytes.data() + 1, bytes.size() - 1 }
        {
            if (bytes.size() < 2) throw cardano_error("cardano address must have at least two bytes!");
            type = (bytes.data()[0] >> 4) & 0xF;
            switch (type) {
                case 0b1110: // reward key
                case 0b1111: // reward script
                case 0b0110: // enterprise key
                case 0b0111: // enterprise script
                    if (bytes.size() < 29) throw cardano_error("cardano reward addresses must have at least 29 bytes: {}!", bytes);
                    break;

                case 0b0000: // base address: keyhash28,keyhash28
                case 0b0001: // base address: scripthash28,keyhash28
                case 0b0010: // base address: keyhash28,scripthash28
                case 0b0011: // base address: scripthash28,scripthash28
                    if (bytes.size() < 57) throw cardano_error("shelley base address must have at least 57 bytes", bytes);
                    break;

                case 0b1000: // byron
                    data = bytes;
                    break;

                case 0b0100: // pointer key
                case 0b0101: // pointer script
                    break;

                default:
                    throw cardano_error("unsupported address type: {}!", type);
            }
        }

        const pay_ident pay_id() const
        {
            switch (type) {
                case 0b0110: // enterprise key
                case 0b0111: // enterprise script
                case 0b0000: // base address: keyhash28,keyhash28
                case 0b0001: // base address: scripthash28,keyhash28
                case 0b0010: // base address: keyhash28,scripthash28
                case 0b0011: // base address: scripthash28,scripthash28
                    return pay_ident { data.subbuf(0, 28), (type & 0x1) > 0 ? pay_ident::ident_type::SHELLEY_SCRIPT : pay_ident::ident_type::SHELLEY_KEY };

                case 0b1000: { // byron
                    auto addr_hash = blake2b<cardano_hash_28>(data);
                    return pay_ident { addr_hash.span(), pay_ident::ident_type::BYRON_KEY };
                }

                default:
                    throw cardano_error("unsupported address for type: {}!", type);
            }
        }

        const stake_ident stake_id() const
        {
            switch (type) {
                case 0b1110: // reward key
                case 0b1111: // reward script
                    return stake_ident { data.subbuf(0, 28), (type & 0x1) > 0 };

                case 0b0000: // base address: keyhash28,keyhash28
                case 0b0001: // base address: scripthash28,keyhash28
                case 0b0010: // base address: keyhash28,scripthash28
                case 0b0011: // base address: scripthash28,scripthash28
                    return stake_ident { data.subbuf(28, 28), (type & 0x2) > 0 };

                default:
                    throw cardano_error("address::stake_id unsupported for address type: {}!", type);
            }
        }

        bool has_stake_id() const
        {
            switch (type) {
                case 0b1110: // reward key
                case 0b1111: // reward script
                case 0b0000: // base address: keyhash28,keyhash28
                case 0b0001: // base address: scripthash28,keyhash28
                case 0b0010: // base address: keyhash28,scripthash28
                case 0b0011: // base address: scripthash28,scripthash28
                    return true;

                default:
                    return false;
            }
        }

        bool has_pay_id() const
        {
            switch (type) {
                case 0b0110: // enterprise key
                case 0b0111: // enterprise script
                case 0b0000: // base address: keyhash28,keyhash28
                case 0b0001: // base address: scripthash28,keyhash28
                case 0b0010: // base address: keyhash28,scripthash28
                case 0b0011: // base address: scripthash28,scripthash28
                    return true;

                default:
                    return false;
            }
        }

        inline json::value to_json() const
        {
            const char *type_str = nullptr;
            switch (type) {
                case 0b1110: // reward key
                    type_str = "shelley-reward-key";
                    break;

                case 0b1111: // reward script
                    type_str = "shelley-reward-script";
                        break;

                case 0b0110: // enterprise key
                    type_str = "shelley-enterprise-key";
                    break;

                case 0b0111: // enterprise script
                    type_str = "shelley-enterprise-script";
                    break;

                case 0b0000: // base address: keyhash28,keyhash28
                case 0b0001: // base address: scripthash28,keyhash28
                case 0b0010: // base address: keyhash28,scripthash28
                case 0b0011: // base address: scripthash28,scripthash28
                    type_str = "shelley-base";
                    break;

                case 0b1000: // byron
                    type_str = "byron";
                    break;

                case 0b0100: // pointer key
                    type_str = "shelley-pointer-key";
                    break;

                case 0b0101: // pointer script
                    type_str = "shelley-pointer-script";
                    break;
            }
            if (!type_str) throw cardano_error("unsupported address type: {}!", type);
            json::object res {
                { "type", type_str },
                { "data", fmt::format("{}", data) }
            };
            if (has_stake_id()) res.emplace("stakeId", stake_id().to_json());
            if (has_pay_id()) res.emplace("payId", pay_id().to_json());
            return res;
        }
    };

    struct __attribute__((packed)) tx_size {

        tx_size(): _size { 0 }
        {
        }
        
        tx_size(size_t sz)
        {
            size_t packed_sz = sz >> 8;
            if (packed_sz >= 256 || (packed_sz == 255 && sz & 0xFF)) throw error("tx size is too big: {}!", sz);
            if (sz & 0xFF) ++packed_sz;
            _size = (uint8_t)packed_sz;
        }

        operator std::size_t() const
        {
            return (size_t)(_size) << 8;
        }
    private:
        uint8_t _size;
    };

    struct __attribute__((packed)) tx_out_idx {

        tx_out_idx(): _out_idx { 0 } {}

        tx_out_idx(size_t out_idx)
        {
            if (out_idx >= (1U << 16)) throw error("tx out idx is too big: {}!", out_idx);
            _out_idx = out_idx;
        }

        tx_out_idx &operator=(size_t out_idx)
        {
            if (out_idx >= (1U << 16)) throw error("tx out idx is too big: {}!", out_idx);
            _out_idx = out_idx;
            return *this;
        }

        operator std::size_t() const
        {
            return _out_idx;
        }
    private:
        uint16_t _out_idx;
    };

    struct tx_input {
        const buffer &tx_hash;
        const cardano::tx_out_idx txo_idx;
        const cardano::tx_out_idx idx;

        inline json::object to_json() const
        {
            return json::object {
                { "hash", fmt::format("{}", tx_hash) },
                { "outIdx", (size_t)txo_idx }
            };
        }
    };

    struct tx_output {
        const cardano::address &address;
        const cardano::amount amount;
        const cardano::tx_out_idx idx;
        const cbor_map *assets = nullptr;

        inline json::object to_json() const;
    };

    struct tx_withdrawal {
        const cardano::address &address;
        const cardano::amount amount;
        const cardano::tx_out_idx idx;
    };

    struct kes_signature {
        const buffer &vkey;
        const buffer &vkey_sig;
        const buffer &vkey_cold;
        const buffer &sig;
        const buffer header_body;
        uint64_t counter = 0;
        uint64_t period = 0;
        cardano::slot slot {};

        bool verify() const
        {
            std::array<uint8_t, sizeof(cardano_vkey) + 2 * 8> ocert_data {};
            if (vkey.size() != sizeof(cardano_vkey))
                throw error("vkey size mismatch!");
            memcpy(ocert_data.data(), vkey.data(), sizeof(cardano_vkey));
            uint64_t ctr = host_to_net<uint64_t>(counter);
            memcpy(ocert_data.data() + sizeof(cardano_vkey), &ctr, 8);
            uint64_t kp = host_to_net<uint64_t>(period);
            memcpy(ocert_data.data() + sizeof(cardano_vkey) + 8, &kp, 8);
            if (!ed25519::verify(vkey_sig, vkey, ocert_data))
                return false;
            uint64_t block_period = (uint64_t)slot / 129600;
            if (period > block_period)
                throw error("KES period {} is greater than the current period {}", period, block_period);
            uint64_t t = block_period - period;
            cardano_kes_signature kes_sig { sig };
            return kes_sig.verify(t, vkey.first<32>(), header_body);
        }
    };

    struct block_vrf {
        const buffer &vkey;
        const buffer &leader_result;
        const buffer &leader_proof;
        const buffer &nonce_result;
        const buffer &nonce_proof;
    };

    struct tx;

    struct block_base {
        block_base(const cbor_value &block_tuple, uint64_t offset, uint64_t era, const cbor_value &block)
            : _block_tuple { block_tuple }, _block { block }, _era { era }, _offset { offset }
        {
        }

        virtual ~block_base() {}
        virtual uint64_t height() const =0;
        virtual cardano_hash_32 hash() const =0;
        virtual const cbor_buffer &prev_hash() const =0;
        virtual const cardano::slot slot() const =0;
        virtual void foreach_tx(const std::function<void(const tx &)> &) const;

        virtual const buffer issuer_vkey() const
        {
            throw error("unsupported");
        }

        virtual const kes_signature kes() const
        {
            throw error("unsupported");
        }

        virtual const block_vrf vrf() const
        {
            throw error("unsupported");
        }

        virtual size_t tx_count() const
        {
            return 0;
        }

        inline uint64_t era() const
        {
            return _era;
        };

        virtual uint64_t value_offset(const cbor_value &v) const
        {
            if (v.data < _block_tuple.data) throw error("internal error: only CBOR values from within the same block are supported!");
            return _offset + (v.data - _block_tuple.data);
        }

        inline uint64_t offset() const
        {
            return _offset;
        }

        inline size_t size() const
        {
            return _block_tuple.size;
        }
    protected:
        const cbor_value &_block_tuple;
        const cbor_value &_block;
        uint64_t _era, _offset;
    };

    struct tx {
        struct vkey_wit_ok {
            size_t total = 0;
            size_t ok = 0;

            bool operator()() const noexcept
            {
                return total == ok;
            }
        };

        tx(const cbor_value &tx, const block_base &blk, const cbor_value *wit=nullptr): _tx { tx }, _blk { blk }, _wit { wit }
        {
        }

        virtual ~tx() {}
        virtual vkey_wit_ok vkey_witness_ok() const =0;
        virtual void foreach_input(const std::function<void(const tx_input &)> &) const {}
        virtual void foreach_output(const std::function<void(const tx_output &)> &) const {}
        virtual void foreach_withdrawal(const std::function<void(const tx_withdrawal &)> &) const {}

        virtual const cardano_hash_32 &hash() const
        {
            if (!_cached_hash.has_value()) {
                _cached_hash.emplace(blake2b<cardano_hash_32>(_tx.data_buf()));
            }
            return _cached_hash.value();
        }

        virtual size_t offset() const
        {
            return _blk.value_offset(_tx);
        }

        virtual size_t size() const
        {
            return _tx.size;
        }

        inline boost::json::value to_json() const
        {
            json::array inputs {};
            foreach_input([&](const auto &tx_in) {
                inputs.emplace_back(tx_in.to_json());
            });
            json::array outputs {};
            foreach_output([&](const auto &tx_out) {
                outputs.emplace_back(tx_out.to_json());
            });
            return json::object {
                { "hash", fmt::format("{}", hash().span()) },
                { "offset", offset() },
                { "size", size() },
                { "slot", block().slot().to_json() },
                { "inputs", std::move(inputs) },
                { "outputs", std::move(outputs) }
            };
        }

        inline buffer raw_data() const
        {
            return _tx.data_buf();
        }

        inline const block_base &block() const
        {
            return _blk;
        }
    protected:
        const cbor_value &_tx;
        const block_base &_blk;
        const cbor_value *_wit = nullptr;
        mutable std::optional<cardano_hash_32> _cached_hash {};
    };

    inline void block_base::foreach_tx(const std::function<void(const tx &)> &) const
    {
    }

    inline uint64_t _extract_epoch_byron_ebb(const buffer &data)
    {
        if (data.size() < 0x400) throw error("buffer must contain at least 4096 elements but has: {}!", data.size());
        if (data[0] != 0x83) throw error("the block's first byte must contain {}", 0x83);
        cbor_parser parser { data.subspan(1, data.size() - 1) };
        cbor_value header {};
        parser.read(header);
        return header.array().at(3).array().at(0).uint();
    }

    inline uint64_t _extract_epoch_byron(const buffer &data)
    {
        if (data.size() < 0x400) throw error("buffer must contain at least 4096 elements but has: {}!", data.size());
        if (data[0] != 0x83) throw error("the block's first byte must contain {}", 0x83);
        cbor_parser parser { data.subspan(1, data.size() - 1) };
        cbor_value header {};
        parser.read(header);
        return header.array().at(3).array().at(0).array().at(0).uint();
    }

    inline uint64_t _extract_epoch_shelley(const buffer &data, uint8_t s1=0x84, uint8_t s2=0x82, uint8_t s3=0x8F)
    {
        if (data.size() < 0x100) throw error("buffer must contain at least 4096 elements but has: {}!", data.size());
        if (data[0] != s1) throw error("the block's first byte must contain {}", s1);
        if (data[1] != s2) throw error("the block's first byte must contain {}", s2);
        if (data[2] != s3) throw error("the block's first byte must contain {}", s3);
        cbor_parser parser { data.subspan(3, 0x100) };
        cbor_value slot {};
        // slot number is the second array element
        parser.read(slot);
        parser.read(slot);
        return cardano::slot { slot.uint() }.epoch();
    }

    inline uint64_t extract_epoch(const buffer &data)
    {
        if (data.size() < 0x400) throw error("buffer must contain at least 4096 elements but has: {}!", data.size());
        if (data[0] != 0x82) throw error("each cardano block must start with a 2-element CBOR array");
        cbor_parser parser { data.subspan(1, 1) };
        cbor_value era {};
        parser.read(era);

        switch (era.uint()) {
        case 0:
            return _extract_epoch_byron_ebb(data.subspan(2, data.size() - 2));

        case 1:
            return _extract_epoch_byron(data.subspan(2, data.size() - 2));

        case 2:
        case 3:
        case 4:
            return _extract_epoch_shelley(data.subspan(2, data.size() - 2), 0x84, 0x82, 0x8F);

        case 5:
            return _extract_epoch_shelley(data.subspan(2, data.size() - 2), 0x85, 0x82, 0x8F);
        case 6:
        case 7:
            return _extract_epoch_shelley(data.subspan(2, data.size() - 2), 0x85, 0x82, 0x8A);

        default:
            throw cardano_error("unsupported era {}!", era.uint());
        }
    }

    inline uint64_t extract_epoch(const std::string &path)
    {
        auto buf = file::read(path);
        return extract_epoch(buf);
    }
}

namespace fmt {
    template<>
    struct formatter<const daedalus_turbo::cardano::slot>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto a, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", (uint64_t)a);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::tx_out_idx>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto a, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", (size_t)a);
        }
    };

    template<>
    struct formatter<const daedalus_turbo::stake_ident>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &id, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "stake_ident(id: {}, type: {})", id.hash.span(), id.script ? "script" : "key");
        }
    };

    template<>
    struct formatter<daedalus_turbo::stake_ident>: public formatter<const daedalus_turbo::stake_ident> {
    };

    template<>
    struct formatter<daedalus_turbo::pay_ident>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &id, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "pay_ident(id: {}, type: {})", id.hash.span(), id.type_name());
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::slot>: public formatter<const daedalus_turbo::cardano::slot> {
    };

    template<>
    struct formatter<daedalus_turbo::cardano::amount_pure> {
        constexpr auto parse(format_parse_context &ctx) -> decltype(ctx.begin()) {
            return ctx.begin();
        }

        template<typename FormatContext>
        auto format(const auto &a, FormatContext &ctx) const -> decltype(ctx.out()) {
            uint64_t full = a.coins / 1'000'000;
            uint64_t rem = a.coins % 1'000'000;
            return fmt::format_to(ctx.out(), "{}.{:06}", full, rem);
        }
    };
    
    template<>
    struct formatter<daedalus_turbo::cardano::amount>: public formatter<daedalus_turbo::cardano::amount_pure> {
        template<typename FormatContext>
        auto format(const auto &a, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{} ADA", daedalus_turbo::cardano::amount_pure { a.coins });
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::amount_asset>: public formatter<daedalus_turbo::cardano::amount_pure> {
        template<typename FormatContext>
        auto format(const auto &a, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{} {}/{}", daedalus_turbo::cardano::amount_pure { a.coins }, a.policy_id, a.asset);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::balance_change>: public formatter<daedalus_turbo::cardano::amount_pure> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            int64_t change = v;
            char sign = '+';
            if (change < 0) {
                sign = '-';
                change = -change;
            }
            int64_t full = change / 1'000'000;
            int64_t rem = change % 1'000'000;
            return fmt::format_to(ctx.out(), "{}{}.{:06}", sign, full, rem);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::multi_balance_change>: public formatter<daedalus_turbo::cardano::balance_change> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = ctx.out();
            for (const auto &[asset_name, change]: v) {
                out_it = fmt::format_to(out_it, "{} {}; ", daedalus_turbo::cardano::balance_change { change }, asset_name);
            }
            return out_it;
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::multi_balance>: public formatter<daedalus_turbo::cardano::amount_pure> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = ctx.out();
            out_it = fmt::format_to(out_it, "[\n");
            for (const auto &[asset_name, amount]: v) {
                out_it = fmt::format_to(out_it, "    {} {}\n", daedalus_turbo::cardano::amount_pure { amount }, asset_name);
            }
            out_it = fmt::format_to(out_it, "]");
            return out_it;
        }
    };

    template<>
    struct formatter<const daedalus_turbo::cardano::address> {
        constexpr auto parse(format_parse_context &ctx) -> decltype(ctx.begin()) {
            return ctx.begin();
        }

        template<typename FormatContext>
        auto format(const daedalus_turbo::cardano::address addr, FormatContext &ctx) const -> decltype(ctx.out()) {
            using daedalus_turbo::buffer;
            switch (addr.type) {
                case 0b1000:
                    return fmt::format_to(ctx.out(), "byron/{}", addr.data);

                case 0b1110:
                case 0b1111:
                    return fmt::format_to(ctx.out(), "shelley-reward/{}-{}", (addr.type & 1) ? "script" : "key", addr.data);

                case 0b0000: // base address: keyhash28,keyhash28
                case 0b0001: // base address: scripthash28,keyhash28
                case 0b0010: // base address: keyhash28,scripthash28
                case 0b0011: // base address: scripthash28,scripthash28
                    return fmt::format_to(ctx.out(), "shelley-base/pay_{}:{}-stake_{}:{}",
                        (addr.type & 1) > 0 ? "script" : "key", buffer { addr.data.data(), 28 },
                        (addr.type & 2) > 0 ? "script" : "key", buffer { addr.data.data() + 28, 28 });

                case 0b0110:
                case 0b0111:
                    return fmt::format_to(ctx.out(), "shelley-enterprise/{}-{}", (addr.type & 1) ? "script" : "key", addr.data);

                case 0b0100:
                case 0b0101:
                    return fmt::format_to(ctx.out(), "shelley-pointer/{}-{}", (addr.type & 1) ? "script" : "key", addr.data);

                default:
                    throw daedalus_turbo::cardano_error("unsupported address type: {}!", addr.type);
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::address>: public formatter<const daedalus_turbo::cardano::address> {
    };
}

namespace daedalus_turbo::cardano {
    inline std::ostream &operator<<(std::ostream &os, const cardano::amount a) {
        os << format("{}", a);
        return os;
    }

    inline json::value amount::to_json() const
    {
        return json::string { fmt::format("{}", *this) };
    }

    inline json::value amount_pure::to_json() const
    {
        return json::string { fmt::format("{}", *this) };
    }

    inline json::value amount_asset::to_json() const
    {
        return json::object {
            { "policyId", fmt::format("{}", policy_id) },
            { "name", asset },
            { "amount", coins },
        };
    }

    inline json::value balance_change::to_json() const
    {
        return json::string { fmt::format("{}", *this) };
    }

    inline json::object multi_balance::to_json() const
    {
        json::object j {};
        for (const auto &[asset_name, amount]: *this) {
            j.emplace(asset_name, amount);
        }
        return j;
    }

    inline json::object tx_output::to_json() const
    {
        auto j = json::object {
            { "address", address.to_json() },
            { "amount", amount.to_json() }
        };
        if (assets != nullptr) {
            auto maj = json::object {};
            for (const auto &[policy_id, p_assets]: *assets) {
                for (const auto &[asset, coin]: p_assets.map()) {
                    std::string readable_name = fmt::format("{}", buffer_readable { asset.buf() });
                    maj.emplace(fmt::format("{} {}", readable_name, policy_id.buf()), fmt::format("{}", amount_pure { coin.uint() }));
                }
            }
            j.emplace("assets", std::move(maj));
        }
        return j;
    }
}

#endif // !DAEDALUS_TURBO_CARDANO_COMMON_HPP