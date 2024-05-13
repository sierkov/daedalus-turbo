/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_COMMON_HPP
#define DAEDALUS_TURBO_CARDANO_COMMON_HPP

#include <chrono>
#include <ctime>
#include <functional>
#include <map>
#include <optional>
#include <ranges>
#include <set>
#include <span>
#include <variant>
#include <dt/cardano/type.hpp>
#include <dt/cbor.hpp>
#include <dt/file.hpp>
#include <dt/format.hpp>
#include <dt/json.hpp>
#include <dt/mutex.hpp>
#include <dt/rational.hpp>
#include <dt/util.hpp>

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
    static constexpr uint64_t density_default_window = 9600; // slots

    using stake_ident = daedalus_turbo::stake_ident;
    using pay_ident = daedalus_turbo::pay_ident;

    inline std::string asset_name(const buffer &policy_id, const buffer &asset_name)
    {
        return fmt::format("{} {}", buffer_readable { asset_name }, policy_id.span());
    }

    struct amount {
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

    struct multi_balance: std::map<std::string, uint64_t> {
        using std::map<std::string, uint64_t>::map;

        inline json::object to_json(size_t offset=0, size_t max_items=1000) const;
    };

    static constexpr uint64_t _shelley_begin_ts = 1596051891 + 7200;
    static constexpr uint64_t _shelley_begin_slot = 208 * 21600;
    static constexpr uint64_t _epoch0_begin_ts = _shelley_begin_ts - _shelley_begin_slot;
    
    struct slot {
        uint64_t _slot = 0;

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self._slot);
        }

        static cardano::slot from_time(const std::chrono::time_point<std::chrono::system_clock> &tp)
        {
            uint64_t secs = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
            if (secs < _shelley_begin_ts)
                throw cardano_error("time point is before the begin of Shelley era: {} seconds of unix time", secs);
            return cardano::slot { secs - _epoch0_begin_ts };
        }

        static cardano::slot from_epoch(uint64_t epoch, uint64_t epoch_slot = 0)
        {
            if (epoch <= 208) {
                return cardano::slot { epoch * 21600 + epoch_slot };
            } else {
                return cardano::slot { (epoch - 208) * 432000 + 208 * 21600 + epoch_slot };
            }
        }

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

        uint64_t epoch_slot() const
        {
            if (_slot <= 208 * 21600) {
                return _slot % 21600;
            } else {
                return (_slot - 208 * 21600) % 432000;
            }
        }

        uint64_t chunk_id() const
        {
            if (_slot <= 208 * 21600) {
                return _slot / 21600;
            } else {
                const auto shelley_slot = _slot - 208 * 21600;
                const auto shelley_chunk = shelley_slot / (432000 / 20);
                return 208 + shelley_chunk;
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
            alignas(mutex::padding) static mutex::unique_lock::mutex_type gmtime_mutex {};
            std::stringstream ss {};
            std::time_t t = unixtime();
            {
                mutex::scoped_lock lk { gmtime_mutex };
                std::tm* tm = std::gmtime(&t);
                ss << std::put_time(tm, "%Y-%m-%d %H:%M:%S");
            }
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
    };

    struct point {
        block_hash hash {};
        cardano::slot slot {};
        uint64_t height = 0;

        bool operator==(const auto &o) const
        {
            return hash == o.hash && slot == o.slot;
        }
    };
    using point_pair = std::pair<point, point>;
    using point_list = std::vector<point>;

    struct stake_pointer {
        cardano::slot slot {};
        uint64_t tx_idx {};
        uint64_t cert_idx {};

        bool operator<(const auto &b) const
        {
            if (slot != b.slot)
                return slot < b.slot;
            if (tx_idx != b.tx_idx)
                return tx_idx < b.tx_idx;
            return cert_idx < b.cert_idx;
        }

        bool operator==(const auto &b) const
        {
            return slot == b.slot && tx_idx == b.tx_idx && cert_idx == b.cert_idx;
        }

        json::object to_json() const
        {
            return json::object {
                { "slot", static_cast<uint64_t>(slot) },
                { "txIdx", tx_idx },
                { "certIdx", cert_idx }
            };
        }
    };

    using stake_ident_hybrid = std::variant<stake_ident, stake_pointer>;

    struct address {
        buffer bytes;
        buffer data;
        uint8_t type = 0;

        address(const buffer &bytes_)
            : bytes { bytes_ }, data { bytes.data() + 1, bytes.size() - 1 }
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
                    if (bytes.size() < 57) throw cardano_error("shelley base address must have at least 57 bytes: {}!", bytes);
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
                case 0b0100: // pointer key
                case 0b0101: // pointer script
                    return pay_ident { data.subbuf(0, 28), (type & 0x1) > 0 ? pay_ident::ident_type::SHELLEY_SCRIPT : pay_ident::ident_type::SHELLEY_KEY };

                case 0b1000: { // byron
                    auto addr_hash = blake2b<cardano_hash_28>(data);
                    return pay_ident { addr_hash.span(), pay_ident::ident_type::BYRON_KEY };
                }

                default:
                    throw cardano_error("unsupported address for type: {}!", type);
            }
        }

        const stake_pointer pointer() const
        {
            stake_pointer p {};
            if (data.size() < 28 + 3)
                throw error("pointer data is too small - expect 31+ bytes but got: {}", data.size());
            auto ptr = data.subspan(28, data.size() - 28);
            uint64_t rel_slot = 0;
            auto sz1 = _read_var_uint_be(rel_slot, ptr);
            p.slot = rel_slot;
            auto sz2 = _read_var_uint_be(p.tx_idx, ptr.subspan(sz1, ptr.size() - sz1));
            _read_var_uint_be(p.cert_idx, ptr.subspan(sz1 + sz2, ptr.size() - sz1 - sz2));
            return p;
        };

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
                case 0b0100: // pointer key
                case 0b0101: // pointer script
                    return true;

                default:
                    return false;
            }
        }

        bool has_pointer() const
        {
            switch (type) {
                case 0b0100: // pointer key
                case 0b0101: // pointer script
                    return true;
                    break;

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
                { "data", fmt::format("{}", bytes) }
            };
            if (has_stake_id())
                res.emplace("stakeId", stake_id().to_json());
            if (has_pay_id())
                res.emplace("payId", pay_id().to_json());
            if (has_pointer())
                res.emplace("stakePointer", pointer().to_json());
            return res;
        }
    private:
        size_t _read_var_uint_be(uint64_t &x, const buffer &buf) const
        {
            if (buf.size() == 0)
                throw cardano_error("can't read a variable integer from an empty buffer!");
            x = 0;
            uint64_t val = static_cast<uint64_t>(buf[0]);
            size_t num_read = 1;
            for (;;) {
                x |= val & 0x7F;
                if (val & 0x80) {
                    if (buf.size() < num_read + 1)
                        throw error("the buffer is too small: {}!", buf.size());
                    val = static_cast<uint64_t>(buf[num_read]);
                    num_read++;
                } else {
                    break;
                }
                x <<= 7;
            }
            return num_read;
        }
    };

    struct tx_size {
        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self._size);
        }

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

    struct tx_out_idx {
        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self._out_idx);
        }

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

    struct cert_idx {

        cert_idx(): _idx { 0 } {}

        cert_idx(size_t idx)
        {
            if (idx >= (1U << 16))
                throw error("tx out idx is too big: {}!", idx);
            _idx = idx;
        }

        cert_idx &operator=(size_t idx)
        {
            if (idx >= (1U << 16))
                throw error("tx out idx is too big: {}!", idx);
            _idx = idx;
            return *this;
        }

        operator std::size_t() const
        {
            return _idx;
        }
    private:
        uint16_t _idx;
    };

    struct epoch {
        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self._epoch);
        }

        static void check(uint64_t epoch)
        {
            if (epoch >= (1U << 16))
                throw error("epoch number is too big: {}!", epoch);
        }

        epoch() =default;

        epoch(uint64_t epoch): _epoch(static_cast<uint16_t>(epoch))
        {
            check(epoch);
        }

        epoch &operator=(uint64_t epoch)
        {
            check(epoch);
            _epoch = static_cast<uint16_t>(epoch);
            return *this;
        }

        operator uint64_t() const
        {
            return _epoch;
        }
    private:
        uint16_t _epoch = 0;
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

    struct collateral_return {
        const cardano::address address;
        const cardano::amount amount;
    };

    struct tx_withdrawal {
        const cardano::address &address;
        const cardano::amount amount;
        const cardano::tx_out_idx idx;
    };

    struct protocol_version {
        uint64_t major = 1;
        uint64_t minor = 0;

        bool operator==(const auto &b) const
        {
            return major == b.major && minor == b.minor;
        }

        bool aggregated_rewards() const
        {
            return major > 2;
        }

        bool forgo_reward_prefilter() const
        {
            return major > 6;
        }
    };

    using nonce = std::optional<cardano_hash_32>;

    struct param_update {
        cardano::pool_hash pool_id {};
        uint64_t epoch = 0;
        std::optional<uint64_t> min_fee_a {};
        std::optional<uint64_t> min_fee_b {};
        std::optional<uint64_t> max_block_body_size {};
        std::optional<uint64_t> max_transaction_size {};
        std::optional<uint64_t> max_block_header_size {};
        std::optional<uint64_t> key_deposit {};
        std::optional<uint64_t> pool_deposit {};
        std::optional<uint64_t> max_epoch {};
        std::optional<uint64_t> n_opt {};
        std::optional<rational_u64> pool_pledge_influence {};
        std::optional<rational_u64> expansion_rate {};
        std::optional<rational_u64> treasury_growth_rate {};
        std::optional<rational_u64> decentralization {};
        std::optional<cardano::nonce> extra_entropy {};
        std::optional<protocol_version> protocol_ver {};
        std::optional<uint64_t> min_utxo_value {};

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.pool_id, self.epoch,
                self.min_fee_a, self.min_fee_b, self.max_block_body_size,
                self.max_transaction_size, self.max_block_header_size, self.key_deposit,
                self.pool_deposit, self.max_epoch, self.n_opt,
                self.pool_pledge_influence, self.expansion_rate, self.treasury_growth_rate,
                self.decentralization, self.extra_entropy, self.protocol_ver, self.min_utxo_value
            );
        }

        bool operator==(const auto &b) const
        {
            if (!_is_equal(min_fee_a, b.min_fee_a))
                return false;
            if (!_is_equal(min_fee_b, b.min_fee_b))
                return false;
            if (!_is_equal(max_block_body_size, b.max_block_body_size))
                return false;
            if (!_is_equal(max_transaction_size, b.max_transaction_size))
                return false;
            if (!_is_equal(max_block_header_size, b.max_block_header_size))
                return false;
            if (!_is_equal(key_deposit, b.key_deposit))
                return false;
            if (!_is_equal(pool_deposit, b.pool_deposit))
                return false;
            if (!_is_equal(max_epoch, b.max_epoch))
                return false;
            if (!_is_equal(n_opt, b.n_opt))
                return false;
            if (!_is_equal(pool_pledge_influence, b.pool_pledge_influence))
                return false;
            if (!_is_equal(expansion_rate, b.expansion_rate))
                return false;
            if (!_is_equal(treasury_growth_rate, b.treasury_growth_rate))
                return false;
            if (!_is_equal(decentralization, b.decentralization))
                return false;
            if (!_is_equal(extra_entropy, b.extra_entropy))
                return false;
            if (!_is_equal(protocol_ver, b.protocol_ver))
                return false;
            if (!_is_equal(min_utxo_value, b.min_utxo_value))
                return false;
            return true;
        }
    private:
        template<typename T>
        static bool _is_equal(const std::optional<T> &a, const std::optional<T> &b)
        {
            if (a.has_value() != b.has_value())
                return false;
            if (a.has_value() && *a != *b)
                return false;
            return true;
        }
    };

    struct stake_deleg {
        stake_ident stake_id {};
        cardano_hash_28 pool_id {};
        size_t cert_idx = 0;
    };

    struct pool_reg {
        cardano_hash_28 pool_id {};
        uint64_t pledge = 0;
        uint64_t cost = 0;
        uint64_t margin_num = 0;
        uint64_t margin_denom = 0;
        stake_ident reward_id {};
        std::set<stake_ident> owners {};
    };

    struct pool_unreg {
        cardano_hash_28 pool_id {};
        cardano::epoch epoch {};
    };

    enum class reward_source { reserves, treasury };

    struct instant_reward {
        reward_source source {};
        std::map<stake_ident, cardano::amount> rewards {};
    };

    struct kes_signature {
        const buffer &vkey;
        const buffer &vkey_sig;
        const buffer &vkey_cold; // issuer_vkey
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

        virtual void foreach_invalid_tx(const std::function<void(const tx &)> &) const
        {
        }

        virtual const protocol_version protocol_ver() const
        {
            return protocol_version {};
        }

        virtual const buffer issuer_vkey() const
        {
            throw error("cardano::block_base::issuer_vkey is not unsupported");
        }

        virtual const kes_signature kes() const
        {
            throw error("cardano::block_base::kes is not unsupported");
        }

        virtual const block_vrf vrf() const
        {
            throw error("cardano::block_base::block_vrf is not unsupported");
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

        virtual bool body_hash_ok() const
        {
            throw error("cardano::block_base::body_hash is not unsupported");
        }

        virtual bool signature_ok() const
        {
            throw error("cardano::block_base::signature_ok is not unsupported");
        }

        inline cardano::pool_hash issuer_hash() const
        {
            return blake2b<cardano::pool_hash>(issuer_vkey());
        }

        inline uint64_t offset() const
        {
            return _offset;
        }

        inline uint32_t size() const
        {
            if (_block_tuple.size > std::numeric_limits<uint32_t>::max())
                throw error("block size is too large: {}", _block_tuple.size);
            return _block_tuple.size;
        }

        inline const buffer raw_data() const
        {
            return _block_tuple.raw_span();
        }
    protected:
        const cbor_value &_block_tuple;
        const cbor_value &_block;
        uint64_t _era, _offset;
    };

    using tail_relative_stake_map = std::map<cardano::slot, double>;


    struct tx {
        struct vkey_wit_ok {
            size_t total = 0;
            size_t ok = 0;

            bool operator()() const noexcept
            {
                return total == ok;
            }
        };

        struct vkey_wit_cnt {
            size_t vkey = 0;
            size_t script = 0;
            size_t other = 0;
            size_t total() const
            {
                return vkey + script + other;
            };
        };

        static double slot_relative_stake(const tail_relative_stake_map &tail_relative_stake, const cardano::slot &slot)
        {
            if (tail_relative_stake.empty())
                return 0.0;
            auto it = tail_relative_stake.lower_bound(slot);
            if (it != tail_relative_stake.end())
                return it->second;
            return 1.0;
        }

        tx(const cbor_value &tx, const block_base &blk, const cbor_value *wit=nullptr, size_t idx=0)
            : _tx { tx }, _blk { blk }, _wit { wit }, _idx { idx }
        {
        }

        virtual ~tx() {}
        virtual vkey_wit_ok vkey_witness_ok() const =0;
        virtual vkey_wit_cnt witness_count() const =0;
        virtual void foreach_input(const std::function<void(const tx_input &)> &) const {}
        virtual void foreach_output(const std::function<void(const tx_output &)> &) const {}
        virtual void foreach_withdrawal(const std::function<void(const tx_withdrawal &)> &) const {}
        virtual void foreach_stake_reg(const std::function<void(const stake_ident &, size_t)> &) const {}
        virtual void foreach_stake_unreg(const std::function<void(const stake_ident &, size_t)> &) const {}
        virtual void foreach_stake_deleg(const std::function<void(const stake_deleg &)> &) const {}
        virtual void foreach_pool_reg(const std::function<void(const pool_reg &)> &) const {}
        virtual void foreach_param_update(const std::function<void(const param_update &)> &) const {}
        virtual void foreach_pool_unreg(const std::function<void(const pool_unreg &)> &) const {}
        virtual void foreach_instant_reward(const std::function<void(const instant_reward &)> &) const {}
        virtual void foreach_collateral(const std::function<void(const tx_input &)> &) const {}
        virtual void foreach_collateral_return(const std::function<void(const tx_output &)> &) const {}

        virtual const cardano::amount fee() const
        {
            return cardano::amount {};
        }

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

        inline json::object to_json(const tail_relative_stake_map &) const;

        inline buffer raw_data() const
        {
            return _tx.data_buf();
        }

        inline const block_base &block() const
        {
            return _blk;
        }

        inline size_t index() const
        {
            return _idx;
        }

        const cbor_value &raw_witness() const
        {
            if (!_wit)
                throw error("transaction wtiness has not beed supplied for this transaction!");
            return *_wit;
        }
    protected:
        const cbor_value &_tx;
        const block_base &_blk;
        const cbor_value *_wit = nullptr;
        const size_t _idx;
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
    struct formatter<daedalus_turbo::cardano::slot>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}/{}/{}", v.epoch(), v.epoch_slot(), static_cast<uint64_t>(v));
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::epoch>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", static_cast<uint64_t>(v));
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
    struct formatter<daedalus_turbo::stake_ident>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &id, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "stake_ident(id: {}, type: {})", id.hash.span(), id.script ? "script" : "key");
        }
    };

    template<>
    struct formatter<daedalus_turbo::pay_ident>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &id, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "pay_ident(id: {}, type: {})", id.hash.span(), id.type_name());
        }
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
            } else if (change == 0) {
                sign = ' ';
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
    struct formatter<daedalus_turbo::cardano::address>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::cardano::address &addr, FormatContext &ctx) const -> decltype(ctx.out()) {
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
                    return fmt::format_to(ctx.out(), "shelley-pointer/pay_{}:{}-stake_ptr:{}", (addr.type & 1) ? "script" : "key", addr.data.subspan(0, 28), addr.pointer());

                default:
                    throw daedalus_turbo::cardano_error("unsupported address type: {}!", addr.type);
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::tx_input>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{} #{}", v.tx_hash, v.txo_idx);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::tx_output>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = fmt::format_to(ctx.out(), "address: {}\n        amount: {}", v.address, v.amount);
            if (v.assets != nullptr) {
                out_it = fmt::format_to(out_it, "\n        assets (name, policy id, amount): [\n");
                for (const auto &[policy_id, p_assets]: *v.assets) {
                    for (const auto &[asset, coin]: p_assets.map()) {
                        std::string readable_name = fmt::format("{}", daedalus_turbo::buffer_readable { asset.buf() });
                        out_it = fmt::format_to(out_it, "            {} {} {}\n", readable_name, policy_id.buf(), daedalus_turbo::cardano::amount_pure { coin.uint() });
                    }
                }
                out_it = fmt::format_to(out_it, "        ]");
            }
            return out_it;
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::tx>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            const auto &slot = v.block().slot();
            auto out_it = fmt::format_to(ctx.out(), "tx hash: {} offset: {} size: {}\ntimestamp: {} UTC epoch: {} slot: {}\ninputs: [\n",
                v.hash(), v.offset(), v.size(), slot.timestamp(), slot.epoch(), slot);
            v.foreach_input([&](const auto &i) {
                out_it = fmt::format_to(out_it, "    {}\n", i);
            });     
            out_it = fmt::format_to(out_it, "]\noutputs: [\n");
            v.foreach_output([&](const auto &o) {
                fmt::format_to(out_it, "    {}\n", o);
            });
            return fmt::format_to(out_it, "]");
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::protocol_version>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}.{}", v.major, v.minor);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::nonce>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            if (v)
                return fmt::format_to(ctx.out(), "{}", *v);
            else
                return fmt::format_to(ctx.out(), "disabled");
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::reward_source>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            switch (v) {
                case daedalus_turbo::cardano::reward_source::reserves:
                    return fmt::format_to(ctx.out(), "reward_source::reserves");

                case daedalus_turbo::cardano::reward_source::treasury:
                    return fmt::format_to(ctx.out(), "reward_source::treasury");

                default:
                    throw daedalus_turbo::error("unsupported reward_source value: {}", static_cast<int>(v));
                    break;
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::stake_pointer>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "stake-pointer(slot: {} tx_idx: {} cert_idx: {})", v.slot, v.tx_idx, v.cert_idx);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::stake_ident_hybrid>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            switch (v.index()) {
                case 0:
                    return fmt::format_to(ctx.out(), "{}", std::get<daedalus_turbo::cardano::stake_ident>(v));

                case 1:
                    return fmt::format_to(ctx.out(), "{}", std::get<daedalus_turbo::cardano::stake_pointer>(v));

                default:
                    throw daedalus_turbo::error("unsupported stake_ident_hybrid index: {}", v.index());
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::param_update>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = fmt::format_to(ctx.out(), "param_update from {} for epoch {} [", v.pool_id, v.epoch);
            if (v.min_fee_a)
                out_it = fmt::format_to(out_it, "min_fee_a: {} ", *v.min_fee_a);
            if (v.min_fee_b)
                out_it = fmt::format_to(out_it, "min_fee_a: {} ", *v.min_fee_b);
            if (v.max_block_body_size)
                out_it = fmt::format_to(out_it, "max_block_body_size: {} ", *v.max_block_body_size);
            if (v.max_transaction_size)
                out_it = fmt::format_to(out_it, "max_transaction_size: {} ", *v.max_transaction_size);
            if (v.max_block_header_size)
                out_it = fmt::format_to(out_it, "max_block_header_size: {} ", *v.max_block_header_size);
            if (v.key_deposit)
                out_it = fmt::format_to(out_it, "key_deposit: {} ", *v.key_deposit);
            if (v.pool_deposit)
                out_it = fmt::format_to(out_it, "pool_deposit: {} ", *v.pool_deposit);
            if (v.max_epoch)
                out_it = fmt::format_to(out_it, "max_epoch: {} ", *v.max_epoch);
            if (v.n_opt)
                out_it = fmt::format_to(out_it, "n_opt: {} ", *v.n_opt);
            if (v.pool_pledge_influence)
                out_it = fmt::format_to(out_it, "pool_pledge_influence: {} ", *v.pool_pledge_influence);
            if (v.expansion_rate)
                out_it = fmt::format_to(out_it, "expansion_rate: {} ", *v.expansion_rate);
            if (v.treasury_growth_rate)
                out_it = fmt::format_to(out_it, "treasury_growth_rate: {} ", *v.treasury_growth_rate);
            if (v.decentralization)
                out_it = fmt::format_to(out_it, "decentralization: {} ", *v.decentralization);
            if (v.extra_entropy)
                out_it = fmt::format_to(out_it, "extra_entropy: {} ", *v.extra_entropy);
            if (v.protocol_ver)
                out_it = fmt::format_to(out_it, "protocol_ver: {}", *v.protocol_ver);
            if (v.min_utxo_value)
                out_it = fmt::format_to(out_it, "min_utxo_value: {} ", *v.min_utxo_value);
            return fmt::format_to(out_it, "]");
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::point>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "({}, {})", v.hash, v.slot);
        }
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

    inline json::object multi_balance::to_json(size_t offset, size_t max_items) const
    {
        json::object j {};
        size_t end_offset = offset + max_items;
        if (end_offset > size())
            end_offset = size();
        size_t i = 0;
        for (const auto &[asset_name, amount]: *this) {
            if (i >= offset)
                j.emplace(asset_name, amount);
            if (++i >= end_offset)
                break;
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

    inline json::object tx::to_json(const tail_relative_stake_map &tail_relative_stake) const
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
            { "fee", fmt::format("{}", fee()) },
            { "inputs", std::move(inputs) },
            { "outputs", std::move(outputs) },
            { "relativeStake", slot_relative_stake(tail_relative_stake, block().slot()) }
        };
    }
}

namespace std {
    template<>
    struct hash<daedalus_turbo::cardano::pool_hash> {
        size_t operator()(const auto &h) const noexcept
        {
            return daedalus_turbo::buffer { h.data(), 8 }.to<size_t>();
        }
    };

    template<>
    struct hash<daedalus_turbo::cardano::stake_pointer> {
        size_t operator()(const auto &stake_ptr) const noexcept
        {
            return (static_cast<uint64_t>(stake_ptr.slot) << 16) | ((stake_ptr.tx_idx & 0xFF) << 8) | (stake_ptr.cert_idx & 0xFF);
        }
    };

    template<>
    struct hash<daedalus_turbo::cardano::stake_ident> {
        size_t operator()(const auto &stake_id) const noexcept
        {
            return daedalus_turbo::buffer { stake_id.hash.data(), 8 }.to<size_t>();
        }
    };

    template<>
    struct hash<daedalus_turbo::cardano::stake_ident_hybrid> {
        size_t operator()(const auto &id) const noexcept
        {
            if (holds_alternative<daedalus_turbo::cardano::stake_ident>(id))
                return hash<daedalus_turbo::cardano::stake_ident> {} (get<daedalus_turbo::cardano::stake_ident>(id));
            else if (holds_alternative<daedalus_turbo::cardano::stake_pointer>(id))
                return hash<daedalus_turbo::cardano::stake_pointer> {} (get<daedalus_turbo::cardano::stake_pointer>(id));
            else
                return 0;
        }
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_COMMON_HPP