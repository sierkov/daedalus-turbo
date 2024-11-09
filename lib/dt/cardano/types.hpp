/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_TYPES_HPP
#define DAEDALUS_TURBO_CARDANO_TYPES_HPP

#include <chrono>
#include <ctime>
#include <dt/blake2b.hpp>
#include <dt/bech32.hpp>
#include <dt/cbor.hpp>
#include <dt/cbor/encoder.hpp>
#include <dt/container.hpp>
#include <dt/ed25519.hpp>
#include <dt/json.hpp>
#include <dt/kes.hpp>
#include <dt/narrow-cast.hpp>
#include <dt/partitioned-map.hpp>
#include <dt/static-map.hpp>
#include <dt/util.hpp>
#include <dt/vrf.hpp>
#include <dt/zpp.hpp>

namespace daedalus_turbo {
    using cardano_error = error;
    using cardano_hash_32 = blake2b_256_hash;
    using cardano_hash_28 = blake2b_224_hash;
    using cardano_vkey = ed25519::vkey;
    using cardano_vkey_span = std::span<const uint8_t, sizeof(cardano_vkey)>;
    using cardano_signature = ed25519::signature;
    using cardano_kes_signature = kes_signature<6>;
    using cardano_kes_signature_data = std::array<uint8_t, cardano_kes_signature::size()>;
    using cardano_vrf_vkey = vrf_vkey;
    using cardano_vrf_result = vrf_result;
    using cardano_vrf_result_span = std::span<const uint8_t, sizeof(cardano_vrf_result)>;
    using cardano_vrf_proof = vrf_proof;
    using cardano_vrf_proof_span = std::span<const uint8_t, sizeof(cardano_vrf_proof)>;

    namespace cardano {
        using vkey = cardano_vkey;
        using key_hash = cardano_hash_28;
        using script_hash = cardano_hash_28;
        using pool_hash = cardano_hash_28;
        using tx_hash = cardano_hash_32;
        using block_hash = cardano_hash_32;
        using vrf_nonce = cardano_hash_32;
        using vrf_vkey = cardano_vrf_vkey;
        using vrf_result = cardano_vrf_result;
        using vrf_proof = cardano_vrf_proof;
        using datum_hash = cardano_hash_32;

        struct shelley_delegate {
            pool_hash delegate {};
            vrf_vkey vrf {};

            bool operator==(const shelley_delegate &o) const
            {
                return delegate == o.delegate && vrf == o.vrf;
            }
        };
        using shelley_delegate_map = map<key_hash, shelley_delegate>;

        struct config;

        struct slot_range {
            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self._min, self._max);
            }

            explicit slot_range(const uint64_t slot): _min { slot}, _max { slot }
            {
            }

            explicit slot_range(const uint64_t min, const uint64_t max): _min { min }, _max { max }
            {
            }

            explicit slot_range(const slot_range &o): _min { o._min }, _max { o._max }
            {
            }

            bool operator<(const slot_range &o) const
            {
                return _min < o._min;
            }

            void update(const uint64_t slot)
            {
                if (slot < _min)
                    throw error("block supplied not in order slot {} observed after slot {}", slot, _min);
                if (slot < _max)
                    throw error("block supplied not in order slot {} observed after slot {}", slot, _max);
                _max = slot;
            }

            uint64_t min() const
            {
                return _min;
            }

            uint64_t max() const
            {
                return _max;
            }
        private:
            uint64_t _min;
            uint64_t _max;
        };

        struct slot {
            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self._slot);
            }

            static slot from_time(const std::chrono::time_point<std::chrono::system_clock> &tp, const cardano::config &cfg);
            static slot from_epoch(const uint64_t epoch, const uint64_t epoch_slot, const cardano::config &cfg);
            static slot from_chunk(const uint64_t chunk, const cardano::config &cfg);
            static slot from_epoch(const uint64_t epoch, const cardano::config &cfg);
            static slot from_future(const cardano::config &cfg);

            slot(const cardano::config &cfg): slot { 0, cfg }
            {
            }

            slot(const uint64_t slot_, const cardano::config &cfg): _slot { slot_ }, _cfg { cfg }
            {
            }

            slot(const slot &o): _slot { o._slot }, _cfg { o._cfg }
            {
            }

            void to_cbor(cbor::encoder &enc) const;

            slot &operator=(const slot &o)
            {
                _slot = o._slot;
                return *this;
            }

            slot &operator+=(const uint64_t num_slots)
            {
                _slot += num_slots;
                return *this;
            }

            operator uint64_t() const
            {
                return _slot;
            }

            json::value to_json() const
            {
                return json::object {
                    { "slot", _slot },
                    { "epoch", epoch() },
                    { "timestamp", timestamp() }
                };
            }

            const cardano::config &config() const
            {
                return _cfg;
            }

            uint64_t epoch() const;
            uint64_t epoch_slot() const;
            uint64_t chunk_id() const;
            uint64_t unixtime() const;
            std::string timestamp() const;
            std::string utc_month() const;
        private:
            uint64_t _slot = 0;
            const cardano::config &_cfg;
        };

        struct point {
            block_hash hash {};
            uint64_t slot = 0;
            uint64_t height = 0;
            uint64_t end_offset = 0;

            bool operator<(const point &o) const
            {
                return slot < o.slot;
            }

            bool operator==(const point &o) const
            {
                return hash == o.hash && slot == o.slot;
            }
        };
        using point_pair = std::pair<point, point>;
        using point_list = std::vector<point>;
        using optional_point = std::optional<point>;

        struct optional_slot: std::optional<uint64_t> {
            using std::optional<uint64_t>::optional;

            optional_slot(const optional_point &p)
                : optional_slot { p ? optional_slot { p->slot } : optional_slot {} }
            {
            }

            optional_slot(const point &p)
                : optional_slot { p.slot }
            {
            }

            bool operator<(const optional_slot &o) const
            {
                if (has_value() && o.has_value())
                    return value() < o.value();
                if (has_value() != o.has_value())
                    return has_value() < o.has_value();
                return false;
            }
        };

        inline bool operator<(const optional_point &a, const optional_point &b)
        {
            if (a.has_value() && b.has_value())
                return a.value() < b.value();
            if (a.has_value() != b.has_value())
                return a.has_value() < b.has_value();
            return false;
        }

        inline bool operator<(const optional_point &a, const optional_slot &b)
        {
            if (a.has_value() && b.has_value())
                return a.value().slot < b.value();
            if (a.has_value() != b.has_value())
                return a.has_value() < b.has_value();
            return false;
        }

        struct cert_loc_t {
            uint64_t slot = 0;
            uint32_t tx_idx = 0;
            uint32_t cert_idx = 0;

            static uint64_t max_slot()
            {
                return std::numeric_limits<decltype(slot)>::max();
            }

            static uint64_t max_tx_idx()
            {
                return std::numeric_limits<decltype(tx_idx)>::max();
            }

            static uint64_t max_cert_idx()
            {
                return std::numeric_limits<decltype(cert_idx)>::max();
            }

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.slot, self.tx_idx, self.cert_idx);
            }

            cert_loc_t() =default;
            cert_loc_t(const cert_loc_t &) =default;
            cert_loc_t(uint64_t, uint64_t, uint64_t);
            cert_loc_t &operator=(const cert_loc_t &) =default;

            bool operator<(const cert_loc_t &b) const
            {
                if (slot != b.slot)
                    return slot < b.slot;
                if (tx_idx != b.tx_idx)
                    return tx_idx < b.tx_idx;
                return cert_idx < b.cert_idx;
            }

            bool operator==(const cert_loc_t &b) const
            {
                return slot == b.slot && tx_idx == b.tx_idx && cert_idx == b.cert_idx;
            }
        };

        struct stake_pointer: cert_loc_t {
            using cert_loc_t::cert_loc_t;
            stake_pointer(const cbor::value &v);

            void to_cbor(cbor::encoder &) const;

            json::object to_json() const
            {
                return json::object {
                    { "slot", slot },
                    { "txIdx", tx_idx },
                    { "certIdx", cert_idx }
                };
            }
        };

        struct __attribute__((packed)) credential_t {
            key_hash hash {};
            bool script { false };

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.hash, self.script);
            }

            credential_t() =default;
            credential_t(const credential_t &) =default;
            credential_t(const key_hash &, bool);
            credential_t(const cbor::value &);
            credential_t(const std::string_view);
            credential_t &operator=(const credential_t &) =default;
            void to_cbor(cbor::encoder &) const;

            bool operator<(const auto &b) const
            {
                // compares the hash and the script in a single operation
                static_assert(sizeof(*this) == 29);
                return memcmp(this, &b, sizeof(*this)) < 0;
            }

            bool operator==(const credential_t &b) const
            {
                return memcmp(this, &b, sizeof(*this)) == 0 && script == b.script;
            }

            bool operator!=(const credential_t &b) const
            {
                return !(*this == b);
            }

            json::value to_json() const
            {
                return json::object {
                        { "hash", fmt::format("{}", hash.span()) },
                        { "script", script }
                };
            }
        };
        using stake_ident = credential_t;

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

            const char *type_name() const
            {
                switch (type) {
                    case ident_type::SHELLEY_KEY:
                        return "shelley-key";
                    case ident_type::SHELLEY_SCRIPT:
                        return "shelley-script";
                    case ident_type::BYRON_KEY:
                        return "byron-key";
                    default:
                        std::unreachable();
                }
            }

            json::value to_json() const
            {
                return json::object {
                    { "hash", fmt::format("{}", hash.span()) },
                    { "type", type_name() }
                };
            }
        };

        using stake_ident_hybrid = std::variant<stake_ident, stake_pointer>;

        extern uint8_vector byron_crc_protected(const buffer &encoded_addr);
        extern std::tuple<uint8_t, size_t> from_haskell_char(std::string_view sv);
        extern uint8_vector from_haskell(std::string_view sv);
        extern uint8_vector byron_avvm_addr(std::string_view redeem_vk);
        extern tx_hash byron_avvm_tx_hash(std::string_view redeem_vk_base64u);

        enum class script_type: uint8_t {
            native = 0,
            plutus_v1 = 1,
            plutus_v2 = 2,
            plutus_v3 = 3
        };

        struct script_info: uint8_vector {
            static script_info from_cbor(const buffer bytes);

            script_info(const script_type type, const buffer script):
                uint8_vector { _canonical(type, script) }, _hash { blake2b<script_hash>(*this) }
            {
            }

            [[nodiscard]] script_hash hash() const
            {
                return _hash;
            }

            [[nodiscard]] script_type type() const
            {
                return static_cast<script_type>(at(0));
            }

            [[nodiscard]] buffer script() const
            {
                return span().subbuf(1);
            }
        private:
            static uint8_vector _canonical(const script_type type, const buffer script)
            {
                uint8_vector bytes {};
                bytes.reserve(script.size() + 1);
                bytes << static_cast<uint8_t>(type) << script;
                return bytes;
            }

            script_hash _hash {};
        };
        using script_info_map = map<script_hash, script_info>;

        struct address {
            address(const address &o):
                _storage { o._storage ? std::make_unique<uint8_vector>(*o._storage) : nullptr },
                _bytes { _storage ? _storage->span() : o._bytes }
            {
            }

            address(address &&o):
                _storage { std::move(o._storage) },
                _bytes { _storage ? _storage->span() : o._bytes }
            {
            }

            explicit address(const buffer bytes): _bytes { bytes }
            {
                if (_bytes.size() < 2)
                    throw cardano_error("cardano address must have at least two bytes!");
                switch (type()) {
                    case 0b1110: // reward key
                    case 0b1111: // reward script
                    case 0b0110: // enterprise key
                    case 0b0111: // enterprise script
                        // there are cases when mainnet addresses contain extra data which is ignored by Cardano Node
                        if (_bytes.size() > 29) [[unlikely]]
                            _bytes = _bytes.subbuf(0, 29);
                        if (_bytes.size() < 29) [[unlikely]]
                            throw cardano_error("cardano reward addresses must have at least 29 bytes: {}!", _bytes);
                        break;

                    case 0b0000: // base address: keyhash28,keyhash28
                    case 0b0001: // base address: scripthash28,keyhash28
                    case 0b0010: // base address: keyhash28,scripthash28
                    case 0b0011: // base address: scripthash28,scripthash28
                        if (_bytes.size() > 57) [[unlikely]]
                            _bytes = _bytes.subbuf(0, 57);
                        if (_bytes.size() < 57) [[unlikely]]
                            throw cardano_error("shelley base address must have at least 57 bytes: {}!", _bytes);
                        break;

                    case 0b1000: // byron
                        // do nothing
                        break;

                    case 0b0100: // keyhash28, pointer
                    case 0b0101: // scripthash28, pointer
                    {
                        auto ptr_buf = _bytes.subbuf(29);
                        uint64_t slot = 0;
                        const auto sz1 = _read_var_uint_be(slot, ptr_buf);
                        uint64_t tx_idx = 0;
                        const auto sz2 = _read_var_uint_be(tx_idx, ptr_buf.subbuf(sz1));
                        uint64_t cert_idx = 0;
                        const auto sz3 = _read_var_uint_be(cert_idx, ptr_buf.subbuf(sz1 + sz2));
                        if (slot > cert_loc_t::max_slot() || tx_idx > cert_loc_t::max_tx_idx() || cert_idx > cert_loc_t::max_cert_idx()) {
                            slot = 0;
                            tx_idx = 0;
                            cert_idx = 0;
                        }
                        stake_pointer ptr { slot, tx_idx, cert_idx };
                        ptr_buf = ptr_buf.subbuf(0, sz1 + sz2 + sz3);
                        uint8_vector ptr_enc {};
                        ptr_enc << _encode_var_uint_be(ptr.slot) << _encode_var_uint_be(ptr.tx_idx) << _encode_var_uint_be(ptr.cert_idx);
                        if (ptr_enc == ptr_buf) [[likely]] {
                            _bytes = _bytes.subbuf(0, 29 + ptr_buf.size());
                        } else {
                            _storage = std::make_unique<uint8_vector>();
                            _storage->reserve(29 + ptr_enc.size());
                            *_storage = _bytes.subbuf(0, 29);
                            *_storage << ptr_enc;
                            _bytes = _storage->span();
                        }
                        break;
                    }

                    default:
                        throw cardano_error("unsupported address type: {}!", type());
                }
            }

            void to_cbor(cbor::encoder &enc) const;

            uint8_t network() const
            {
                if (!is_byron()) [[likely]]
                    return _bytes[0] & 0xF;
                throw error("network id is supported only for shelley+ addresses at the moment!");
            }

            uint8_t type() const
            {
                return (_bytes[0] >> 4) & 0xF;
            }

            buffer data() const
            {
                if (!is_byron()) [[likely]]
                    return _bytes.subbuf(1, _bytes.size() - 1);
                return _bytes;
            }

            buffer bytes() const
            {
                return _bytes;
            }

            const pay_ident pay_id() const
            {
                switch (type()) {
                    case 0b0110: // enterprise key
                    case 0b0111: // enterprise script
                    case 0b0000: // base address: keyhash28,keyhash28
                    case 0b0001: // base address: scripthash28,keyhash28
                    case 0b0010: // base address: keyhash28,scripthash28
                    case 0b0011: // base address: scripthash28,scripthash28
                    case 0b0100: // pointer key
                    case 0b0101: // pointer script
                        return pay_ident { data().subbuf(0, 28), (type() & 0x1) > 0 ? pay_ident::ident_type::SHELLEY_SCRIPT : pay_ident::ident_type::SHELLEY_KEY };

                    case 0b1000: { // byron
                        auto addr_hash = blake2b<cardano_hash_28>(data());
                        return pay_ident { addr_hash.span(), pay_ident::ident_type::BYRON_KEY };
                    }

                    default:
                        throw cardano_error("unsupported address for type: {}!", type());
                }
            }

            const stake_pointer pointer() const
            {

                if (data().size() < 28 + 3)
                    throw error("pointer data is too small - expect 31+ bytes but got: {}", data().size());
                const auto ptr = data().subspan(28, data().size() - 28);
                uint64_t slot, tx_idx, cert_idx;
                const auto sz1 = _read_var_uint_be(slot, ptr);
                const auto sz2 = _read_var_uint_be(tx_idx, ptr.subspan(sz1, ptr.size() - sz1));
                _read_var_uint_be(cert_idx, ptr.subspan(sz1 + sz2, ptr.size() - sz1 - sz2));
                return { slot, tx_idx, cert_idx };
            };

            const stake_ident stake_id() const
            {
                switch (type()) {
                    case 0b1110: // reward key
                    case 0b1111: // reward script
                        return stake_ident { data().subbuf(0, 28), (type() & 0x1) > 0 };

                    case 0b0000: // base address: keyhash28,keyhash28
                    case 0b0001: // base address: scripthash28,keyhash28
                    case 0b0010: // base address: keyhash28,scripthash28
                    case 0b0011: // base address: scripthash28,scripthash28
                        return stake_ident { data().subbuf(28, 28), (type() & 0x2) > 0 };

                    default:
                        throw cardano_error("address::stake_id unsupported for address type: {}!", type());
                }
            }

            const stake_ident_hybrid stake_id_hybrid() const
            {
                if (has_stake_id())
                    return stake_id();
                if (has_pointer())
                    return pointer();
                throw error("address {} has neither a stake_id not a pointer reference!", _bytes);
            }

            bool has_stake_id() const
            {
                switch (type()) {
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
                switch (type()) {
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
                switch (type()) {
                    case 0b0100: // pointer key
                    case 0b0101: // pointer script
                        return true;
                        break;

                    default:
                        return false;
                }
            }

            bool has_stake_id_hybrid() const
            {
                return has_stake_id() || has_pointer();
            }

            bool is_byron() const
            {
                return type() == 0b1000;
            }

            json::value to_json() const
            {
                const char *type_str = nullptr;
                switch (type()) {
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
                if (!type_str)
                    throw cardano_error("unsupported address type: {}!", type());
                json::object res {
                    { "type", type_str },
                    { "data", fmt::format("{}", _bytes) }
                };
                if (has_stake_id())
                    res.emplace("stakeId", stake_id().to_json());
                if (has_pay_id())
                    res.emplace("payId", pay_id().to_json());
                if (has_pointer())
                    res.emplace("stakePointer", pointer().to_json());
                return res;
            }

            bool operator==(const address &o) const
            {
                return _bytes == o._bytes;
            }
        private:
            std::unique_ptr<uint8_vector> _storage {};
            buffer _bytes;

            static size_t _read_var_uint_be(uint64_t &x, const buffer &buf)
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
                        ++num_read;
                    } else {
                        break;
                    }
                    x <<= 7;
                }
                return num_read;
            }

            static uint8_vector _encode_var_uint_be(uint64_t x)
            {
                uint8_vector out {};
                uint8_t next_byte = 0;
                for (;;) {
                    next_byte |= x & 0x7F;
                    out.emplace_back(next_byte);
                    x >>= 7;
                    if (!x)
                        break;
                    next_byte = 0x80;
                }
                std::ranges::reverse(out);
                return out;
            }
        };

        struct address_buf: uint8_vector {
            address_buf(const std::string_view &addr_sv): uint8_vector {}
            {
                static const std::string_view prefix { "0x" };
                if (addr_sv.substr(0, 2) == prefix) {
                    bytes_from_hex(*this, addr_sv.substr(2));
                } else {
                    const bech32 addr_bech32(addr_sv);
                    resize(addr_bech32.size());
                    memcpy(data(), addr_bech32.data(), addr_bech32.size());
                }
            }

            operator buffer() const
            {
                return buffer { *this };
            }
        };

        using asset_map = map<uint8_vector, uint64_t>;
        using policy_map = map<script_hash, asset_map>;

        inline std::string asset_name(const buffer &policy_id, const buffer &asset_name)
        {
            return fmt::format("{} {}", buffer_readable { asset_name }, policy_id.span());
        }

        struct multi_balance: map<std::string, uint64_t> {
            using map::map;

            inline json::object to_json(size_t offset=0, size_t max_items=1000) const;
        };

        using multi_balance_flat = vector<std::pair<std::string, uint64_t>>;

        struct amount {
            uint64_t coins { 0 };

            operator uint64_t() const
            {
                return coins;
            }

            inline json::value to_json() const;
        };

        struct amount_pure: amount {
            inline json::value to_json() const;
        };

        struct tx_out_idx {
            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self._out_idx);
            }

            tx_out_idx(): _out_idx { 0 } {}

            tx_out_idx(size_t out_idx)
            {
                if (out_idx >= (1U << 16)) [[unlikely]]
                    throw error("tx out idx is too big: {}!", out_idx);
                _out_idx = out_idx;
            }

            tx_out_idx &operator=(size_t out_idx)
            {
                if (out_idx >= (1U << 16)) [[unlikely]]
                    throw error("tx out idx is too big: {}!", out_idx);
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
            const buffer tx_hash;
            const tx_out_idx txo_idx;
            const tx_out_idx idx;

            json::object to_json() const
            {
                return json::object {
                    { "hash", fmt::format("{}", tx_hash) },
                    { "outIdx", static_cast<size_t>(txo_idx) }
                };
            }
        };

        struct tx_out_ref {
            tx_hash hash {};
            tx_out_idx idx {};

            static tx_out_ref from_input(const tx_input &txin)
            {
                return { txin.tx_hash, txin.txo_idx };;
            }

            std::strong_ordering operator<=>(const auto &o) const
            {
                const int cmp = memcmp(hash.data(), o.hash.data(), hash.size());
                if (cmp > 0)
                    return std::strong_ordering::greater;
                if (cmp < 0)
                    return std::strong_ordering::less;
                return idx <=> o.idx;
            }
            bool operator==(const tx_out_ref &) const =default;
            bool operator<(const tx_out_ref &) const =default;
        };
        using tx_out_ref_list = vector<tx_out_ref>;

        struct tx_mint {
            const buffer policy_id;
            const cbor::map *assets = nullptr;
        };

        struct tx_output {
            const cardano::address address;
            const cardano::amount amount;
            const tx_out_idx idx;
            const cbor_value &raw_data;
            const cbor_value *assets = nullptr;
            const cbor_value *datum = nullptr;
            const cbor_value *script_ref = nullptr;

            static tx_output from_cbor(uint64_t era, uint64_t idx, const cbor::value &out_raw);
            inline json::object to_json() const;
        };

        struct tx_out_data {
            using datum_option_type = std::variant<datum_hash, uint8_vector>;

            uint64_t coin = 0;
            uint8_vector address {};
            std::optional<uint8_vector> assets {};
            std::optional<datum_option_type> datum {};
            std::optional<uint8_vector> script_ref {};

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.coin, self.address, self.assets, self.datum, self.script_ref);
            }

            static tx_out_data from_output(const tx_output &txo);
            void to_cbor(cbor::encoder &) const;

            bool empty() const noexcept
            {
                return !(coin || assets || datum ||script_ref);
            }

            bool operator==(const auto &o) const
            {
                return coin == o.coin && address == o.address && assets == o.assets && datum == o.datum && script_ref == o.script_ref;
            }
        };
        using tx_out_data_list = vector<tx_out_data>;
        using txo_map = partitioned_map<tx_out_ref, tx_out_data>;

        struct protocol_version {
            uint64_t major = 1;
            uint64_t minor = 0;

            bool operator==(const auto &b) const
            {
                return major == b.major && minor == b.minor;
            }

            bool operator<(const auto &o) const
            {
                if (major != o.major)
                    return major < o.major;
                return minor < o.minor;
            }

            bool aggregated_rewards() const
            {
                return major > 2;
            }

            bool forgo_reward_prefilter() const
            {
                return major > 6;
            }

            bool keep_pointers() const
            {
                return major < 9;
            }

            uint64_t era() const {
                switch (major) {
                    case 0: return 0;
                    case 1: return 1;
                    case 2: return 2;
                    case 3: return 3;
                    case 4: return 4;
                    case 5:
                    case 6:
                        return 5;
                    case 7:
                    case 8:
                        return 6;
                    case 9: return 7;
                    default: throw error("unsupported protocol version: {}", *this);
                }
            }
        };

        using nonce = std::optional<vrf_nonce>;

        struct plutus_cost_model: static_map<std::string, int64_t> {
            using static_map::static_map;

            using storage_type = static_map;
            using diff_type = map<std::string, std::pair<std::optional<int64_t>, std::optional<int64_t>>>;

            static plutus_cost_model from_cbor(const plutus_cost_model &orig, const cbor_array &data);
            static plutus_cost_model from_json(const plutus_cost_model &orig, const json::value &data);

            void update(const plutus_cost_model &src);
            diff_type diff(const plutus_cost_model &o) const;
        };

        struct ex_units {
            uint64_t mem = 0;
            uint64_t steps = 0;

            static ex_units from_cbor(const cbor::value &v);

            bool operator==(const ex_units &o) const
            {
                return mem == o.mem && steps == o.steps;
            }

            bool operator>(const ex_units &o) const
            {
                return mem > o.mem || steps > o.steps;
            }
        };

        struct ex_unit_prices {
            rational_u64 mem {};
            rational_u64 steps {};

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.mem, self.steps);
            }

            bool operator==(const ex_unit_prices &o) const
            {
                return mem == o.mem && steps == o.steps;
            }
        };

        struct plutus_cost_models {
            std::optional<plutus_cost_model> v1 {};
            std::optional<plutus_cost_model> v2 {};
            std::optional<plutus_cost_model> v3 {};

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.v1, self.v2, self.v3);
            }

            void to_cbor(cbor::encoder &) const;

            bool operator==(const plutus_cost_models &o) const noexcept
            {
                return v1 == o.v1 && v2 == o.v2 && v3 == o.v3;
            }
        };

        struct pool_voting_thresholds_t {
            rational_u64 comittee_normal { 0.51 };
            rational_u64 comittee_no_confidence { 0.51 };
            rational_u64 hard_fork_initiation { 0.51 };
            rational_u64 motion_no_confidence { 0.51 };
            rational_u64 pp_secirity_group { 0.51 };

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.comittee_normal, self.comittee_no_confidence, self.hard_fork_initiation,
                    self.motion_no_confidence, self.pp_secirity_group);
            }

            pool_voting_thresholds_t() =default;
            pool_voting_thresholds_t(const pool_voting_thresholds_t &) =default;
            pool_voting_thresholds_t(const json::value &);
            void to_cbor(cbor::encoder &) const;
        };

        struct drep_voting_thresholds_t {
            rational_u64 motion_no_confidence { 0.67 };
            rational_u64 committee_normal { 0.67 };
            rational_u64 committee_no_confidence { 0.6 };
            rational_u64 update_to_constitution { 0.75 };
            rational_u64 hard_fork_initiation { 0.6 };
            rational_u64 pp_network_group { 0.67 };
            rational_u64 pp_economic_group { 0.67 };
            rational_u64 pp_technical_group { 0.67 };
            rational_u64 pp_gov_group { 0.75 };
            rational_u64 treasury_withdrawal { 0.67 };

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.motion_no_confidence, self.committee_normal, self.committee_no_confidence,
                    self.update_to_constitution, self.hard_fork_initiation,
                    self.pp_network_group, self.pp_economic_group, self.pp_technical_group,
                    self.pp_gov_group, self.treasury_withdrawal
                );
            }

            drep_voting_thresholds_t() =default;
            drep_voting_thresholds_t(const drep_voting_thresholds_t &) =default;
            drep_voting_thresholds_t(const json::value &);
            void to_cbor(cbor::encoder &) const;
        };

        struct protocol_params {
            uint64_t min_fee_a = 0;
            uint64_t min_fee_b = 0;
            uint64_t max_block_body_size {};
            uint64_t max_transaction_size {};
            uint64_t max_block_header_size {};
            uint64_t key_deposit = 2'000'000;
            uint64_t pool_deposit = 500'000'000;
            uint64_t e_max = 0;
            uint64_t n_opt = 150;
            rational_u64 pool_pledge_influence { 3, 10 };
            rational_u64 expansion_rate { 3, 1000 };
            rational_u64 treasury_growth_rate { 1, 5 };
            rational_u64 decentralization { 1, 1 };
            rational_u64 decentralizationThreshold { 4, 5 };
            nonce extra_entropy {};
            protocol_version protocol_ver {};
            uint64_t min_utxo_value = 0;
            uint64_t min_pool_cost = 0;
            uint64_t lovelace_per_utxo_byte = 0;
	        cardano::ex_unit_prices ex_unit_prices {};
            ex_units max_tx_ex_units {};
            ex_units max_block_ex_units {};
            uint64_t max_value_size = 0;
            uint64_t max_collateral_pct = 0;
            uint64_t max_collateral_inputs = 0;
	        cardano::plutus_cost_models plutus_cost_models {};
            pool_voting_thresholds_t pool_voting_thresholds {};
            drep_voting_thresholds_t drep_voting_thresholds {};
            uint64_t comittee_min_size = 7;
            uint64_t committee_max_term_length = 146;
            uint64_t gov_action_lifetime = 6;
            uint64_t gov_action_deposit = 100'000'000'000;
            uint64_t drep_deposit = 500'000'000;
            uint64_t drep_activity = 20;
            rational_u64 min_fee_ref_script_cost_per_byte { 15, 1 };

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(
                    self.min_fee_a, self.min_fee_b,
                    self.max_block_body_size, self.max_transaction_size, self.max_block_header_size,
                    self.key_deposit, self.pool_deposit, self.e_max,
                    self.n_opt, self.pool_pledge_influence,
                    self.expansion_rate, self.treasury_growth_rate, self.decentralization,
                    self.decentralizationThreshold, self.extra_entropy, self.protocol_ver,
                    self.min_utxo_value,
                    self.min_pool_cost, self.lovelace_per_utxo_byte,
                    self.ex_unit_prices, self.max_tx_ex_units, self.max_block_ex_units,
                    self.max_value_size,
                    self.max_collateral_pct, self.max_collateral_inputs,
                    self.plutus_cost_models
                );
            }

            bool operator==(const auto &o) const
            {
                return min_fee_a == o.min_fee_a && min_fee_b == o.min_fee_b
                    && max_block_body_size == o.max_block_body_size && max_transaction_size == o.max_transaction_size && max_block_header_size == o.max_block_header_size
                    && key_deposit == o.key_deposit && pool_deposit == o.pool_deposit && e_max == o.e_max
                    && n_opt == o.n_opt && pool_pledge_influence == o.pool_pledge_influence
                    && expansion_rate == o.expansion_rate && treasury_growth_rate == o.treasury_growth_rate && decentralization == o.decentralization
                    && decentralizationThreshold == o.decentralizationThreshold && extra_entropy == o.extra_entropy && protocol_ver == o.protocol_ver
                    && min_utxo_value == o.min_utxo_value
                    && min_pool_cost == o.min_pool_cost
                    && lovelace_per_utxo_byte == o.lovelace_per_utxo_byte
                    && ex_unit_prices == o.ex_unit_prices
                    && max_tx_ex_units == o.max_tx_ex_units
                    && max_block_ex_units == o.max_block_ex_units
                    && max_value_size == o.max_value_size
                    && max_collateral_pct == o.max_collateral_pct
                    && max_collateral_inputs == o.max_collateral_inputs
                    && plutus_cost_models == o.plutus_cost_models;
            }

            void clear()
            {
                *this = {};
            }
        };

        struct param_update {
            block_hash hash {};
            std::optional<uint64_t> min_fee_a {};
            std::optional<uint64_t> min_fee_b {};
            std::optional<uint64_t> max_block_body_size {};
            std::optional<uint64_t> max_transaction_size {};
            std::optional<uint64_t> max_block_header_size {};
            std::optional<uint64_t> key_deposit {};
            std::optional<uint64_t> pool_deposit {};
            std::optional<uint64_t> e_max {};
            std::optional<uint64_t> n_opt {};
            std::optional<rational_u64> pool_pledge_influence {};
            std::optional<rational_u64> expansion_rate {};
            std::optional<rational_u64> treasury_growth_rate {};
            std::optional<rational_u64> decentralization {};
            std::optional<nonce> extra_entropy {};
            std::optional<protocol_version> protocol_ver {};
            std::optional<uint64_t> min_utxo_value {};
            std::optional<uint64_t> min_pool_cost {};
            std::optional<uint64_t> lovelace_per_utxo_byte {};
            std::optional<cardano::ex_unit_prices> ex_unit_prices {};
            std::optional<ex_units> max_tx_ex_units {};
            std::optional<ex_units> max_block_ex_units {};
            std::optional<uint64_t> max_value_size {};
            std::optional<uint64_t> max_collateral_pct {};
            std::optional<uint64_t> max_collateral_inputs {};
            std::optional<cardano::plutus_cost_models> plutus_cost_models {};

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(
                    self.hash,
                    self.min_fee_a, self.min_fee_b,
                    self.max_block_body_size, self.max_transaction_size, self.max_block_header_size,
                    self.key_deposit, self.pool_deposit, self.e_max,
                    self.n_opt, self.pool_pledge_influence,
                    self.expansion_rate, self.treasury_growth_rate, self.decentralization,
                    self.extra_entropy, self.protocol_ver,
                    self.min_utxo_value,
                    self.min_pool_cost, self.lovelace_per_utxo_byte,
                    self.ex_unit_prices, self.max_tx_ex_units, self.max_block_ex_units,
                    self.max_value_size,
                    self.max_collateral_pct, self.max_collateral_inputs,
                    self.plutus_cost_models
                );
            }

            void hash_from_cbor(const cbor_value &val)
            {
                blake2b(hash, val.raw_span());
            }

            bool operator==(const auto &o) const
            {
                return hash == o.hash;
            }

            void rehash();
        };

        struct param_update_proposal {
            pool_hash pool_id {};
            std::optional<uint64_t> epoch {};
            param_update update {};

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.pool_id, self.epoch, self.update);
            }
        };

        struct param_update_vote {
            pool_hash pool_id {};
            block_hash proposal_id {};
            bool vote = false;
        };

        struct drep_t {
            enum type_t {
                abstain, no_confidence, credential
            };

            type_t typ {};
            std::optional<credential_t> cred {};

            static constexpr auto serialize(auto &archive, auto &self)
            {
                return archive(self.typ, self.cred);
            }

            drep_t() =default;
            drep_t(const type_t &);
            drep_t(const credential_t &);
            drep_t(const cbor::value &v);
            void to_cbor(cbor::encoder &) const;

            bool operator<(const drep_t &o) const noexcept
            {
                if (typ != o.typ)
                    return typ < o.typ;
                if (cred && o.cred) {
                    if (cred->script != o.cred->script)
                        return cred->script > o.cred->script; // inverse the order for scripts to come first
                    return cred->hash < o.cred->hash;
                }
                return cred.has_value() < o.cred.has_value();
            }
        };
    }
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::cardano::protocol_version>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}.{}", v.major, v.minor);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::slot>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}/{}/{}", v.epoch(), v.epoch_slot(), static_cast<uint64_t>(v));
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::tx_out_idx>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto a, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", (size_t)a);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::stake_ident>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &id, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "stake-{} #{}", id.script ? "script" : "key", id.hash);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::pay_ident>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &id, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "pay-{} #{}", id.type_name(), id.hash);
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
    struct formatter<daedalus_turbo::cardano::amount>: formatter<daedalus_turbo::cardano::amount_pure> {
        template<typename FormatContext>
        auto format(const auto &a, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{} ADA", daedalus_turbo::cardano::amount_pure { a.coins });
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::multi_balance>: formatter<daedalus_turbo::cardano::amount_pure> {
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
    struct formatter<daedalus_turbo::cardano::point>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "({}, {}, {}, {})", v.hash, v.slot, v.height, v.end_offset);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::tx_out_ref>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}#{}", v.hash, v.idx);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::tx_out_data::datum_option_type>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            switch (v.index()) {
                case 0: return fmt::format_to(ctx.out(), "{}", std::get<daedalus_turbo::cardano::datum_hash>(v));
                case 1: return fmt::format_to(ctx.out(), "{}", std::get<daedalus_turbo::uint8_vector>(v));
                default: throw daedalus_turbo::error("unsupported variant index: {}", v.index());
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::tx_out_data>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            if (!v.address.empty()) [[likely]] {
                return fmt::format_to(ctx.out(), "address: #{} ({}) coin: {} assets: {} datum: {} script_ref: {}",
                    v.address, daedalus_turbo::cardano::address { v.address }, daedalus_turbo::cardano::amount { v.coin }, v.assets, v.datum, v.script_ref);
            }
            return fmt::format_to(ctx.out(), "tx_out_data::empty");
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::stake_pointer>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "stake-pointer(slot: {} tx_idx: {} cert_idx: {})", v.slot, v.tx_idx, v.cert_idx);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::stake_ident_hybrid>: formatter<uint64_t> {
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
    struct formatter<daedalus_turbo::cardano::shelley_delegate>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "delegate: {} vrf: {}", v.delegate, v.vrf);
        }
    };

    enum class script_type: uint8_t {
        native = 0,
        plutus_v1 = 1,
        plutus_v2 = 2,
        plutus_v3 = 3
    };

    template<>
    struct formatter<daedalus_turbo::cardano::script_type>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::cardano::script_type &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using daedalus_turbo::cardano::script_type;
            switch (v) {
                case script_type::native: return fmt::format_to(ctx.out(), "native");
                case script_type::plutus_v1: return fmt::format_to(ctx.out(), "plutus_v1");
                case script_type::plutus_v2: return fmt::format_to(ctx.out(), "plutus_v2");
                case script_type::plutus_v3: return fmt::format_to(ctx.out(), "plutus_v3");
                default: throw daedalus_turbo::cardano_error("unsupported address type: {}!", static_cast<int>(v));
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::address>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::cardano::address &addr, FormatContext &ctx) const -> decltype(ctx.out()) {
            using daedalus_turbo::buffer;
            switch (addr.type()) {
                case 0b1000:
                    return fmt::format_to(ctx.out(), "byron/{}", addr.bytes());

                case 0b1110:
                case 0b1111:
                    return fmt::format_to(ctx.out(), "shelley-reward{}/{}-{}", addr.network() == 1 ? "" : fmt::format("{}", addr.network()),
                                (addr.type() & 1) ? "script" : "key", addr.data());

                case 0b0000: // base address: keyhash28,keyhash28
                case 0b0001: // base address: scripthash28,keyhash28
                case 0b0010: // base address: keyhash28,scripthash28
                case 0b0011: // base address: scripthash28,scripthash28
                    return fmt::format_to(ctx.out(), "shelley-base{}/pay_{}:{}-stake_{}:{}", addr.network() == 1 ? "" : fmt::format("{}", addr.network()),
                        (addr.type() & 1) > 0 ? "script" : "key", buffer { addr.data().data(), 28 },
                        (addr.type() & 2) > 0 ? "script" : "key", buffer { addr.data().data() + 28, 28 });

                case 0b0110:
                case 0b0111:
                    return fmt::format_to(ctx.out(), "shelley-enterprise{}/{}-{}", addr.network() == 1 ? "" : fmt::format("{}", addr.network()),
                        (addr.type() & 1) ? "script" : "key", addr.data());

                case 0b0100:
                case 0b0101:
                    return fmt::format_to(ctx.out(), "shelley-pointer{}/pay_{}:{}-stake_ptr:{}", addr.network() == 1 ? "" : fmt::format("{}", addr.network()),
                                (addr.type() & 1) ? "script" : "key", addr.data().subspan(0, 28), addr.pointer());

                default:
                    throw daedalus_turbo::cardano_error("unsupported address type: {}!", addr.type());
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::protocol_params>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "min_fee_a: {} "
                "min_fee_b: {} max_block_body_size: {} max_transaction_size: {} max_block_header_size: {} key_deposit: {} "
                "pool_deposit: {} e_max: {} n_opt: {} pool_pledge_influence: {} expansion_rate: {} "
                "treasury_growth_rate: {} decentralization: {} decentralizationThreshold: {} extra_entropy: {} protocol_ver: {} "
                "min_utxo_value: {} "
                "min_pool_cost: {} lovelace_per_utxo_byte: {} "
                "ex_unit_prices: {} max_tx_ex_units: {} max_block_ex_units: {} "
                "max_value_size: {} "
                "max_collateral_pct: {} max_collateral_inputs: {} "
                "plutus_cost_models: {}",
                v.min_fee_a,
                v.min_fee_b, v.max_block_body_size, v.max_transaction_size, v.max_block_header_size, v.key_deposit,
                v.pool_deposit, v.e_max, v.n_opt, v.pool_pledge_influence, v.expansion_rate,
                v.treasury_growth_rate, v.decentralization, v.decentralizationThreshold, v.extra_entropy, v.protocol_ver,
                v.min_utxo_value,
                v.min_pool_cost, v.lovelace_per_utxo_byte,
                v.ex_unit_prices, v.max_tx_ex_units, v.max_block_ex_units,
                v.max_value_size,
                v.max_collateral_pct, v.max_collateral_inputs,
                v.plutus_cost_models
            );
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::ex_unit_prices>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "mem: {} steps: {}", v.mem, v.steps);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::ex_units>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "mem: {} steps: {}", v.mem, v.steps);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::plutus_cost_models>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "v1: ({}) v2: ({}) v3: ({})", v.v1, v.v2, v.v3);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::param_update>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = fmt::format_to(ctx.out(), "param_update [ hash: {} ", v.hash);
            out_it = _format_to(out_it, v.min_fee_a, "min_fee_a");
            out_it = _format_to(out_it, v.min_fee_b, "min_fee_b");
            out_it = _format_to(out_it, v.max_block_body_size, "max_block_body_size");
            out_it = _format_to(out_it, v.max_transaction_size, "max_transaction_size");
            out_it = _format_to(out_it, v.max_block_header_size, "max_block_header_size");
            out_it = _format_to(out_it, v.key_deposit, "key_deposit");
            out_it = _format_to(out_it, v.pool_deposit, "pool_deposit");
            out_it = _format_to(out_it, v.e_max, "e_max");
            out_it = _format_to(out_it, v.n_opt, "n_opt");
            out_it = _format_to(out_it, v.pool_pledge_influence, "pool_pledge_influence");
            out_it = _format_to(out_it, v.expansion_rate, "expansion_rate");
            out_it = _format_to(out_it, v.treasury_growth_rate, "treasury_growth_rate");
            out_it = _format_to(out_it, v.decentralization, "decentralization");
            out_it = _format_to(out_it, v.extra_entropy, "extra_entropy");
            out_it = _format_to(out_it, v.protocol_ver, "protocol_ver");
            out_it = _format_to(out_it, v.min_utxo_value, "min_utxo_value");
            out_it = _format_to(out_it, v.min_pool_cost, "min_pool_cost");
            out_it = _format_to(out_it, v.lovelace_per_utxo_byte, "lovelace_per_utxo_byte");
            out_it = _format_to(out_it, v.ex_unit_prices, "ex_unit_prices");
            out_it = _format_to(out_it, v.max_tx_ex_units, "max_tx_ex_units");
            out_it = _format_to(out_it, v.max_block_ex_units, "max_block_ex_units");
            out_it = _format_to(out_it, v.max_value_size, "max_value_size");
            out_it = _format_to(out_it, v.max_collateral_pct, "max_collateral_pct");
            out_it = _format_to(out_it, v.max_collateral_inputs, "max_collateral_inputs");
            out_it = _format_to(out_it, v.plutus_cost_models, "plutus_cost_models");
            return fmt::format_to(out_it, "]");
        }
    private:
        template<typename Y>
        static auto _format_to(auto out_it, const std::optional<Y> &v, const std::string_view name)
        {
            if (v)
                out_it = fmt::format_to(out_it, "{}: {} ", name, *v);
            return out_it;
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::param_update_proposal>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "pool_id: {} epoch: {} params: {}", v.pool_id, v.epoch, v.update);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::param_update_vote>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "pool_id: {} proposal_id: {} vote: {}", v.pool_id, v.proposal_id, v.vote);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::slot_range>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "[{}, {}]", v.min(), v.max());
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::drep_t>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            switch (v.typ) {
                case daedalus_turbo::cardano::drep_t::credential: return fmt::format_to(ctx.out(), "{}", v.cred.value());
                case daedalus_turbo::cardano::drep_t::abstain: return fmt::format_to(ctx.out(), "abstain");
                case daedalus_turbo::cardano::drep_t::no_confidence: return fmt::format_to(ctx.out(), "no-confidence");
                default: throw daedalus_turbo::error("unsupported drep.type: {}", static_cast<int>(v.typ));
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::plutus_cost_model>: formatter<daedalus_turbo::cardano::plutus_cost_model::storage_type> {
    };

    template<>
    struct formatter<daedalus_turbo::cardano::optional_slot>: formatter<std::optional<uint64_t>> {
    };
}

namespace std {
    template<>
    struct hash<daedalus_turbo::cardano::tx_out_ref> {
        size_t operator()(const auto &o) const noexcept
        {
            return *reinterpret_cast<const size_t *>(o.hash.data());
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
            if (holds_alternative<daedalus_turbo::cardano::stake_pointer>(id))
                return hash<daedalus_turbo::cardano::stake_pointer> {} (get<daedalus_turbo::cardano::stake_pointer>(id));
            return 0;
        }
    };

    template<>
    struct hash<daedalus_turbo::cardano::param_update> {
        size_t operator()(const auto &v) const noexcept
        {
            return daedalus_turbo::buffer { v.hash.data(), 8 }.to<size_t>();
        }
    };
}

namespace daedalus_turbo::cardano {
    inline json::value amount::to_json() const
    {
        return json::string { fmt::format("{}", *this) };
    }

    inline json::object multi_balance::to_json(const size_t offset, const size_t max_items) const
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
}

#endif // !DAEDALUS_TURBO_CARDANO_TYPES_HPP
