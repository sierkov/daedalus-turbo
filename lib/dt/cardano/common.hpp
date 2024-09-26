/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_COMMON_HPP
#define DAEDALUS_TURBO_CARDANO_COMMON_HPP

#include <functional>
#include <map>
#include <optional>
#include <ranges>
#include <set>
#include <span>
#include <variant>
#include <dt/array.hpp>
#include <dt/cardano/config.hpp>
#include <dt/cardano/types.hpp>
#include <dt/cbor.hpp>
#include <dt/file.hpp>
#include <dt/format.hpp>
#include <dt/rational.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::cardano {
    static constexpr uint64_t density_default_window = 9600; // slots

    struct amount_asset: amount {
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

    struct tx_withdrawal {
        const address address;
        const amount amount;
        const tx_out_idx idx;
    };

    struct stake_deleg {
        stake_ident stake_id {};
        cardano_hash_28 pool_id {};
        size_t cert_idx = 0;
    };

    using ipv4_addr = array<uint8_t, 4>;
    using ipv6_addr = array<uint8_t, 16>;

    struct relay_addr {
        std::optional<ipv6_addr> ipv6 {};
        std::optional<ipv4_addr> ipv4 {};
        std::optional<uint16_t> port {};

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.ipv6, self.ipv4, self.port);
        }

        bool operator==(const relay_addr &o) const
        {
            return ipv4 == o.ipv4 && ipv6 == o.ipv6 && port == o.port;
        }
    };

    struct relay_host {
        std::string host {};
        std::optional<uint16_t> port {};

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.host, self.port);
        }

        bool operator==(const relay_host &o) const
        {
            return host == o.host && port == o.port;
        }
    };

    struct relay_dns {
        std::string name {};

        bool operator==(const relay_dns &o) const
        {
            return name == o.name;
        }
    };
    using relay_info = std::variant<relay_addr, relay_host, relay_dns>;
    using relay_list = vector<relay_info>;

    struct pool_metadata {
        std::string url {};
        cardano_hash_32 hash {};

        bool operator==(const pool_metadata &o) const
        {
            return url == o.url && hash == o.hash;
        }
    };

    struct pool_reg {
        cardano_hash_28 pool_id {};
        vrf_vkey vrf_vkey {};
        uint64_t pledge = 0;
        uint64_t cost = 0;
        rational_u64 margin {};
        stake_ident reward_id {};
        set<stake_ident> owners {};
        relay_list relays {};
        std::optional<pool_metadata> metadata {};
        // needed to produce binary-compatible state snapshots as Cardano Node accepts
        // non-mainnet reward addresses in the mainnet ledger
        uint8_t reward_network = 1;

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.pool_id, self.vrf_vkey, self.pledge, self.cost, self.margin, self.reward_id, self.owners, self.relays, self.metadata, self.reward_network);
        }
    };

    struct pool_unreg {
        cardano_hash_28 pool_id {};
        cardano::epoch epoch {};
    };

    enum class reward_source { reserves, treasury };

    struct instant_reward {
        reward_source source {};
        std::map<stake_ident, amount> rewards {};
    };

    struct kes_signature {
        const buffer vkey;
        const buffer vkey_sig;
        const buffer vkey_cold; // issuer_vkey
        const buffer sig;
        const buffer header_body;
        uint64_t counter = 0;
        uint64_t period = 0;
        uint64_t slot = 0;

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
        const buffer vkey;
        const buffer leader_result;
        const buffer leader_proof;
        const buffer nonce_result;
        const buffer nonce_proof;
    };

    struct tx;

    struct block_base {
        block_base(const cbor_value &block_tuple, const uint64_t offset, const uint64_t era, const cbor_value &block, const config &cfg)
            : _block_tuple { block_tuple }, _block { block }, _era { era }, _offset { offset }, _cfg { cfg }
        {
        }

        virtual ~block_base() {}
        virtual uint64_t height() const =0;
        virtual block_hash hash() const =0;
        virtual buffer prev_hash() const =0;
        virtual uint64_t slot() const =0;
        virtual void foreach_tx(const std::function<void(const tx &)> &) const;

        virtual void foreach_update_proposal(const std::function<void(const param_update_proposal &)> &) const
        {
        }

        virtual void foreach_update_vote(const std::function<void(const param_update_vote &)> &) const
        {
        }

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

        buffer header_raw_data() const
        {
            return _block.at(0).raw_span();
        }

        cardano::slot slot_object() const
        {
            return { slot(), config() };
        }

        uint64_t era() const
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

        pool_hash issuer_hash() const
        {
            return blake2b<pool_hash>(issuer_vkey());
        }

        uint64_t offset() const
        {
            return _offset;
        }

        uint64_t end_offset() const
        {
            return _offset + _block_tuple.size;
        }

        uint32_t size() const
        {
            if (_block_tuple.size > std::numeric_limits<uint32_t>::max())
                throw error("block size is too large: {}", _block_tuple.size);
            return _block_tuple.size;
        }

        const buffer raw_data() const
        {
            return _block_tuple.raw_span();
        }

        const config &config() const
        {
            return _cfg;
        }
    protected:
        const cbor_value &_block_tuple;
        const cbor_value &_block;
        uint64_t _era, _offset;
        const cardano::config &_cfg;
        mutable std::optional<block_hash> _cached_hash {};
    };

    using tail_relative_stake_map = map<point, double>;

    struct genesis_deleg {
        buffer hash;
        buffer pool_id;
        buffer vrf_vkey;
    };

    using stake_reg_observer = std::function<void(const stake_ident &, size_t, std::optional<uint64_t>)>;
    using stake_unreg_observer = std::function<void(const stake_ident &, size_t, std::optional<uint64_t>)>;

    struct tx {
        struct wit_ok {
            size_t vkey_total = 0;
            size_t vkey_ok = 0;
            size_t script_total = 0;
            size_t script_ok = 0;

            operator bool() const
            {
                return vkey_total == vkey_ok && script_total == script_ok;
            }
        };

        static double slot_relative_stake(const tail_relative_stake_map &tail_relative_stake, const uint64_t slot)
        {
            if (tail_relative_stake.empty())
                return 0.0;
            if (const auto it = tail_relative_stake.lower_bound(point { .slot=slot }); it != tail_relative_stake.end())
                return it->second;
            return 1.0;
        }

        tx(const cbor_value &tx, const block_base &blk, const cbor::value *wit=nullptr, const size_t idx=0)
            : _tx { tx }, _blk { blk }, _wit { wit }, _idx { idx }
        {
        }

        virtual ~tx() {}
        virtual wit_ok witnesses_ok(const tx_out_data_list *input_data=nullptr) const =0;
        virtual void foreach_input(const std::function<void(const tx_input &)> &) const {}
        virtual void foreach_output(const std::function<void(const tx_output &)> &) const {}
        virtual size_t foreach_mint(const std::function<void(const buffer &, const cbor::map &)> &) const { return 0; }
        virtual void foreach_withdrawal(const std::function<void(const tx_withdrawal &)> &) const {}
        virtual void foreach_stake_reg(const stake_reg_observer &) const {}
        virtual void foreach_stake_unreg(const stake_unreg_observer &) const {}
        virtual void foreach_stake_deleg(const std::function<void(const stake_deleg &)> &) const {}
        virtual void foreach_pool_reg(const std::function<void(const pool_reg &)> &) const {}
        virtual void foreach_param_update(const std::function<void(const param_update_proposal &)> &) const {}
        virtual void foreach_pool_unreg(const std::function<void(const pool_unreg &)> &) const {}
        virtual void foreach_genesis_deleg(const std::function<void(const genesis_deleg &, size_t)> &) const {}
        virtual void foreach_instant_reward(const std::function<void(const instant_reward &)> &) const {}
        virtual void foreach_collateral(const std::function<void(const tx_input &)> &) const {}
        virtual void foreach_collateral_return(const std::function<void(const tx_output &)> &) const {}

        virtual const amount fee() const
        {
            return {};
        }

        virtual const cardano_hash_32 &hash() const
        {
            if (!_cached_hash)
                _cached_hash.emplace(blake2b<cardano_hash_32>(_tx.data_buf()));
            return *_cached_hash;
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

        const cbor_value &raw_cbor() const
        {
            return _tx;
        }

        buffer raw_data() const
        {
            return _tx.data_buf();
        }

        const block_base &block() const
        {
            return _blk;
        }

        size_t index() const
        {
            return _idx;
        }

        const cbor_value &raw_witness() const
        {
            if (!_wit)
                throw error("a transaction witness has not been supplied for this transaction!");
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
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::cardano::epoch>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", static_cast<uint64_t>(v));
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::amount_asset>: formatter<daedalus_turbo::cardano::amount_pure> {
        template<typename FormatContext>
        auto format(const auto &a, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{} {}/{}", daedalus_turbo::cardano::amount_pure { a.coins }, a.policy_id, a.asset);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::balance_change>: formatter<daedalus_turbo::cardano::amount_pure> {
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
    struct formatter<daedalus_turbo::cardano::multi_balance_change>: formatter<daedalus_turbo::cardano::balance_change> {
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
    struct formatter<daedalus_turbo::cardano::tx_input>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{} #{}", v.tx_hash, v.txo_idx);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::tx_output>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = fmt::format_to(ctx.out(), "address: {}\n        amount: {}", v.address, v.amount);
            if (v.assets != nullptr) {
                out_it = fmt::format_to(out_it, "\n        assets (name, policy id, amount): [\n");
                for (const auto &[policy_id, p_assets]: v.assets->map()) {
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
    struct formatter<daedalus_turbo::cardano::tx>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            const auto &slot = v.block().slot_object();
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
    struct formatter<daedalus_turbo::cardano::nonce>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            if (v)
                return fmt::format_to(ctx.out(), "{}", *v);
            else
                return fmt::format_to(ctx.out(), "disabled");
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::reward_source>: formatter<uint64_t> {
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
    struct formatter<daedalus_turbo::cardano::relay_info>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            switch (v.index()) {
                case 0: {
                    const auto &ra = std::get<daedalus_turbo::cardano::relay_addr>(v);
                    return fmt::format_to(ctx.out(), "port: {} ipv4: {} ipv6: {}", ra.port, ra.ipv4, ra.ipv6);
                }
                case 1: {
                    const auto &rh = std::get<daedalus_turbo::cardano::relay_host>(v);
                    return fmt::format_to(ctx.out(), "port: {} host: {}", rh.port, rh.host);
                }
                case 2: {
                    const auto &rd = std::get<daedalus_turbo::cardano::relay_dns>(v);
                    return fmt::format_to(ctx.out(), "dns: {}", rd.name);
                }
                default: return fmt::format_to(ctx.out(), "unsupporte reley info value with index: {}", v.index());
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::pool_metadata>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "url: {} hash: {}", v.url, v.hash);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::pool_reg>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "pool_id: {} vrf: {} pledge: {} cost: {} margin: {} reward: {} owners: {} relays: {} metadata: {}",
                v.pool_id, v.vrf_vkey, v.pledge, v.cost, v.margin, v.reward_id, v.owners, v.relays, v.metadata);
        }
    };
}

namespace daedalus_turbo::cardano {
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

    inline json::object tx_output::to_json() const
    {
        auto j = json::object {
            { "address", address.to_json() },
            { "amount", amount.to_json() }
        };
        if (assets != nullptr) {
            auto maj = json::object {};
            for (const auto &[policy_id, p_assets]: assets->map()) {
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
            { "slot", block().slot_object().to_json() },
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
}

#endif // !DAEDALUS_TURBO_CARDANO_COMMON_HPP