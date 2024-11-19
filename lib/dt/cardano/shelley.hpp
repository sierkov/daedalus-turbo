/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_SHELLEY_HPP
#define DAEDALUS_TURBO_CARDANO_SHELLEY_HPP

#include <dt/cardano/common.hpp>
#include <dt/cbor.hpp>
#include <dt/ed25519.hpp>

namespace daedalus_turbo::cardano::shelley {
    static constexpr uint64_t kes_period_slots = 129600;

    struct stake_reg_cert {
        stake_ident stake_id {};
    };

    struct stake_dereg_cert {
        stake_ident stake_id {};
    };

    struct stake_deleg_cert {
        stake_ident stake_id {};
        pool_hash pool_id {};
    };

    struct pool_reg_cert {
        pool_hash pool_id {};
        pool_params params {};

        static pool_reg_cert from_cbor(const cbor::value &);
    };

    struct pool_retire_cert {
        cardano_hash_28 pool_id {};
        cardano::epoch epoch {};

        static pool_retire_cert from_cbor(const cbor::value &);
    };

    struct genesis_deleg_cert {
        key_hash hash;
        pool_hash pool_id;
        cardano::vrf_vkey vrf_vkey;
    };

    enum class reward_source { reserves, treasury };

    struct instant_reward_cert {
        reward_source source {};
        map<stake_ident, amount> rewards {};

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.source, self.rewards);
        }

        instant_reward_cert() =default;
        instant_reward_cert(const cbor::value &);
    };

    struct cert_t {
        using value_type = std::variant<
            stake_reg_cert, stake_dereg_cert, stake_deleg_cert, pool_reg_cert, pool_retire_cert,
            genesis_deleg_cert, instant_reward_cert>;
        value_type val;

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.val);
        }

        cert_t() =delete;
        cert_t(const cbor::value &);
    };

    inline void parse_shelley_param_update_common(param_update &res, const uint64_t idx, const cbor_value &val)
    {
        switch (idx) {
            case 0: res.min_fee_a.emplace(val.uint()); break;
            case 1: res.min_fee_b.emplace(val.uint()); break;
            case 2: res.max_block_body_size.emplace(val.uint()); break;
            case 3: res.max_transaction_size.emplace(val.uint()); break;
            case 4: res.max_block_header_size.emplace(val.uint()); break;
            case 5: res.key_deposit.emplace(val.uint()); break;
            case 6: res.pool_deposit.emplace(val.uint()); break;
            case 7: res.e_max.emplace(val.uint()); break;
            case 8: res.n_opt.emplace(val.uint()); break;
            case 9:
                res.pool_pledge_influence.emplace(
                val.tag().second->array().at(0).uint(),
                val.tag().second->array().at(1).uint()
                );
                break;
            case 10:
                res.expansion_rate.emplace(
                    val.tag().second->array().at(0).uint(),
                    val.tag().second->array().at(1).uint()
                );
                break;
            case 11:
                res.treasury_growth_rate.emplace(
                    val.tag().second->array().at(0).uint(),
                    val.tag().second->array().at(1).uint()
                );
                break;
            case 12:
                res.decentralization.emplace(
                    val.tag().second->array().at(0).uint(),
                    val.tag().second->array().at(1).uint()
                );
                break;
            case 13:
                if (val.array().at(0).uint() == 1)
                    res.extra_entropy.emplace(val.array().at(1).buf());
                else if (val.array().at(0).uint() == 0)
                    res.extra_entropy.emplace();
                else
                    logger::warn("unsupported shelley extra_entropy update: {}", val.array().at(0).uint());
                break;
            case 14: res.protocol_ver.emplace(val.array().at(0).uint(), val.array().at(1).uint());
                break;
            default:
                throw error("protocol parameter index is out of the expected range for common params: {}", idx);
        }
    }

    inline param_update parse_shelley_param_update(const cbor::value &proposal)
    {
        param_update upd {};
        for (const auto &[idx, val]: proposal.map()) {
            switch (idx.uint()) {
                case 0:
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                case 8:
                case 9:
                case 10:
                case 11:
                case 12:
                case 13:
                case 14:
                    parse_shelley_param_update_common(upd, idx.uint(), val);
                    break;
                case 15:
                    upd.min_utxo_value.emplace(val.uint());
                    break;
                default:
                    throw error("shelley unsupported protocol parameters update: {}", idx.uint());
                    break;
            }
        }
        return upd;
    }

    struct tx;

    struct block: block_base {
        using auxiliary_map = map<size_t, const cbor::value &>;

        block(const cbor_value &block_tuple, const uint64_t offset, const uint64_t era, const cbor_value &block, const cardano::config &cfg)
            : block_base { block_tuple, offset, era, block, cfg }
        {
            // cardano::network may call this to parse only the headers; in that case the block will contain just the header
            if (_block.array().size() >= 3 && transactions().size() != witnesses().size())
                throw error("slot: {} the number of transactions {} does not match the number of witnesses {}", slot(), transactions().size(), witnesses().size());
        }

        cardano_hash_32 hash() const override
        {
            if (!_cached_hash)
                _cached_hash.emplace(blake2b<cardano_hash_32>(header_cbor().raw_span()));
            return *_cached_hash;
        }

        buffer prev_hash() const override
        {
            const auto &val = header_body().at(2);
            if (val.is_null())
                return config().byron_genesis_hash;
            return header_body().at(2).buf();
        }

        uint64_t height() const override
        {
            return header_body().at(0).uint();
        }

        size_t tx_count() const override
        {
            return transactions().size();
        }

        void foreach_tx(const std::function<void(const cardano::tx &)> &observer) const override;
        void foreach_update_proposal(const std::function<void(const param_update_proposal &)> &observer) const override;

        uint64_t slot() const override
        {
            return header_body().at(1).uint();
        }

        const cbor_value &header_cbor() const
        {
            return _block.array().at(0);
        }

        const cbor_array &header() const
        {
            return header_cbor().array();
        }

        const buffer header_body_raw() const
        {
            return header().at(0).raw_span();
        }

        const cbor_array &header_body() const
        {
            return header().at(0).array();
        }

        const cbor_array &transactions() const
        {
            return _block.array().at(1).array();
        }

        const cbor_array &witnesses() const
        {
            return _block.array().at(2).array();
        }

        const auxiliary_map &auxiliary() const
        {
            if (!_aux_cache) {
                auxiliary_map m {};
                for (const auto &[idx, val]: _block.array().at(3).map()) {
                    m.try_emplace(idx.uint(), val);
                }
                _aux_cache.emplace(std::move(m));
            }
            return *_aux_cache;
        }

        const cbor::value *auxiliary_at(const size_t tx_idx) const
        {
            const auto &aux = auxiliary();
            if (const auto it = aux.find(tx_idx); it != aux.end())
                return &it->second;
            return nullptr;
        }

        const buffer issuer_vkey() const override
        {
            return header_body().at(3).buf();
        }

        const kes_signature kes() const override
        {
            const auto &op_cert = header_body();
            size_t op_start_idx = 9;
            return kes_signature {
                op_cert.at(op_start_idx + 0).buf(),
                op_cert.at(op_start_idx + 3).buf(),
                issuer_vkey(),
                header().at(1).buf(),
                header_body_raw(),
                op_cert.at(op_start_idx + 1).uint(),
                op_cert.at(op_start_idx + 2).uint(),
                slot()
            };
        }

        const block_vrf vrf() const override
        {
            const auto &vkey = header_body().at(4).span();
            const auto &leader_vrf = header_body().at(6).array();
            const auto &nonce_vrf = header_body().at(5).array();
            return block_vrf {
                vkey,
                leader_vrf.at(0).span(),
                leader_vrf.at(1).span(),
                nonce_vrf.at(0).span(),
                nonce_vrf.at(1).span()
            };
        }

        const protocol_version protocol_ver() const override
        {
            return protocol_version { header_body().at(13).uint(), header_body().at(14).uint() };
        }

        bool body_hash_ok() const override
        {
            const auto &exp_hash = header_body().at(8).buf();
            auto act_hash = _calc_body_hash(_block.array(), 1, 4);
            return exp_hash == act_hash;
        }

        bool signature_ok() const override
        {
            auto kes_slot = slot();
            auto kes_data = kes();
            auto vkey = issuer_vkey();
            return _validate_kes(kes_slot, kes_data, vkey);
        }
    protected:
        mutable std::optional<auxiliary_map> _aux_cache {};

        static cardano_hash_32 _calc_body_hash(const cbor_array &block, const size_t begin_idx, const size_t end_idx)
        {
            const size_t num_hashes = end_idx - begin_idx;
            std::vector<cardano_hash_32> body_hash_in(num_hashes);
            for (size_t i = 0; i < num_hashes; ++i) {
                blake2b(body_hash_in[i], block.at(begin_idx + i).raw_span());
            }
            return blake2b<cardano_hash_32>(buffer { body_hash_in.data(), body_hash_in.size() * sizeof(body_hash_in[0]) });
        }
    private:
        static bool _validate_op_cert(const kes_signature &kes_, const buffer &issuer_vkey_)
        {
            std::array<uint8_t, sizeof(cardano_vkey) + 2 * sizeof(uint64_t)> ocert_data {};
            if (kes_.vkey.size() != sizeof(cardano::vkey))
                throw error("vkey size mismatch!");
            memcpy(ocert_data.data(), kes_.vkey.data(), kes_.vkey.size());
            const auto ctr = host_to_net<uint64_t>(kes_.counter);
            memcpy(ocert_data.data() + sizeof(cardano_vkey), &ctr, sizeof(uint64_t));
            const auto kp = host_to_net<uint64_t>(kes_.period);
            memcpy(ocert_data.data() + kes_.vkey.size() + sizeof(uint64_t), &kp, sizeof(uint64_t));
            return ed25519::verify(kes_.vkey_sig, issuer_vkey_, ocert_data);
        }

        static bool _validate_kes(const uint64_t slot_, const kes_signature &kes_, const buffer &issuer_vkey_)
        {
            if (!_validate_op_cert(kes_, issuer_vkey_)) {
                logger::error("the signature of the block's operational certificate is invalid!");
                return false;
            }
            uint64_t kp = slot_ / kes_period_slots;
            if (kes_.period > kp) {
                logger::error("vkey kes period {} is greater than current kes_period {}", kes_.period, kp);
                return false;
            }
            uint64_t t = kp - kes_.period;
            cardano_kes_signature kes_sig { kes_.sig };
            if (!kes_sig.verify(t, kes_.vkey.first<32>(), kes_.header_body)) {
                logger::error("KES signature verification failed!");
                return false;
            }
            return true;
        }
    };

    struct tx: cardano::tx {
        using cardano::tx::tx;

        void foreach_input(const std::function<void(const tx_input &)> &observer) const override;

        void foreach_output(const std::function<void(const tx_output &)> &observer) const override
        {
            const cbor_array *outputs = nullptr;
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 1)
                    outputs = &entry.array();
            }
            if (outputs == nullptr) [[unlikely]]
                return;
            for (size_t i = 0; i < outputs->size(); i++)
                observer(tx_output::from_cbor(_blk.era(), i, outputs->at(i)));
        }

        void foreach_withdrawal(const std::function<void(const tx_withdrawal &)> &observer) const override
        {
            const cbor_map *withdrawals = nullptr;
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 5) withdrawals = &entry.map();
            }
            if (withdrawals == nullptr) return;
            for (size_t i = 0; i < withdrawals->size(); i++) {
                const auto &[address, amount] = withdrawals->at(i);
                if (i >= 0x10000) throw cardano_error("transaction withdrawal number is too high {}!", i);
                observer(tx_withdrawal { cardano::address { address.buf() }, cardano::amount { amount.uint() }, i });
            }
        }

        const amount fee() const override
        {
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 2)
                    return { entry.uint() };
            }
            throw error("a shelley+ transaction has no fee information: {} at offset {}!", hash(), offset());
        }

        void foreach_param_update(const std::function<void(const param_update_proposal &)> &observer) const override
        {
            _if_item_present(6, [&](const auto &update) {
                const uint64_t epoch = update.array().at(1).uint();
                for (const auto &[genesis_deleg_hash, proposal]: update.array().at(0).map()) {
                    param_update_proposal prop { genesis_deleg_hash.buf(), epoch, parse_shelley_param_update(proposal) };
                    prop.update.rehash();
                    observer(prop);
                }
            });
        }

        std::optional<uint64_t> validity_end() const override;
        wit_cnt witnesses_ok(const plutus::context *ctx=nullptr) const override;
        virtual wit_cnt witnesses_ok_other(const plutus::context *ctx=nullptr) const;
        void foreach_witness(const std::function<void(uint64_t, const cbor::value &)> &observer) const override;
        void foreach_cert(const std::function<void(const cbor::value &cert, size_t cert_idx)> &observer) const override;
        void foreach_script(const std::function<void(script_info &&)> &, const plutus::context *ctx=nullptr) const override;
    protected:
        set<key_hash> _witnesses_ok_vkey(const cbor::value &w_val) const;
        size_t _witnesses_ok_bootstrap(const cbor::value &w_val) const;
        size_t _witnesses_ok_native_script(const cbor::value &w_val, const set<key_hash> &vkeys) const;
        virtual wit_cnt _witnesses_ok_other(uint64_t typ, const cbor::value &w_val, const plutus::context *ctx=nullptr) const;

        void _if_item_present(const uint64_t idx, const std::function<void(const cbor_value &)> &observer) const
        {
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == idx)
                    observer(entry);
            }
        }

        void _foreach_cert(const uint64_t cert_type, const std::function<void(const cbor::value &, size_t cert_idx)> &observer) const
        {
            foreach_cert([cert_type, &observer](const auto &cert, const size_t cert_idx) {
                if (cert.at(0).uint() == cert_type)
                    observer(cert, cert_idx);
            });
        }
    };

    inline void block::foreach_update_proposal(const std::function<void(const param_update_proposal &)> &observer) const
    {
        foreach_tx([&](const auto &tx) {
            tx.foreach_param_update(observer);
        });
    }
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::cardano::shelley::reward_source>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            switch (v) {
                case daedalus_turbo::cardano::shelley::reward_source::reserves:
                    return fmt::format_to(ctx.out(), "reward_source::reserves");

                case daedalus_turbo::cardano::shelley::reward_source::treasury:
                    return fmt::format_to(ctx.out(), "reward_source::treasury");

                default:
                    throw daedalus_turbo::error("unsupported reward_source value: {}", static_cast<int>(v));
                break;
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::shelley::pool_reg_cert>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "pool_id: {} params: ({})", v.pool_id, v.params);
        }
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_SHELLEY_HPP