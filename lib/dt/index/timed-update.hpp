/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_TIMED_UPDATE_HPP
#define DAEDALUS_TURBO_INDEX_TIMED_UPDATE_HPP

#include <dt/cardano.hpp>
#include <dt/index/common.hpp>

namespace daedalus_turbo::index::timed_update {
    struct stake_withdraw {
        cardano::stake_ident stake_id {};
        uint64_t amount = 0;

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.stake_id, self.amount);
        }
    };
    struct collected_collateral_input {
        cardano::tx_hash tx_hash {};
        cardano::tx_out_idx txo_idx {};

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.tx_hash, self.txo_idx);
        }
    };
    struct collected_collateral_refund {
        using serialize = ::zpp::bits::members<1>;
        cardano::amount refund {};
    };
    struct donation {
        uint64_t coin = 0;
    };
    using variant = std::variant<
        cardano::shelley::stake_reg_cert,
        cardano::conway::reg_cert,
        cardano::conway::stake_reg_deleg_cert,
        cardano::conway::vote_reg_deleg_cert,
        cardano::conway::stake_vote_reg_deleg_cert,
        cardano::conway::reg_drep_cert,
        cardano::shelley::pool_reg_cert,
        cardano::shelley::genesis_deleg_cert,
        cardano::shelley::instant_reward_cert,
        cardano::shelley::stake_deleg_cert,
        cardano::conway::vote_deleg_cert,
        cardano::conway::stake_vote_deleg_cert,
        cardano::conway::auth_committee_hot_cert,
        cardano::conway::resign_committee_cold_cert,
        cardano::conway::update_drep_cert,
        stake_withdraw,
        cardano::shelley::stake_dereg_cert,
        cardano::shelley::pool_retire_cert,
        cardano::conway::unreg_cert,
        cardano::conway::unreg_drep_cert,
        cardano::param_update_proposal,
        cardano::param_update_vote,
        collected_collateral_input,
        collected_collateral_refund,
        cardano::conway::proposal_t,
        cardano::conway::vote_info_t
    >;
    struct item {
        cardano::cert_loc_t loc {};
        variant update;

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.loc, self.update);
        }

        bool operator<(const auto &b) const
        {
            if (loc == b.loc)
                return update.index() < b.update.index();
            return loc < b.loc;
        }
    };

    struct chunk_indexer: chunk_indexer_one_epoch<item> {
        using chunk_indexer_one_epoch::chunk_indexer_one_epoch;
    protected:
        void index_tx(const cardano::tx &tx) override
        {
            const auto slot = tx.block().slot();
            if (const auto *c_tx = dynamic_cast<const cardano::conway::tx *>(&tx); c_tx) {
                c_tx->foreach_cert([&](const auto &v, const auto cert_idx) {
                    cardano::conway::cert_t cert { v };
                    std::visit([&](const auto &c) {
                        _data.emplace_back(cardano::cert_loc_t { slot, tx.index(), cert_idx }, c);
                    }, cert.val);
                });
                {
                    size_t prop_idx = 0;
                    c_tx->foreach_proposal([&](const auto &p) {
                        _data.emplace_back(cardano::cert_loc_t { slot, tx.index(), prop_idx++ }, p);
                    });
                }
                {
                    size_t vote_idx = 0;
                    c_tx->foreach_vote([&](const auto &p) {
                        _data.emplace_back(cardano::cert_loc_t { slot, tx.index(), vote_idx++ }, p);
                    });
                }
            } else {
                tx.foreach_cert([&](const auto &v, const auto cert_idx) {
                    cardano::shelley::cert_t cert { v };
                    std::visit([&](const auto &c) {
                        _data.emplace_back(cardano::cert_loc_t { slot, tx.index(), cert_idx }, c);
                    }, cert.val);
                });
            }
            tx.foreach_withdrawal([&](const auto &with) {
                _data.emplace_back(cardano::cert_loc_t { slot, tx.index(), 0 }, stake_withdraw { with.address.stake_id(), with.amount });
            });
        }

        void index_invalid_tx(const cardano::tx &tx) override
        {
            const auto slot = tx.block().slot();
            if (const auto *babbage_tx = dynamic_cast<const cardano::babbage::tx *>(&tx); babbage_tx) {
                if (const auto c_ret = babbage_tx->collateral_return(); c_ret)
                    _data.emplace_back(cardano::cert_loc_t { slot, tx.index(), 0 }, collected_collateral_refund { c_ret->amount });
            }
            tx.foreach_collateral([&](const auto &tx_in) {
                logger::debug("collect collateral {}#{}", tx_in.tx_hash, tx_in.txo_idx);
                _data.emplace_back(cardano::cert_loc_t { slot, tx.index(), 0 }, collected_collateral_input { tx_in.tx_hash, tx_in.txo_idx });
            });
        }

        void _index_epoch(const cardano::block_base &blk, data_type &idx) override
        {
            blk.foreach_update_proposal([&](const auto &prop) {
                idx.emplace_back(cardano::cert_loc_t { blk.slot(), 0, 0 }, prop);
            });
            blk.foreach_update_vote([&](const auto &vote) {
                idx.emplace_back(cardano::cert_loc_t { blk.slot(), 0, 0 }, vote);
            });
        }
    };
    using indexer = indexer_one_epoch<chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_TIMED_UPDATE_HPP