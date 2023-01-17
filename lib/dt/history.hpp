/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_HISTORY_HPP
#define DAEDALUS_TURBO_HISTORY_HPP

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>

#include <dt/bech32.hpp>
#include <dt/cardano.hpp>
#include <dt/cbor.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/index.hpp>
#include <dt/index-type.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo
{
    using namespace std;

    struct transaction {
        uint8_vector id;
        uint8_vector spent_id;
        uint64_t amount;
        uint64_t withdraw;
        uint64_t slot;
        uint16_t out_idx;

        bool operator<(const transaction &tx) const
        {
            if (slot < tx.slot) return true;
            if (slot == tx.slot) {
                size_t min_size = std::min(id.size(), tx.id.size());
                int cmp = memcmp(id.data(), tx.id.data(), min_size);
                if (cmp < 0) return true;
                if (cmp == 0 && id.size() < tx.id.size()) return true;
            }
            return false;
        }
    };

    inline ostream &operator<<(ostream &os, const transaction &tx)
    {
        os << "epoch: " << slot_to_epoch(tx.slot) << ", slot: " << tx.slot << ", tx: " << tx.id;
        if (tx.withdraw > 0) {
            os << ", widthdraw rewards: " << tx.withdraw / 1000000 << "." << tx.withdraw % 1000000 << " ADA";
        } else {
            os << ", out: " << tx.out_idx << ", inflow " << tx.amount / 1000000 << "." << tx.amount % 1000000 << " ADA";
        }
        if (tx.spent_id.size() > 0) {
            os << ", spent: " << tx.spent_id;
        }
        os << endl;
        return os;
    }

    struct history {
        uint8_vector stake_addr;
        vector<transaction> transactions;
        uint64_t last_slot = 0;
        uint64_t num_disk_reads = 0;

        history(const buffer &address)
            : stake_addr(address), transactions()
        {
        }

        uint64_t utxo_balance()
        {
            uint64_t bal = 0;
            for (const auto &tx: transactions) {
                if (tx.spent_id.size() == 0) bal += tx.amount;
            }
            return bal;
        }

        uint64_t utxo_balance_latest()
        {
            uint64_t bal = 0;
            for (const auto &tx: transactions) {
                if (slot_to_epoch(tx.slot) == slot_to_epoch(last_slot) && tx.spent_id.size() == 0) bal += tx.amount;
            }
            return bal;
        }

        uint64_t reward_withdrawals()
        {
            uint64_t w = 0;
            for (const auto &tx: transactions) {
                if (tx.withdraw > 0) w += tx.withdraw;
            }
            return w;
        }
    };

    inline ostream &operator<<(ostream &os, const history &h)
    {
        if (h.transactions.size() > 0) {
            set<uint8_vector> incoming, outgoing;
            uint64_t total_balance = 0;
            for (const auto &tx: h.transactions) {
                os << tx;
                incoming.insert(tx.id);
                if (tx.spent_id.size() > 0) outgoing.insert(tx.spent_id);
                else total_balance += tx.amount;
            }
            os << "transactions affecting stake address: " << buffer(h.stake_addr)
                << " incoming: " << incoming.size() << ", outgoing: " << outgoing.size() << "\n"
                << "available balance without rewards: " << total_balance / 1000000 << "." << total_balance % 1000000 << " ADA" << endl;
            os << "last indexed blockchain slot: " << h.last_slot << ", last epoch: " << slot_to_epoch(h.last_slot)
                << ", i/o cost (# random reads): " << h.num_disk_reads;
        } else {
            os << "last indexed blockchain slot: " << h.last_slot << ", last epoch: " << slot_to_epoch(h.last_slot) << "\n"
                << "no transactions affecting stake address " << buffer(h.stake_addr) << " have been found!";
        }
        os << endl;
        return os;
    }

    class reconstructor
    {
        chunk_registry _cr;
        index_reader<addr_use_item> _addr_use_idx;
        index_reader<tx_use_item> _tx_use_idx;
        vector<block_item> _block_index;

        struct addr_match {
            uint8_t stake_addr[28];
            uint8_t tx_hash[32];
            uint64_t amount;
            uint64_t withdraw;
            uint64_t tx_out_idx;
            cardano_block_context block;
            
            addr_match(const buffer &address, const buffer &tx_hash_, uint64_t amount, uint16_t tx_out_idx_, uint64_t withdraw_, const cardano_block_context &block_ctx)
                : amount(amount), withdraw(withdraw_), tx_out_idx(tx_out_idx_), block(block_ctx)
            {
                memcpy(stake_addr, address.data(), address.size());
                memcpy(tx_hash, tx_hash_.data(), tx_hash_.size());
            }

            bool operator<(const addr_match &m) const {
                return block.era < m.block.era
                    || block.slot < m.block.slot
                    || memcmp(tx_hash, m.tx_hash, sizeof(tx_hash)) < 0
                    || tx_out_idx < m.tx_out_idx
                    || withdraw < m.withdraw;
            }    
        };

        class addr_matcher: public cardano_processor {
            set<addr_match> &matches;
            const buffer search_address;

        public:

            addr_matcher(set<addr_match> &matches_, const buffer &addr)
                : matches(matches_), search_address(addr)
            {
            }

            void every_tx_output(const cardano_tx_output_context &ctx, const cbor_buffer &address, uint64_t amount) {
                uint8_t address_type = address.data()[0] >> 4;
                if (address.size() != 57 || address_type >= 4) return;
                if (memcmp(search_address.data(), address.data() + 29, search_address.size()) != 0) return;
                addr_match m(address, buffer(ctx.tx_ctx.hash, sizeof(ctx.tx_ctx.hash)), amount, ctx.out_idx, 0, ctx.tx_ctx.block_ctx);
                auto [it, ok] = matches.insert(move(m));
                if (!ok) throw error("failed to insert a matching withdrawal!");
            };

            void every_tx_withdrawal(const cardano_tx_context &ctx, const cbor_buffer &address, uint64_t amount)
            {
                if (address.size() != 29 || address.data()[0] != 0xE1) return;
                if (memcmp(search_address.data(), address.data() + 1, search_address.size()) != 0) return;
                addr_match m(address, buffer(ctx.hash, sizeof(ctx.hash)), 0, 0, amount, ctx.block_ctx);
                auto [it, ok] = matches.insert(move(m));
                if (!ok) throw error("failed to insert a matching withdrawal!");
            }
        };

    public:

        reconstructor(const string &db_path, const string &idx_path, bool lz4=false)
            : _cr(db_path, lz4), _addr_use_idx(idx_path + "/addruse/index.bin"), _tx_use_idx(idx_path + "/txuse/index.bin"), _block_index()
        {
            const string block_index_path = idx_path + "/block/index.bin";
            size_t block_index_size = filesystem::file_size(block_index_path);
            if (block_index_size % sizeof(block_item) != 0) throw error("File size of %s must divide without remainder by %zu", block_index_path.c_str(), sizeof(block_item));
            _block_index.resize(block_index_size / sizeof(block_item));
            if (block_index_size > 0) {
                ifstream is(block_index_path, ios::binary);
                if (!is.read(reinterpret_cast<char *>(_block_index.data()), block_index_size))
                    throw sys_error("Read from %s has failed!", block_index_path.c_str());
            }
        }

        history reconstruct_raw_addr(const buffer &stake_addr) {
            history hist(stake_addr);
            hist.last_slot = _block_index.rbegin()->slot;
            
            auto [ ok_addr, addr_use, addr_n_reads ] = _addr_use_idx.find(stake_addr);
            hist.num_disk_reads = addr_n_reads;
            if (ok_addr) {
                set<addr_match> matches;
                addr_matcher proc(matches, stake_addr);
                cardano_parser parser(proc);

                cbor_value tx;
                uint8_t tx_hash[32];
                for (;;) {
                    uint64_t tx_offset = unpack_offset(addr_use.tx_offset, sizeof(addr_use.tx_offset));
                    auto bi_it = lower_bound(_block_index.begin(), _block_index.end(), block_item(tx_offset));
                    if (bi_it == _block_index.end()) throw error("unknown offset: %zu!", addr_use.tx_offset);
                    if (bi_it != _block_index.begin()) bi_it = std::prev(bi_it);
                    if (!(bi_it->offset <= tx_offset && bi_it->offset + bi_it->size >= tx_offset + 1)) throw error("internal error block metadata does not match the transaction!");
                    ++hist.num_disk_reads;
                    _cr.read(tx_offset, tx);
                    cardano_chunk_context chunk_ctx(bi_it->offset);
                    cardano_block_context block_ctx(chunk_ctx, bi_it->offset, bi_it->era, bi_it->block_number, bi_it->slot, slot_to_epoch(bi_it->slot));
                    blake2b_best(tx_hash, sizeof(tx_hash), reinterpret_cast<const char *>(tx.data), tx.size);
                    cardano_tx_context tx_ctx(block_ctx, tx_offset, 0, buffer(tx_hash, sizeof(tx_hash)));
                    parser.parse_tx(tx_ctx, tx);
                    ++hist.num_disk_reads;
                    auto next_res = _addr_use_idx.next(stake_addr);
                    if (!std::get<0>(next_res)) break;
                    addr_use = std::get<1>(next_res);
                }

                for (auto it = matches.begin(); it != matches.end(); it++) {
                    if (sizeof(it->tx_hash) != 32) throw runtime_error("unexpected tx_hash of size different from 32 bytes!");
                    transaction tx_meta;
                    tx_meta.slot = it->block.slot;
                    tx_meta.id = buffer(it->tx_hash, sizeof(it->tx_hash));
                    tx_meta.out_idx = it->tx_out_idx;
                    tx_meta.amount = it->amount;
                    tx_meta.withdraw = it->withdraw;
                    if (it->withdraw == 0) {
                        tx_meta.id = buffer(it->tx_hash, sizeof(it->tx_hash));
                        uint8_t tx_use_key[32 + 2];
                        memcpy(tx_use_key, it->tx_hash, sizeof(it->tx_hash));
                        memcpy(tx_use_key + sizeof(it->tx_hash), &it->tx_out_idx, 2);
                        auto [ ok_tx_use, tx_use, tx_n_reads ] = _tx_use_idx.find(buffer(tx_use_key, sizeof(tx_use_key)));
                        hist.num_disk_reads += tx_n_reads;                    
                        if (ok_tx_use) {
                            ++hist.num_disk_reads;
                            uint64_t tx_offset = unpack_offset(tx_use.tx_offset, sizeof(tx_use.tx_offset));
                            _cr.read(tx_offset, tx);
                            blake2b_best(tx_hash, sizeof(tx_hash), reinterpret_cast<const char *>(tx.data), tx.size);
                            tx_meta.spent_id = buffer(tx_hash, sizeof(tx_hash));
                        }
                    }
                    hist.transactions.push_back(move(tx_meta));
                }
            }
            sort(hist.transactions.begin(), hist.transactions.end(), [](const auto &a, const auto &b) { return a < b; });
            return hist;
        }

        history reconstruct(const buffer &address) {
            if (address.size() != 29 || address.data()[0] != 0xE1) throw runtime_error("only shelley stake reward addresses (type 14) are supported!");
            const buffer stake_addr(address.data() + 1, address.size() - 1);
            return reconstruct_raw_addr(stake_addr);
        }

    };

}

#endif // !DAEDALUS_TURBO_HISTORY_HPP
