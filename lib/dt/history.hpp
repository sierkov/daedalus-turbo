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
#include <utility>

#include <dt/bech32.hpp>
#include <dt/cardano.hpp>
#include <dt/cbor.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/index.hpp>
#include <dt/index-type.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo
{

    struct transaction {
        uint8_vector id;
        uint8_vector spent_id;
        uint64_t amount;
        uint64_t withdraw = 0;
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

    inline std::ostream &operator<<(std::ostream &os, const transaction &tx)
    {
        os << "epoch: " << slot_to_epoch(tx.slot) << ", slot: " << tx.slot << ", tx: " << tx.id;
        if (tx.withdraw > 0) {
            os << ", withdraw rewards: " << cardano_amount(tx.withdraw);
        } else {
            os << ", out: " << tx.out_idx << ", inflow: " << cardano_amount(tx.amount);
        }
        if (tx.spent_id.size() > 0) {
            os << ", spent: " << tx.spent_id;
        }
        os << "\n";
        return os;
    }

    struct history {
        uint8_vector stake_addr;
        std::vector<transaction> transactions;
        uint64_t last_slot = 0;
        uint64_t num_disk_reads = 0;
        uint64_t num_idx_reads = 0;
        uint64_t total_tx_outputs = 0;
        uint64_t total_tx_outputs_unspent = 0;
        uint64_t total_utxo_balance = 0;
        uint64_t total_withdrawals = 0;

        history(const buffer &address)
            : stake_addr(address), transactions()
        {
        }

        uint64_t utxo_balance() const
        {
            return total_utxo_balance;
        }

        uint64_t reward_withdrawals() const
        {
            return total_withdrawals;
        }

        void add_tx(transaction &&tx)
        {
            if (tx.withdraw == 0) {
                ++total_tx_outputs;
                if (tx.spent_id.size() == 0) {
                    total_utxo_balance += tx.amount;
                    ++total_tx_outputs_unspent;
                }
            } else {
                total_withdrawals += tx.withdraw;
            } 
            transactions.emplace_back(tx);
        }
    };

    inline std::ostream &operator<<(std::ostream &os, const history &h)
    {
        if (h.transactions.size() > 0) {
            for (const auto &tx: h.transactions) {
                if (tx.withdraw == 0) os << tx;
            }
            os << "transaction outputs affecting stake address " << buffer(h.stake_addr)
                << ": " << h.total_tx_outputs << " of them unspent: " << h.total_tx_outputs_unspent << "\n"
                << "available balance without rewards: " << cardano_amount(h.utxo_balance());
            os << "\n";
            os << "last indexed slot: " << h.last_slot << ", last epoch: " << slot_to_epoch(h.last_slot)
                << ", # random reads: " << h.num_disk_reads
                << " of them from indices: " << h.num_idx_reads << " (" << std::fixed << std::setprecision(1) << 100 * (double)h.num_idx_reads / h.num_disk_reads << "%)";
        } else {
            os << "last indexed slot: " << h.last_slot << ", last epoch: " << slot_to_epoch(h.last_slot) << "\n"
                << "no transactions affecting stake address " << buffer(h.stake_addr) << " have been found!";
        }
        os << "\n";
        return os;
    }

    class reconstructor
    {
        chunk_registry _cr;
        index_reader<addr_use_item> _addr_use_idx;
        index_reader<tx_use_item> _tx_use_idx;
        std::vector<block_item> _block_index;

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
                return memcmp(tx_hash, m.tx_hash, sizeof(tx_hash)) < 0
                    || tx_out_idx < m.tx_out_idx
                    || withdraw < m.withdraw;
            }
        };

        struct spent_tx_check {
            const addr_match *match;
            uint64_t tx_offset;
            size_t tx_size;
            bool do_check;

            spent_tx_check(const addr_match &m, bool chk, uint64_t tx_off=0, size_t tx_sz=0)
                : match(&m), tx_offset(tx_off), tx_size(tx_sz), do_check(chk)
            {
            }
            
        };

        class addr_matcher: public cardano_processor {
            std::set<addr_match> &matches;
            const buffer search_address;

        public:

            addr_matcher(std::set<addr_match> &matches_, const buffer &addr)
                : matches(matches_), search_address(addr)
            {
            }

            void every_tx_output(const cardano_tx_output_context &ctx, const cbor_buffer &address, uint64_t amount) {
                uint8_t address_type = address.data()[0] >> 4;
                if (address.size() != 57 || address_type >= 4) return;
                if (memcmp(search_address.data(), address.data() + 29, search_address.size()) != 0) return;
                addr_match m(address, buffer(ctx.tx_ctx.hash, sizeof(ctx.tx_ctx.hash)), amount, ctx.out_idx, 0, ctx.tx_ctx.block_ctx);
                auto [it, ok] = matches.insert(std::move(m));
                if (!ok) throw error_fmt("failed to insert a matching transaction - already exists!");
            };

            void every_tx_withdrawal(const cardano_tx_context &ctx, const cbor_buffer &address, uint64_t amount)
            {
                if (address.size() != 29 || address.data()[0] != 0xE1) return;
                if (memcmp(search_address.data(), address.data() + 1, search_address.size()) != 0) return;
                addr_match m(address, buffer(ctx.hash, sizeof(ctx.hash)), 0, 0, amount, ctx.block_ctx);
                auto [it, ok] = matches.insert(std::move(m));
                if (!ok) throw error_fmt("failed to insert a matching withdrawal - already exists!");
            }
        };

    public:

        reconstructor(const std::string &db_path, const std::string &idx_path, bool lz4=false)
            : _cr(db_path, lz4), _addr_use_idx(idx_path + "/addruse/index.bin"), _tx_use_idx(idx_path + "/txuse/index.bin"), _block_index()
        {
            const std::string block_index_path = idx_path + "/block/index.bin";
            size_t block_index_size = std::filesystem::file_size(block_index_path);
            if (block_index_size % sizeof(block_item) != 0) throw error_fmt("File size of {} must divide without remainder by {}", block_index_path, sizeof(block_item));
            _block_index.resize(block_index_size / sizeof(block_item));
            if (block_index_size > 0) {
                std::ifstream is(block_index_path, std::ios::binary);
                if (!is.read(reinterpret_cast<char *>(_block_index.data()), block_index_size))
                    throw error_sys_fmt("Read from {} has failed!", block_index_path);
            }
        }

        uint64_t last_slot() const
        {
            uint64_t last_slot = 0;
            if (_block_index.size() > 0) last_slot = _block_index.rbegin()->slot;
            return last_slot;
        }

        const block_item &find_block(uint64_t tx_offset) {
            auto bi_it = lower_bound(_block_index.begin(), _block_index.end(), tx_offset, [](const block_item &b, size_t off) { return b.offset + b.size <= off; });
            if (bi_it == _block_index.end()) throw error_fmt("unknown offset: {}!", tx_offset);
            if (!(tx_offset >= bi_it->offset && tx_offset < bi_it->offset + bi_it->size)) throw error_fmt("internal error block metadata does not match the transaction!");
            return *bi_it;
        }

        history reconstruct_raw_addr(const buffer &stake_addr) {
            history hist(stake_addr);
            if (_block_index.size() == 0) return hist;
            const block_item &last_block = *_block_index.rbegin();
            hist.last_slot = last_block.slot;
            
            auto [ ok_addr, addr_use, addr_n_reads ] = _addr_use_idx.find(stake_addr);
            hist.num_idx_reads = hist.num_disk_reads = addr_n_reads;
            if (ok_addr) {
                std::set<addr_match> matches;
                addr_matcher proc(matches, stake_addr);
                cardano_parser parser(proc);

                cbor_value tx;
                uint8_t tx_hash[32];
                for (;;) {
                    uint64_t tx_offset = unpack_offset(addr_use.tx_offset, sizeof(addr_use.tx_offset));
                    const block_item &bi = find_block(tx_offset);
                    hist.num_disk_reads += _cr.read(tx_offset, tx, unpack_tx_size(addr_use.tx_size), 2);
                    cardano_chunk_context chunk_ctx(bi.offset);
                    cardano_block_context block_ctx(chunk_ctx, bi.offset, bi.era, bi.block_number, bi.slot, slot_to_epoch(bi.slot));
                    blake2b_best(tx_hash, sizeof(tx_hash), reinterpret_cast<const char *>(tx.data), tx.size);
                    cardano_tx_context tx_ctx(block_ctx, tx_offset, tx.size, 0, buffer(tx_hash, sizeof(tx_hash)));
                    parser.parse_tx(tx_ctx, tx);
                    // do not count disk read since it is not a random but a sequential one!
                    auto next_res = _addr_use_idx.next(stake_addr);
                    if (!std::get<0>(next_res)) break;
                    addr_use = std::get<1>(next_res);
                }

                std::vector<spent_tx_check> spent_checks;
                spent_checks.reserve(matches.size());

                for (auto it = matches.begin(); it != matches.end(); it++) {
                    if (sizeof(it->tx_hash) != 32) throw error_fmt("unexpected tx_hash of size different from 32 bytes!");
                    if (it->withdraw == 0) {
                        uint8_t tx_use_key[32 + 2];
                        memcpy(tx_use_key, it->tx_hash, sizeof(it->tx_hash));
                        memcpy(tx_use_key + sizeof(it->tx_hash), &it->tx_out_idx, 2);
                        auto [ ok_tx_use, tx_use, tx_n_reads ] = _tx_use_idx.find(buffer(tx_use_key, sizeof(tx_use_key)));
                        hist.num_disk_reads += tx_n_reads;
                        hist.num_idx_reads += tx_n_reads;
                        if (ok_tx_use) {
                            spent_checks.emplace_back(*it, true, unpack_offset(tx_use.tx_offset, sizeof(tx_use.tx_offset)), unpack_tx_size(tx_use.tx_size));
                        } else {
                            spent_checks.emplace_back(*it, false);
                        }
                    } else {
                        spent_checks.emplace_back(*it, false);
                    }
                }

                // order by tx_offset to improve disk access performance
                std::sort(spent_checks.begin(), spent_checks.end(), [](const auto &a, const auto &b) { return a.tx_offset < b.tx_offset; });
                for (const auto &chk: spent_checks) {
                    transaction tx_meta;
                    if (chk.do_check) {
                        hist.num_disk_reads += _cr.read(chk.tx_offset, tx, chk.tx_size, 2);
                        blake2b_best(tx_hash, sizeof(tx_hash), reinterpret_cast<const char *>(tx.data), tx.size);
                        tx_meta.spent_id = buffer(tx_hash, sizeof(tx_hash));
                    }
                    tx_meta.id = buffer(chk.match->tx_hash, sizeof(chk.match->tx_hash));
                    tx_meta.slot = chk.match->block.slot;
                    tx_meta.out_idx = chk.match->tx_out_idx;
                    tx_meta.amount = chk.match->amount;
                    tx_meta.withdraw = chk.match->withdraw;
                    hist.add_tx(std::move(tx_meta));
                }
            }
            std::sort(hist.transactions.begin(), hist.transactions.end(), [](const auto &a, const auto &b) { return a < b; });
            return hist;
        }

        history reconstruct(const buffer &address) {
            if (address.size() != 29 || address.data()[0] != 0xE1) throw error_fmt("only shelley stake reward addresses (type 14) are supported!");
            const buffer stake_addr(address.data() + 1, address.size() - 1);
            return reconstruct_raw_addr(stake_addr);
        }

    };

}

#endif // !DAEDALUS_TURBO_HISTORY_HPP
