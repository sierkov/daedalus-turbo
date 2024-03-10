/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_HISTORY_HPP
#define DAEDALUS_TURBO_HISTORY_HPP

#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <utility>
#include <dt/cardano.hpp>
#include <dt/cbor.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/index/block-meta.hpp>
#include <dt/index/pay-ref.hpp>
#include <dt/index/stake-ref.hpp>
#include <dt/index/tx.hpp>
#include <dt/index/txo-use.hpp>
#include <dt/indexer.hpp>
#include <dt/json.hpp>
#include <dt/scheduler.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo {
    struct history_mock_block: cardano::block_base {
        history_mock_block(const index::block_meta::item &block_meta, const cbor_value &tx, uint64_t tx_offset)
            : cardano::block_base { tx, block_meta.offset, block_meta.era, tx }, _block_meta { block_meta }, _tx { tx }, _tx_offset { tx_offset }
        {
        }

        cardano_hash_32 hash() const override
        {
            throw cardano_error("internal error: hash() unsupported for partial blocks!");
        }

        const cbor_buffer &prev_hash() const override
        {
            throw cardano_error("internal error: prev_hash() unsupported for partial blocks!");
        }

        uint64_t height() const override
        {
            throw cardano_error("internal error: height() unsupported for partial blocks!");
        }

        const cardano::slot slot() const override
        {
            return cardano::slot { _block_meta.slot };
        }

        uint64_t value_offset(const cbor_value &v) const override
        {
            if (&v != &_tx)
                throw cardano_error("internal error: value_offset can be computed only for the referenced tx value!");
            return _tx_offset;
        }
    private:
        const index::block_meta::item &_block_meta;
        const cbor_value &_tx;
        uint64_t _tx_offset;
    };

    struct transaction_output {
        uint64_t use_offset = 0;
        uint16_t out_idx = 0;
        cardano::tx_size use_size {};
        cardano::amount amount {};
        cardano::multi_balance assets {};
    };

    struct transaction_input {
        uint64_t tx_offset = 0;
        const transaction_output *output = nullptr;
    };

    struct transaction {
        std::vector<transaction_output> outputs {};
        std::vector<transaction_input> inputs {};
        cardano::tx_size size {};
        cardano_hash_32 hash {};
        cardano::slot slot {};

        bool operator<(const auto &b) const
        {
            return slot < b.slot;
        }

        cardano::multi_balance_change balance_change() const
        {
            cardano::multi_balance_change changes {};
            for (const auto &out: outputs) {
                changes["ADA"] += out.amount;
                for (const auto &[asset_name, amount]: out.assets) {
                    changes[asset_name] += amount;
                }
            }
            for (const auto &in: inputs) {
                changes["ADA"] -= (int64_t)in.output->amount;
                for (const auto &[asset_name, amount]: in.output->assets) {
                    changes[asset_name] -= amount;
                }
            }
            return changes;
        }

        inline json::object to_json() const
        {
            json::object j {
                { "hash", fmt::format("{}", hash.span()) },
                { "slot", slot.to_json() },
                { "balanceChange", fmt::format("{}", balance_change()) },
                { "spentInputs", inputs.size() },
                { "newOutputs", outputs.size() }
            };
            return j;
        }
    };

    struct transaction_map: std::map<uint64_t, transaction> {
        using std::map<uint64_t, transaction>::map;

        inline json::array to_json(size_t offset=0, size_t max_items=1000) const
        {
            size_t end_offset = offset + max_items;
            if (end_offset > size())
                end_offset = size();
            json::array txs {};
            // transactions are returned in descending order!
            size_t i = 0;
            for (const auto &[cr_offset, tx]: *this | std::views::reverse) {
                if (i >= offset)
                    txs.emplace_back(tx.to_json());
                if (++i >= end_offset)
                    break;
            }
            return txs;
        }
    };

    struct reconstructor;

    template<typename T>
    struct history {
        T id {};
        transaction_map transactions {};
        cardano::slot last_slot {};
        uint64_t num_disk_reads = 0;
        uint64_t num_idx_reads = 0;
        uint64_t total_tx_outputs = 0;
        uint64_t total_tx_outputs_unspent = 0;
        uint64_t total_utxo_balance = 0;
        cardano::multi_balance balance_assets {};
        uint64_t total_withdrawals = 0;
        bool full_history = false;

        template<typename IDX>
        bool find_incoming_txos(index::reader_multi<IDX> &ref_idx)
        {
            timer t { "find referenced tx outputs", logger::level::debug };
            IDX search_item { id };
            auto [ ref_count, ref_item ] = ref_idx.find(search_item);
            for (size_t i = 0; i < ref_count; i++) {
                auto it = transactions.emplace_hint(transactions.end(), (uint64_t)ref_item.offset, transaction { .size=ref_item.size });
                it->second.outputs.emplace_back(0, static_cast<uint16_t>(ref_item.out_idx));
                if (i < ref_count - 1)
                    ref_idx.read(ref_item);
            }
            return transactions.size() > 0;
        }

        std::vector<uint64_t> find_used_txos(scheduler &sched, const index::reader_multi_mt<index::txo_use::item> &txo_use_idx)
        {
            timer t { "identify used tx outputs", logger::level::debug };
            auto &p = progress::get();
            size_t num_txos = 0;
            std::vector<uint64_t> txo_tasks {};
            txo_tasks.reserve(transactions.size());
            for (const auto &it: transactions) {
                txo_tasks.emplace_back(it.first);
                num_txos += it.second.outputs.size();
            }
            if (transactions.size() < 100000)
                _find_used_txos_small(p, sched, txo_tasks, txo_use_idx);
            else
                _find_used_txos_large(p, sched, num_txos, txo_use_idx);
            p.update("find spent txos", 1.0);
            p.inform();
            return txo_tasks;
        }

        void add_spending_txs(std::vector<uint64_t> &txo_tasks)
        {
            timer t { "add spending transactions", logger::level::debug };
            // use txo_tasks because txos map is being updated in this loop
            for (auto tx_off: txo_tasks) {
                auto &txo_item = transactions.at(tx_off);
                for (const auto &out: txo_item.outputs) {
                    if (out.use_offset != 0) {
                        auto it = transactions.emplace_hint(transactions.end(), out.use_offset, transaction { .size=out.use_size });
                        it->second.inputs.emplace_back(tx_off, &out);
                    }
                }
            }
        }

        inline void fill_raw_tx_data(scheduler &sched, chunk_registry &cr, const reconstructor &r, const bool spending_only=false);

        void compute_balances()
        {
            timer t { "compute account balance", logger::level::debug };
            for (const auto &[offset, tx]: transactions) {
                for (const auto &out: tx.outputs) {
                    total_tx_outputs++;
                    if (out.use_offset != 0) continue;
                    total_tx_outputs_unspent++;
                    total_utxo_balance += out.amount;
                    for (const auto &[asset_name, amount]: out.assets) {
                        balance_assets[asset_name] += amount;
                    }
                }
            }
        }

        cardano::amount utxo_balance() const
        {
            return cardano::amount { total_utxo_balance };
        }

        uint64_t reward_withdrawals() const
        {
            return total_withdrawals;
        }

        inline json::object to_json(size_t max_items=1000) const
        {
            return json::object {
                { "id", id.to_json() },
                { "txCount", transactions.size() },
                { "balance", fmt::format("{}", cardano::amount { total_utxo_balance }) },
                { "assetCount", balance_assets.size() },
                { "assets", balance_assets.to_json(0, max_items) },
                { "withdrawals", total_withdrawals },
                { "transactions", transactions.to_json(0, max_items) }
            };
        }

    private:
        struct parse_task {
            chunk_registry::chunk_info chunk {};
            std::vector<typename transaction_map::value_type *> tasks {};
        };
        using parse_tasks = std::map<uint64_t, parse_task>;

        void _find_used_txos_small(progress &p, scheduler &sched, std::vector<uint64_t> &txo_tasks, const index::reader_multi_mt<index::txo_use::item> &txo_use_idx)
        {
            size_t num_parts = sched.num_workers();
            std::atomic_size_t num_ready { 0 };
            sched.on_result("search-txo-use", [&](const auto &res) {
                if (res.type() == typeid(scheduled_task_error))
                    return;
                auto task_n_reads = std::any_cast<size_t>(res);
                num_disk_reads += task_n_reads;
                num_idx_reads += task_n_reads;
            });
            for (size_t i = 0; i < num_parts; ++i) {
                size_t start_idx = i * txo_tasks.size() / num_parts;
                size_t end_idx = (i + 1) * txo_tasks.size() / num_parts;
                sched.submit("search-txo-use", 100, [this, start_idx, end_idx, &txo_tasks, &txo_use_idx, &p, &num_ready]() {
                    auto txo_use_data = txo_use_idx.init_thread();
                    index::txo_use::item search_item {};
                    for (size_t j = start_idx; j < end_idx; ++j) {
                        auto &txo_item = transactions.at(txo_tasks[j]);
                        search_item.hash = txo_item.hash;
                        for (auto &out: txo_item.outputs) {
                            search_item.out_idx = out.out_idx;
                            auto [ use_count, use_item ] = txo_use_idx.find(search_item, txo_use_data);
                            if (use_count > 0) {
                                if (use_count > 1)
                                    throw error("internal error: multiple txo-use entries for the same tx offset {}!", txo_tasks[j]);
                                out.use_offset = use_item.offset;
                                out.use_size = use_item.size;
                            }
                        }
                        if (num_ready.fetch_add(1) % 1000 == 0) {
                            p.update("find spent txos", ++num_ready, transactions.size());
                            p.inform();
                        }
                    }
                    return txo_use_data.num_reads;
                });
            }
            sched.process(false);
        }

        void _find_used_txos_large(progress &p, scheduler &sched, size_t num_txos, const index::reader_multi_mt<index::txo_use::item> &txo_use_idx)
        {
            std::atomic_size_t num_ready { 0 };
            sched.on_result("search-txo-use", [&](const auto &res) {
                if (res.type() == typeid(scheduled_task_error))
                    return;
                auto task_n_reads = std::any_cast<size_t>(res);
                num_disk_reads += task_n_reads;
                num_idx_reads += task_n_reads;
            });
            size_t num_parts = txo_use_idx.num_parts();
            for (size_t pi = 0; pi < num_parts; ++pi) {
                sched.submit("search-txo-use", 100, [this, pi, num_txos, &txo_use_idx, &p, &num_ready]() {
                    auto txo_use_data = txo_use_idx.init_thread(pi);
                    index::txo_use::item item {};
                    while (txo_use_idx.read_part(pi, item, txo_use_data)) {
                        auto it = transactions.find(item.offset);
                        if (it == transactions.end())
                            continue;
                        auto &txo_item = it->second;
                        for (auto &out: txo_item.outputs) {
                            if (item.out_idx != out.out_idx)
                                continue;
                            out.use_offset = item.offset;
                            out.use_size = item.size;
                            if (num_ready.fetch_add(1) % 1000 == 0) {
                                p.update("find spent txos", ++num_ready, num_txos);
                                p.inform();
                            }
                        }
                    }
                    return txo_use_data.num_reads;
                });
            }
            sched.process(false);
        }
    };

    struct reconstructor {
        struct find_tx_res {
            uint64_t offset = 0;
            cbor_value tx_raw {};
            index::block_meta::item block_info {};

            explicit operator bool() const
            {
                return offset > 0;
            }
        };

        reconstructor(scheduler &sched, chunk_registry &cr)
            : _sched { sched }, _cr { cr }, _idx_dir { indexer::incremental::storage_dir(_cr.data_dir().string()) },
                _stake_ref_idx { indexer::multi_reader_paths(_idx_dir.string(), "stake-ref") },
                _pay_ref_idx { indexer::multi_reader_paths(_idx_dir.string(), "pay-ref") },
                _tx_idx { indexer::multi_reader_paths(_idx_dir.string(), "tx") },
                _txo_use_idx { indexer::multi_reader_paths(_idx_dir.string(), "txo-use") },
                _block_index {}
        {
            index::reader_multi<index::block_meta::item> block_meta_idx { indexer::multi_reader_paths(_idx_dir.string(), "block-meta") };
            _block_index.reserve(block_meta_idx.size());
            index::block_meta::item item {};
            while (block_meta_idx.read(item)) {
                _block_index.emplace_back(std::move(item));
            }
        }

        uint64_t last_slot() const
        {
            uint64_t last_slot = 0;
            if (_block_index.size() > 0) last_slot = _block_index.rbegin()->slot;
            return last_slot;
        }

        const index::block_meta::item &find_block(uint64_t tx_offset) const {
            auto bi_it = lower_bound(_block_index.begin(), _block_index.end(), tx_offset, [](const auto &b, size_t off) { return b.offset + b.size - 1 < off; });
            if (bi_it == _block_index.end())
                throw error("unknown offset: {}!", tx_offset);
            if (!(tx_offset >= bi_it->offset && tx_offset < bi_it->offset + bi_it->size))
                throw error("internal error block metadata does not match the transaction!");
            return *bi_it;
        }

        find_tx_res find_tx(const buffer &tx_hash)
        {
            find_tx_res res {};
            auto [ txo_count, txo_item ] = _tx_idx.find(index::tx::item { tx_hash });
            if (txo_count == 0) return res;
            res.offset = txo_item.offset;
            res.block_info = find_block(txo_item.offset);
            _cr.read(txo_item.offset, res.tx_raw);
            return res;
        }

        history<stake_ident> find_stake_balance(const stake_ident &stake_id)
        {
            return _balance(_stake_ref_idx, stake_id);
        }

        history<stake_ident> find_stake_history(const stake_ident &stake_id)
        {
            return _history(_stake_ref_idx, stake_id);
        }

        history<pay_ident> find_pay_history(const pay_ident &pay_id)
        {
            return _history(_pay_ref_idx, pay_id);
        }

    private:
        scheduler &_sched;
        chunk_registry &_cr;
        const std::filesystem::path _idx_dir;
        index::reader_multi<index::stake_ref::item> _stake_ref_idx;
        index::reader_multi<index::pay_ref::item> _pay_ref_idx;
        index::reader_multi<index::tx::item> _tx_idx;
        index::reader_multi_mt<index::txo_use::item> _txo_use_idx;
        std::vector<index::block_meta::item> _block_index;

        template<typename IDX, typename ID>
        const history<ID> _history(index::reader_multi<IDX> &ref_idx, const ID &id)
        {
            timer t { "history reconstruction", logger::level::debug };
            progress_guard pg { "fetch incoming txos", "find spent txos", "load spent txo data" };
            history<ID> hist { id };
            if (_block_index.size() == 0)
                return hist;
            const auto &last_block = *_block_index.rbegin();
            hist.last_slot = last_block.slot;
            if (!hist.find_incoming_txos(ref_idx))
                return hist;
            hist.fill_raw_tx_data(_sched, _cr, *this);
            {
                auto txo_tasks = hist.find_used_txos(_sched, _txo_use_idx);
                hist.add_spending_txs(txo_tasks);
            }
            hist.fill_raw_tx_data(_sched, _cr, *this, true);
            hist.compute_balances();
            hist.full_history = true;
            return hist;
        }

        template<typename IDX, typename ID>
        const history<ID> _balance(index::reader_multi<IDX> &ref_idx, const ID &id)
        {
            return _history(ref_idx, id);
        }
    };

    template<typename T>
    inline void history<T>::fill_raw_tx_data(scheduler &sched, chunk_registry &cr, const reconstructor &r, const bool spending_only)
    {
        timer t1 { "fill_raw_tx_data - full", logger::level::debug };
        const std::string progress_id { spending_only ? "load spent txo data" : "fetch incoming txos" };
        // group txos by their chunk based on their offsets
        parse_tasks chunk_tasks {};
        for (auto &tx_it: transactions) {
            if (spending_only && tx_it.second.outputs.size() > 0)
                continue;
            const auto &chunk = cr.find(tx_it.first);
            auto [task_it, created] = chunk_tasks.emplace(chunk.offset, parse_task {});
            if (created) task_it->second.chunk = chunk;
            task_it->second.tasks.emplace_back(&tx_it);
        }

        timer t2 { fmt::format("fill_raw_tx_data - {} load and parse tasks", chunk_tasks.size()), logger::level::debug };
        // extract transaction data
        auto &p = progress::get();
        if (!chunk_tasks.empty()) {
            size_t num_ready = 0;
            sched.on_result("parse-chunk", [&](const auto &) {
                p.update(progress_id, ++num_ready, chunk_tasks.size());
                p.inform();
            });
            for (auto &[chunk_offset, chunk_info]: chunk_tasks) {
                sched.submit("parse-chunk", 100, [&]() {
                    size_t updates = 0;
                    auto data = file::read(cr.full_path(chunk_info.chunk.rel_path()));
                    buffer buf { data };
                    cbor_value tx_raw {};
                    for (auto tx_ptr: chunk_info.tasks) {
                        auto &[tx_offset, tx_item] = *tx_ptr;
                        if (tx_offset < chunk_offset) throw error("task offset: {} < chunk_offset: {}!", tx_offset, chunk_offset);
                        size_t tx_size = (size_t)tx_item.size;
                        size_t tx_chunk_offset = tx_offset - chunk_offset;
                        // tx_size is imprecise so bound it down to the chunk size
                        if (tx_size > buf.size() - tx_chunk_offset) tx_size = buf.size() - tx_chunk_offset;
                        auto tx_buf = buf.subbuf(tx_chunk_offset, tx_size);
                        cbor_parser tx_parser { tx_buf };
                        try {
                            tx_parser.read(tx_raw);
                            const index::block_meta::item &block_meta = r.find_block(tx_offset);
                            history_mock_block mock_blk { block_meta, tx_raw, tx_offset };
                            auto tx = cardano::make_tx(tx_raw, mock_blk);
                            tx_item.hash = tx->hash();
                            tx_item.slot = block_meta.slot;
                            if (tx_item.outputs.size() > 0) {
                                tx->foreach_output([&](const auto &out) {
                                    auto tx_out_it = std::lower_bound(tx_item.outputs.begin(), tx_item.outputs.end(), out.idx, [&](const auto &el, const auto &v) { return el.out_idx < v; });
                                    if (tx_out_it == tx_item.outputs.end() || tx_out_it->out_idx != out.idx) return;
                                    updates++;
                                    tx_out_it->amount = out.amount;
                                    if (out.assets != nullptr) {
                                        for (const auto &[policy_id, policy_assets]: *out.assets) {
                                            for (const auto &[asset_name, amount]: policy_assets.map()) {
                                                tx_out_it->assets[cardano::asset_name(policy_id.buf(), asset_name.buf())] = amount.uint();
                                            }
                                        }
                                    }
                                });
                            }
                        } catch (std::exception &ex) {
                            throw error("cannot parse tx at offset {} size {}: {}", tx_offset, (size_t)tx_item.size, ex.what());
                        }
                    }
                    return updates;
                });
            }
            sched.process(false);
            num_disk_reads += chunk_tasks.size();
        }            
        p.update(progress_id, 1.0);
        p.inform();
    }

}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::transaction>: formatter<size_t> {
        template<typename FormatContext>
        auto format(const auto &tx, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "slot: {}/{} hash: {} balance change: {}\n",
                tx.slot.epoch(), tx.slot, tx.hash.span(), tx.balance_change());
        }
    };

    template<typename T>
    struct formatter<daedalus_turbo::history<T>>: formatter<size_t> {
        template<typename FormatContext>
        auto format(const auto &h, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = ctx.out();
            if (h.full_history) {
                for (const auto &[offset, tx]: h.transactions)
                   out_it = fmt::format_to(out_it, "{}", tx);
            }
            out_it = fmt::format_to(out_it, "transaction outputs affecting {}: {} of them unspent: {}\n",
                h.id, h.total_tx_outputs, h.total_tx_outputs_unspent);
            out_it = fmt::format_to(out_it, "available balance without rewards: {}\n", daedalus_turbo::cardano::amount { h.utxo_balance() });
            if (h.balance_assets.size() > 0)
                out_it = fmt::format_to(out_it, "asset balances: {}\n", h.balance_assets);
            return fmt::format_to(out_it, "last indexed slot: {}, last epoch: {}, # random reads: {} of them from indices: {} ({:0.1f}%)\n",
                h.last_slot, h.last_slot.epoch(), h.num_disk_reads, h.num_idx_reads,
                h.num_disk_reads > 0 ? 100 * (double)h.num_idx_reads / h.num_disk_reads: 0.0);
        }
    };
}

#endif // !DAEDALUS_TURBO_HISTORY_HPP