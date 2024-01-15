/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 *
 * This code uses a binary dump of the ledger state produced by Cardano Node.
 * Moreover, at the moment it relies on the relative ordering of the data structures.
 * So, it can be very brittle.
 * The code has been tested with the ledger snapshot at end of epoch 432 (last slot 106012751). */
#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <random>
#include <ranges>
#include <span>
#include <sstream>
#include <string>
#include <dt/cardano.hpp>
#include <dt/cbor.hpp>
#include <dt/history.hpp>
#include <dt/util.hpp>

namespace {
    using namespace daedalus_turbo;
    namespace rv = std::ranges::views;

    struct test_error {
        stake_ident id {};
        uint64_t balance_expected = 0;
        uint64_t balance_actual = 0;
        int64_t diff = 0;
        size_t tx_count = 0;

        inline double diff_rel() const
        {
            return abs(diff) / (double)balance_expected;
        }
    };

    struct stake_item {
        stake_ident id {};
        uint64_t balance {};
    };
    using stake_list = std::vector<stake_item>;

    static void verify_sample(reconstructor &r, const stake_list &stake_dist, double min_pct, double max_pct)
    {
        timer t { "verify sample" };
        std::seed_seq seed { 0, 1, 2, 3, 4, 5 };
        std::default_random_engine rnd { seed };
        std::uniform_real_distribution<double> dist { 0.0, 1.0 };
        double cum_rel_diff = 0;
        std::vector<double> timings {};
        std::vector<test_error> errors {};
        size_t num_except = 0;

        auto sample_pct = max_pct - min_pct;
        logger::info("distribution size: {} sample size: {:0.2f}% estimated number of ids: {}",
            stake_dist.size(), sample_pct * 100, static_cast<size_t>(stake_dist.size() * sample_pct));
        size_t sample_no = 0;
        for (const auto &item: stake_dist) {
            if (min_pct > 0.0 || max_pct < 1.0) {
                auto pass = dist(rnd);
                if (pass < min_pct || pass >= max_pct)
                    continue;
            }
            sample_no++;
            try {
                timer rt { fmt::format("verify sample {}: {}", sample_no, item.id), logger::level::info };
                history h = r.find_stake_balance(item.id);
                uint64_t bal = h.utxo_balance();
                if (bal != item.balance) {
                    test_error te { item.id, item.balance, bal, (int64_t)te.balance_actual - (int64_t)te.balance_expected, h.transactions.size() };
                    logger::warn("{} the computed balance differs by {} ADA", te.id, cardano::balance_change { te.diff });
                    cum_rel_diff += te.diff_rel();
                    errors.emplace_back(std::move(te));
                }
                timings.emplace_back(rt.stop());
            } catch (std::exception &ex) {
                ++num_except;
                logger::error("sample: {} stake_id: {} message: {}", sample_no, item.id, ex.what());
            }
        }
        std::ostringstream log_msg {};
        log_msg << "correct: " << (sample_no - errors.size() - num_except) << "/" << sample_no;
        if (errors.size() > 0) {
            log_msg << ", among the incorrect the mean rel. diff is " << cum_rel_diff * 100 / errors.size() << "%";
        }
        if (num_except > 0) {
            log_msg << ", failed to reconstruct: " << num_except << " stake addresses";
        }
        log_msg << '\n';
        if (sample_no > 0) {
            log_msg << "reconstruction time" << std::fixed << std::setprecision(6)
                << " mean: " << accumulate(timings.begin(), timings.end(), (double)0.0) / timings.size() << " secs"
                << " max: " << *max_element(timings.begin(), timings.end()) << " secs"
                << " min: " << *min_element(timings.begin(), timings.end()) << " secs"
                << '\n';
        }
        sort(errors.begin(), errors.end(), [](const auto &a, const auto &b) { return a.tx_count < b.tx_count; });
        for (const auto &te: errors | rv::take(10)) {
            log_msg
                << fmt::format("{}", te.id)
                << " tx count: " << te.tx_count
                << " differs by " << te.diff / 1'000'000u << "." << abs(te.diff) % 1'000'000u << " ADA"
                << " or " << te.diff_rel() * 100 << "%"
                << '\n';
        }
        logger::info(log_msg.str());
    }

    static std::pair<stake_list, cardano::slot> parse_ledger_snapshot(const std::string &ledger_path)
    {
        timer t { "parsing ledger state" };
        auto buf = file::read(ledger_path);
        buf.shrink_to_fit();
        logger::debug("loaded {} size: {} MB", ledger_path, buf.size() / 1'000'000u);
        cbor_parser parser { buf };
        cbor_value v {};
        parser.read(v);
        static array<size_t, 7> last_slot_path { 1, 5, 1, 1, 0, 0, 0 };
        cardano::slot latest_slot = extract_value(v, last_slot_path, 0).uint();
        stake_list latest_stake_dist {};
        static array<size_t, 10> stake_latest_path { 1, 5, 1, 1, 1, 3, 1, 1, 4, 0 };
        for (const auto &[id_info, balance]: extract_value(v, stake_latest_path, 0).map()) {
            const auto &id = id_info.array();
            latest_stake_dist.emplace_back(stake_ident { id.at(1).buf(), id.at(0).uint() == 1 }, balance.uint());
        }
        return std::make_pair(std::move(latest_stake_dist), latest_slot);
    }
}

int main(int argc, char **argv)
try {
    std::ios_base::sync_with_stdio(false);
    if (argc < 3) {
        logger::error("Usage: validate-balance <data-dir> <ledger-snapshot> [<sample-ratio-max>] [<sample-ratio-min>]");
        return 1;
    }
    const std::string data_dir { argv[1] };
    const auto db_dir = data_dir + "/compressed";
    const auto idx_dir = data_dir + "/index";
    const std::string ledger_path { argv[2] };
    double min_pct = 0.0;
    double max_pct = 0.001;
    if (argc >= 4)
        max_pct = std::stod(argv[3]);
    if (argc >= 5)
        min_pct = std::stod(argv[4]);
    timer t { "complete test" };
    auto [ledger_stake_dist, ledger_slot] = parse_ledger_snapshot(ledger_path);
    scheduler sched {};
    chunk_registry cr { sched, db_dir };
    cr.init_state();
    reconstructor r { sched, cr, idx_dir };
    if (ledger_slot != r.last_slot())
        throw error("ledger last slot: {} does not match raw data last slot: {}", ledger_slot, r.last_slot());
    verify_sample(r, ledger_stake_dist, min_pct, max_pct);
} catch (std::exception &ex) {
    logger::error("exception in main: {}", ex.what());
}