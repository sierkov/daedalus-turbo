/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

/*
 * This code uses a binary dump of the ledger state made by Cardano Node.
 * Moreover, at the moment it relies on the relative ordering of the data structures.
 * So, it can be very brittle.
 * The code has been tested with the ledger snapshot at the slot number 77374448.
 */

#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <random>
#include <ranges>
#include <span>
#include <string>
#include <dt/cbor.hpp>
#include <dt/history.hpp>
#include <dt/util.hpp>

using namespace daedalus_turbo;
namespace rv = std::ranges::views;

auto &log_stream = std::cout;

struct test_error {
    array<uint8_t, 28> stake_addr;
    uint64_t balance_expected = 0;
    uint64_t balance_actual = 0;
    int64_t diff = 0;
    size_t tx_count = 0;

    inline double diff_rel() const
    {
        return abs(diff) / (double)balance_expected;
    }
};

static void sample_test_set(reconstructor &r, const cbor_map &stake, const cbor_map &stake_mark, uint64_t ledger_last_slot, size_t n_samples)
{
    if (ledger_last_slot != r.last_slot())
        throw error_fmt("ledger snapshot's slot: {} does not match raw data last slot: {}", ledger_last_slot, r.last_slot());
    std::seed_seq seed { 0, 1, 2, 3, 4, 5 };
    std::default_random_engine rnd(seed);
    std::uniform_int_distribution<size_t> dist(0, stake.size());
    double cum_rel_diff = 0;
    std::vector<double> timings;
    std::vector<test_error> errors;
    size_t num_except = 0;
    for (size_t i = 0; i < n_samples; ++i) {
        size_t stake_idx = dist(rnd);
        const cbor_map_value &item = stake[stake_idx];
        if (item.first.type != CBOR_ARRAY) throw error_fmt("expected CBOR_ARRAY as a stake key but got CBOR type: {}!", (size_t)item.first.type);
        const cbor_array &a = item.first.array();
        if (a.size() != 2) throw error_fmt("expected array with two elements but got: {}!", a.size());
        if (a[0].type != CBOR_UINT) throw error_fmt("expected the first entry to be UINT but got CBOR type: {}!", a[0].type);
        //if (a[0].uint() != 0) throw error_fmt("expected the first entry to be 0 but got: {}!", a[0].uint());
        if (a[1].type != CBOR_BYTES) throw error_fmt("expected the second entry to be BYTES but got CBOR type: {}!", a[1].type);
        const buffer &stake_addr = a[1].buf();
        try {
            timer rt("reconstruct");
            history h = r.reconstruct_raw_addr(a[1].buf());
            uint64_t bal = h.utxo_balance();
            timings.push_back(rt.stop());
            uint64_t exp_bal = item.second.uint();
            auto mark_it = find_if(stake_mark.begin(), stake_mark.end(),
                [&stake_addr](const auto &v) {
                    const cbor_array &v_a = v.first.array();
                    if (v_a.size() != 2) throw error_fmt("unexpected format for stake_mark!");
                    if (v_a[0].uint() != 1) throw error_fmt("unexpected format for stake_mark entry key part 1!");
                    if (v_a[1].type != CBOR_BYTES) throw error_fmt("unexpected format for stake_mark entry key part 2!");
                    const buffer &v_stake_addr = v_a[1].buf();
                    return v_stake_addr.size() == stake_addr.size() && memcmp(v_stake_addr.data(), stake_addr.data(), stake_addr.size());
                }
            );
            if (mark_it == stake_mark.end()) throw error_fmt("can't find stake_mark data for stake_addr!");
            if (bal != exp_bal) {
                test_error te;
                if (te.stake_addr.size() != stake_addr.size()) throw error_fmt("unexpected stake_addr.size(): {}", stake_addr.size());
                memcpy(te.stake_addr.data(), stake_addr.data(), te.stake_addr.size());
                te.balance_expected = exp_bal;
                te.balance_actual = bal;
                te.diff = (int64_t)te.balance_actual - (int64_t)te.balance_expected;
                te.tx_count = h.transactions.size();
                cum_rel_diff += te.diff_rel();
                errors.push_back(te);
            }
        } catch (std::exception &ex) {
            log_stream << "sample " << i << ", stake_addr: " << stake_addr
                << " ERROR: " << ex.what()
                << std::endl;
            ++num_except;
        }
    }
    log_stream << "correct: " << (n_samples - errors.size() - num_except) << "/" << n_samples;
    if (errors.size() > 0) {
        log_stream << ", among the incorrect the mean rel. diff is " << cum_rel_diff * 100 / errors.size() << "%";
    }
    if (num_except > 0) {
        log_stream << ", failed to reconstruct: " << num_except << " stake addresses";
    }
    log_stream << '\n';
    log_stream << "reconstruction time" << std::fixed << std::setprecision(6)
            << " mean: " << accumulate(timings.begin(), timings.end(), (double)0.0) / timings.size() << " secs"
            << " max: " << *max_element(timings.begin(), timings.end()) << " secs"
            << " min: " << *min_element(timings.begin(), timings.end()) << " secs"
            << '\n';
    sort(errors.begin(), errors.end(), [](const auto &a, const auto &b) { return a.tx_count < b.tx_count; });
    for (const auto &te: errors | rv::take(10)) {
        log_stream
            << "stake_addr: " << buffer(te.stake_addr.data(), te.stake_addr.size())
            << " tx count: " << te.tx_count
            << " differs by " << te.diff / 1'000'000u << "." << abs(te.diff) % 1'000'000u << " ADA"
            << " or " << te.diff_rel() * 100 << "%"
            << '\n';
    }
}

static void test_random_sample(reconstructor &r, const std::string &ledger_path, size_t n_samples)
{
    auto buf = read_whole_file(ledger_path);
    buf.shrink_to_fit();
    log_stream << "loaded " << ledger_path << " into RAM, size: " << buf.size() / 1'000'000u << " MB" << std::endl;

    cbor_parser parser(buf.data(), buf.size());
    
    cbor_value v;
    for (size_t num_values = 0; !parser.eof(); ++num_values) {
        parser.read(v);
        if (num_values != 0) continue;
        array<size_t, 10> stake_latest_path { 1, 5, 1, 1, 1, 3, 1, 1, 4, 0 };
        const cbor_value &stake_latest = extract_value(v, stake_latest_path, 0);
        array<size_t, 9> stake_mark_path { 1, 5, 1, 1, 1, 3, 2, 0, 0 };
        const cbor_value &stake_mark = extract_value(v, stake_mark_path, 0);
        array<size_t, 7> last_slot_path { 1, 5, 1, 1, 0, 0, 0 };
        const cbor_value &last_slot = extract_value(v, last_slot_path, 0);
        log_stream << "ledger state has been parsed, starting evaluations ..." << std::endl;
        sample_test_set(r, stake_latest.map(), stake_mark.map(), last_slot.uint(), n_samples);
    }
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        std::cerr << "Usage: validate-balance <immutabledb-path> <indices-path> <ledger-path> [<num-samples>]" << std::endl;
        return 1;
    }
    const std::string immutable_path(argv[1]);
    const std::string indices_path(argv[2]);
    const std::string ledger_path(argv[3]);
    size_t num_samples = 10000;
    if (argc == 5) num_samples = std::stoul(argv[4]);
    reconstructor r(immutable_path, indices_path);
    test_random_sample(r, ledger_path, num_samples);
}
