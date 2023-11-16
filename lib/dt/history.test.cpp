/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/cardano/type.hpp>
#include <dt/history.hpp>
#include <dt/indexer.hpp>
#include <dt/scheduler.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite history_suite = [] {
    "history"_test = [] {
        static const std::string db_dir { "./data/chunk-registry"s };
        static const std::string tmp_db_dir { "./tmp/compressed" };
        static const std::string idx_dir { "./tmp/index" };
        for (const auto &dir_path: { tmp_db_dir, idx_dir }) {
            if (std::filesystem::exists(dir_path))
                std::filesystem::remove_all(dir_path);
        }
        "simple reconstruction"_test = [] {
            scheduler sched {};
            chunk_registry src_cr { sched, db_dir };
            src_cr.init_state(false, true, false);
            auto indexers = indexer::default_list(sched, idx_dir);
            indexer::incremental idxr { sched, tmp_db_dir, indexers };
            idxr.import(src_cr);
            
            reconstructor r { sched, idxr, idx_dir };
            const auto &b1 = r.find_block(648087);
            const auto &b2 = r.find_block(648088);
            expect(b1.slot == b2.slot) << b1.slot << " " << b2.slot;
            const auto &m1 = r.find_block(652756);
            const auto &m2 = r.find_block(652756 + 665);
            expect(m1.slot == m2.slot) << m1.slot << " " << m2.slot;
            const auto &e1 = r.find_block(162'930'893);
            const auto &e2 = r.find_block(162'930'893 + 30028);
            expect(e1.slot == e2.slot) << e1.slot << " " << e2.slot;

            // known-item search
            {
                history hist = r.find_stake_history(cardano::address { cardano::address_buf { "stake1uxw70wgydj63u4faymujuunnu9w2976pfeh89lnqcw03pksulgcrg" } }.stake_id());
                expect(hist.utxo_balance() == 32'476'258'673_ull) << hist.utxo_balance();
                expect(hist.transactions.size() == 2_u) << hist.transactions.size();
            }
            
            // missing-item search
            {
                history hist = r.find_stake_history(cardano::address { cardano::address_buf { "0xE10001020304050607080910111213141516171819202122232425262728" } }.stake_id());
                expect(hist.transactions.size() == 0_u) << hist.transactions.size();
            }
        };
    };
};