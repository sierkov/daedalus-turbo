/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/type.hpp>
#include <dt/history.hpp>
#include <dt/indexer.hpp>
#include <dt/scheduler.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite history_suite = [] {
    "history"_test = [] {
        static const std::string src_dir { "./data/chunk-registry"s };
        static const std::string data_dir { "./tmp" };
        for (const auto &e: std::filesystem::directory_iterator { data_dir }) {
            if (e.is_directory())
                std::filesystem::remove_all(e.path());
        }
        "simple reconstruction"_test = [] {
            chunk_registry src_cr { src_dir, false };
            indexer::incremental idxr { indexer::default_list(data_dir), data_dir, false };
            idxr.import(src_cr);
            
            reconstructor r { idxr };
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
                history hist = r.find_history(cardano::address { cardano::address_buf { "stake1uxw70wgydj63u4faymujuunnu9w2976pfeh89lnqcw03pksulgcrg" } }.stake_id());
                expect(hist.utxo_balance() == 32'476'258'673_ull) << hist.utxo_balance();
                expect(hist.transactions.size() == 2_u) << hist.transactions.size();
            }
            
            // missing-item search
            {
                history hist = r.find_history(cardano::address { cardano::address_buf { "0xE10001020304050607080910111213141516171819202122232425262728" } }.stake_id());
                expect(hist.transactions.size() == 0_u) << hist.transactions.size();
            }
        };
    };
};