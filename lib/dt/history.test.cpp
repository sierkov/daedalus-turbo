#include <boost/ut.hpp>

#include <dt/history.hpp>
#include <dt/indexer.hpp>
#include <dt/logger.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

const std::string DATA_DIR = "./data"s;

suite history_suite = [] {
    "history"_test = [] {
        "simple reconstruction"_test = [] {
            logger_null logger;
            indexer idxr(logger);
            idxr.index(DATA_DIR, DATA_DIR, 1);
            reconstructor r(DATA_DIR, DATA_DIR, false);
            uint8_vector addr = cardano_parse_address("stake1uxw70wgydj63u4faymujuunnu9w2976pfeh89lnqcw03pksulgcrg");
            history hist = r.reconstruct(addr);
            expect(hist.transactions.size() == 3_u) << hist.transactions.size();
            expect(hist.utxo_balance() == 32'476'258'673_ull) << hist.utxo_balance();
            const block_item &b1 = r.find_block(648087);
            const block_item &b2 = r.find_block(648088);
            expect(b1.slot == b2.slot) << b1.slot << " " << b2.slot;
            const block_item &m1 = r.find_block(652756);
            const block_item &m2 = r.find_block(652756 + 665);
            expect(m1.slot == m2.slot) << m1.slot << " " << m2.slot;
            const block_item &e1 = r.find_block(162'930'893);
            const block_item &e2 = r.find_block(162'930'893 + 30028);
            expect(e1.slot == e2.slot) << e1.slot << " " << e2.slot;
        };
    };
};
