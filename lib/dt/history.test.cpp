#include <boost/ut.hpp>
#include <dt/history.hpp>
#include <dt/indexer.hpp>
#include <dt/logger.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

const string DATA_DIR = "./data"s;

suite history_suite = [] {
    "history"_test = [] {
        logger_null logger;
        indexer idxr(logger);
        idxr.index(DATA_DIR, DATA_DIR, 1);
        reconstructor r(DATA_DIR, DATA_DIR, false);
        uint8_vector addr = cardano_parse_address("stake1uxw70wgydj63u4faymujuunnu9w2976pfeh89lnqcw03pksulgcrg");
        history hist = r.reconstruct(addr);
        expect(hist.transactions.size() == 3_u) << hist.transactions.size();
        expect(hist.utxo_balance() == 32'476'258'673_ull) << hist.utxo_balance();
    };
};
