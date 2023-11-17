/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/cardano.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite cardano_common_suite = [] {
    "cardano::common"_test = [] {
        "amount"_test = [] {
            {
                cardano::amount a { 1'010 };
                std::string a_text { "0.001010 ADA" };
                expect(format("{}", a) == a_text);
                std::ostringstream ss;
                ss << a;
                expect(ss.str() == a_text);
            }
            {
                cardano::amount a { 678'900'012'345 };
                std::string a_text { "678900.012345 ADA" };
                expect(format("{}", a) == a_text);
                std::ostringstream ss;
                ss << a;
                expect(ss.str() == a_text);
            }
        };
        "slot"_test = [] {
            expect(cardano::slot {} == 0);

            cardano::slot byron_1 { 7 };
            expect(byron_1 == 7);
            expect(byron_1.epoch() == 0);
            expect(byron_1.utc_month() == "2017-09") << byron_1.utc_month();
            expect(byron_1.unixtime() == 1506203231) << byron_1.unixtime(); // 1596051751

            cardano::slot byron_2 { 2'158'515 };
            expect(byron_2 == 2158515);
            expect(byron_2.epoch() == 99);
            expect(byron_2.utc_month() == "2019-02") << byron_2.utc_month();
            expect(byron_2.unixtime() == 1549373391) << byron_2.unixtime();

            cardano::slot shelley_1 { 8'812'978 };
            expect(shelley_1 == 8'812'978);
            expect(shelley_1.epoch() == 218);
            expect(shelley_1.utc_month() == "2020-09") << shelley_1.utc_month();
            expect(shelley_1.unixtime() == 1600379269) << shelley_1.unixtime();

            cardano::slot babbage_1 { 101'142'576 };
            expect(babbage_1 == 101142576ULL);
            expect(babbage_1.epoch() == 431);
            expect(babbage_1.utc_month() == "2023-08") << babbage_1.utc_month();
            expect(babbage_1.unixtime() == 1692708867) << babbage_1.unixtime();

            expect(cardano::slot { 21600 }.epoch() == 1);
            expect(cardano::slot { 2981652 }.epoch() == 138);
            expect(cardano::slot { 4449600 }.epoch() == 206);
            expect(cardano::slot { 4492800 }.epoch() == 208);
            expect(cardano::slot { 75745595 }.epoch() == 372);
            expect(cardano::slot { 75772873 }.epoch() == 373);
        };
        "tx_size"_test = [] {
            for (const auto &[sz, exp_sz]: {
                std::pair { 0U, 0U },
                std::pair { 55U, 256U },
                std::pair { 256U, 256U },
                std::pair { 512U, 512U },
                std::pair { 600U, 768U },
                std::pair { 16384U, 16384U },
                std::pair { 16385U, 16640U },
                std::pair { 32768U, 32768U },
                std::pair { 32769U, 33024U },
                std::pair { 65200U, 65280U },
                std::pair { 65280U, 65280U }
            }) {
                expect(cardano::tx_size { sz } == exp_sz) << "tx_size" << sz << "=>" << cardano::tx_size { sz } << "!=" << exp_sz;
            }
            expect(boost::ut::throws<error>([]() { cardano::tx_size { 655281 }; }));
            expect(boost::ut::throws<error>([]() { cardano::tx_size { 65536 }; }));
            expect(boost::ut::throws<error>([]() { cardano::tx_size { 100000 }; }));
        };
        "tx_out_idx"_test = [] {
            for (const auto &[idx, exp_idx]: {
                std::pair { 0U, 0U },
                std::pair { 55U, 55U },
                std::pair { 256U, 256U },
                std::pair { 600U, 600U },
                std::pair { 16384U, 16384U },
                std::pair { 32769U, 32769U },
                std::pair { 65200U, 65200U },
                std::pair { 65535U, 65535U }
            }) {
                expect(cardano::tx_out_idx { idx } == exp_idx) << "tx_out_idx" << idx << "=>" << cardano::tx_out_idx { idx } << "!=" << exp_idx;
            }
            expect(boost::ut::throws<error>([]() { cardano::tx_out_idx { 65536 }; }));
            expect(boost::ut::throws<error>([]() { cardano::tx_out_idx { 100000 }; }));
        };
        "stake_deleg"_test = [] {
            auto chunk = file::read("./data/chunk-registry/immutable/9C5C0267DCA941851D0330E19B91712618EB6DB4BF17E458BCF00829F84CF3CF.zstd");
            cbor_parser parser { chunk };
            cbor_value block_tuple {};
            size_t num_delegs = 0;
            while (!parser.eof()) {
                parser.read(block_tuple);
                auto blk = cardano::make_block(block_tuple, block_tuple.data - chunk.data());
                blk->foreach_tx([&](const auto &tx) {
                    tx.foreach_stake_deleg([&](const auto &) {
                        num_delegs++;
                    });
                });
            }
            expect(num_delegs == 208_u);
        };
        "pool_reg"_test = [] {
            auto chunk = file::read("./data/chunk-registry/immutable/DF597E3FA352A7BD2F021733804C33729EBAA3DCAA9C0643BD263EFA09497B03.zstd");
            cbor_parser parser { chunk };
            cbor_value block_tuple {};
            size_t num_regs = 0;
            while (!parser.eof()) {
                parser.read(block_tuple);
                auto blk = cardano::make_block(block_tuple, block_tuple.data - chunk.data());
                blk->foreach_tx([&](const auto &tx) {
                    tx.foreach_pool_reg([&](const auto &) {
                        num_regs++;
                    });
                });
            }
            expect(num_regs == 2_u);
        };
        "extract_epoch"_test = [] {
            expect(cardano::extract_epoch("./data/chunk-registry/immutable/526D236112DB8E38E66F37D330C85AFE0C268D81DF853DDDE4E88551EB9B0637.zstd") == 0_ull);
            expect(cardano::extract_epoch("./data/chunk-registry/immutable/DF597E3FA352A7BD2F021733804C33729EBAA3DCAA9C0643BD263EFA09497B03.zstd") == 222_ull);
            expect(cardano::extract_epoch("./data/chunk-registry/immutable/BA19B67C08713E930BF42C2CA5DE03EA7679C07198611062235F89B267B2E558.zstd") == 247_ull);
            expect(cardano::extract_epoch("./data/chunk-registry/immutable/7C46426DDF73FFFAD5970B0F1C0983A3A98F5AC3EC080BDFB59DBF86AC1AE9A1.zstd") == 267_ull);
            expect(cardano::extract_epoch("./data/chunk-registry/immutable/1A6CC809A5297CFC502B229B4CD31A9B00B71638CEAEDE45409D4F0EBC534356.zstd") == 297_ull);
            expect(cardano::extract_epoch("./data/chunk-registry/immutable/47F62675C9B0161211B9261B7BB1CF801EDD4B9C0728D9A6C7A910A1581EED41.zstd") == 362_ull);
            expect(cardano::extract_epoch("./data/chunk-registry/immutable/9C5C0267DCA941851D0330E19B91712618EB6DB4BF17E458BCF00829F84CF3CF.zstd") == 368_ull);
        };
    };  
};