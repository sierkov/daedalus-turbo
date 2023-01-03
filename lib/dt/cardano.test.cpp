/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <boost/ut.hpp>
#include <dt/cardano.hpp>
#include <dt/util.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

static const string data_dir = "./data";

suite cardano_processor_test = [] {

    "every_block"_test = [] {
        should("count blocks") = [] {
            class MyProcessor: public cardano_processor {
            public:
                size_t block_count = 0;

                void every_block(const cardano_block_context &, const cbor_value &) {
                    block_count++;
                }
            };

            bin_string chunk;
            read_whole_file(data_dir + "/03306.chunk", chunk);
            MyProcessor proc;
            cardano_parser parser(proc);
            cardano_chunk_context chunk_ctx(0);
            parser.parse_chunk(chunk_ctx, chunk);
            expect(proc.block_count == 1078_u);
        };
    };

    "every_tx"_test = [] {
        should("count transactions") = [] {
            class MyProcessor: public cardano_processor {
            public:
                size_t tx_count = 0;

                void every_tx(const cardano_tx_context &, const cbor_value &, uint64_t) {
                    tx_count++;
                }
            };

            bin_string chunk;
            read_whole_file(data_dir + "/03306.chunk", chunk);
            MyProcessor proc;
            cardano_parser parser(proc);
            cardano_chunk_context chunk_ctx(0);
            parser.parse_chunk(chunk_ctx, chunk);
            expect(proc.tx_count == 13302_u);
        };
    };

    "byron transaction inputs are ignored"_test = [] {
        should("see tx inputs") = [] {
            class MyProcessor: public cardano_processor {
            public:
                uint64_t tx_in_cnt = 0;

                void every_tx_input(const cardano_tx_input_context &, const cbor_buffer &, uint64_t) {
                    tx_in_cnt++;
                }
            };

            bin_string chunk;
            read_whole_file(data_dir + "/03000.chunk", chunk);
            MyProcessor proc;
            cardano_parser parser(proc);
            cardano_chunk_context chunk_ctx(0);
            parser.parse_chunk(chunk_ctx, chunk);
            expect(proc.tx_in_cnt == 45834_u);
        };
    };

    "non-byron transaction inputs are not ignored"_test = [] {
        should("sum inputs") = [] {
            class MyProcessor: public cardano_processor {
            public:
                uint64_t tx_in_cnt = 0;

                void every_tx_input(const cardano_tx_input_context &, const cbor_buffer &, uint64_t) {
                    tx_in_cnt++;
                }
            };

            bin_string chunk;
            read_whole_file(data_dir + "/00000.chunk", chunk);
            MyProcessor proc;
            cardano_parser parser(proc);
            cardano_chunk_context chunk_ctx(0);
            parser.parse_chunk(chunk_ctx, chunk);
            expect(proc.tx_in_cnt == 0_u);
        };
    };

    "epoch_to_slot_calc"_test = [] {
        should("work for slot 21600") = [] {
            uint64_t slot = 21600;
            expect(slot_to_epoch(slot) == 1);
            expect(slot_to_epoch_slot(slot) == 0);
        };
        should("work for slot 2981652") = [] {
            uint64_t slot = 2981652;
            expect(slot_to_epoch(slot) == 138);
            expect(slot_to_epoch_slot(slot) == 852);
        };
        should("work for slot 4449600") = [] {
            uint64_t slot = 4449600;
            expect(slot_to_epoch(slot) == 206);
            expect(slot_to_epoch_slot(slot) == 0);
        };
        should("work for slot 4471199") = [] {
            uint64_t slot = 4471199;
            expect(slot_to_epoch(slot) == 206);
            expect(slot_to_epoch_slot(slot) == 21599);
        };
        should("work for slot 4471200") = [] {
            uint64_t slot = 4471200;
            expect(slot_to_epoch(slot) == 207);
            expect(slot_to_epoch_slot(slot) == 0);
        };
        should("work for slot 4492799") = [] {
            uint64_t slot = 4492799;
            expect(slot_to_epoch(slot) == 207);
            expect(slot_to_epoch_slot(slot) == 21599);
        };
        should("work for slot 4492800") = [] {
            uint64_t slot = 4492800;
            expect(slot_to_epoch(slot) == 208);
            expect(slot_to_epoch_slot(slot) == 0);
        };
        should("work for slot 4924780") = [] {
            uint64_t slot = 4924780;
            expect(slot_to_epoch(slot) == 208);
            expect(slot_to_epoch_slot(slot) == 431980);
        };
        should("work for slot 75745595") = [] {
            uint64_t slot = 75745595;
            expect(slot_to_epoch(slot) == 372);
            expect(slot_to_epoch_slot(slot) == 404795);
        };
        should("work for slot 75772873") = [] {
            uint64_t slot = 75772873;
            expect(slot_to_epoch(slot) == 373);
            expect(slot_to_epoch_slot(slot) == 73);
        };
    };

};
