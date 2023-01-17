/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
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

static const string DATA_DIR = "./data";

suite cardano_processor_test = [] {
    "cardano"_test = [] {
        "every_block"_test = [] {
            should("count blocks") = [] {
                class my_processor: public cardano_processor {
                public:
                    size_t block_count = 0;

                    void every_block(const cardano_block_context &, const cbor_value &) {
                        block_count++;
                    }
                };

                uint8_vector chunk;
                read_whole_file(DATA_DIR + "/03306.chunk", chunk);
                my_processor proc;
                cardano_parser parser(proc);
                cardano_chunk_context chunk_ctx(0);
                parser.parse_chunk(chunk_ctx, chunk);
                expect(proc.block_count == 1078_u);
            };
        };

        "every_tx"_test = [] {
            should("count transactions") = [] {
                class my_processor: public cardano_processor {
                public:
                    size_t tx_count = 0;

                    void every_tx(const cardano_tx_context &, const cbor_value &, uint64_t) {
                        tx_count++;
                    }
                };

                uint8_vector chunk;
                read_whole_file(DATA_DIR + "/03306.chunk", chunk);
                my_processor proc;
                cardano_parser parser(proc);
                cardano_chunk_context chunk_ctx(0);
                parser.parse_chunk(chunk_ctx, chunk);
                expect(proc.tx_count == 13302_u);
            };
        };

        "byron transaction inputs are ignored"_test = [] {
            should("see tx inputs") = [] {
                class my_processor: public cardano_processor {
                public:
                    uint64_t tx_in_cnt = 0;

                    void every_tx_input(const cardano_tx_input_context &, const cbor_buffer &, uint64_t) {
                        tx_in_cnt++;
                    }
                };

                uint8_vector chunk;
                read_whole_file(DATA_DIR + "/03000.chunk", chunk);
                my_processor proc;
                cardano_parser parser(proc);
                cardano_chunk_context chunk_ctx(0);
                parser.parse_chunk(chunk_ctx, chunk);
                expect(proc.tx_in_cnt == 45834_u);
            };
        };

        "non-byron transaction inputs are not ignored"_test = [] {
            should("sum inputs") = [] {
                class my_processor: public cardano_processor {
                public:
                    uint64_t tx_in_cnt = 0;                    

                    void every_tx_input(const cardano_tx_input_context &, const cbor_buffer &, uint64_t) {
                        tx_in_cnt++;
                    }
                };

                uint8_vector chunk;
                read_whole_file(DATA_DIR + "/00000.chunk", chunk);
                my_processor proc;
                cardano_parser parser(proc);
                cardano_chunk_context chunk_ctx(0);
                parser.parse_chunk(chunk_ctx, chunk);
                expect(proc.tx_in_cnt == 0_u);
            };
        };

        "blocks from all epochs"_test = [] {
            for (const auto &chunk_id: { "00000", "01000", "01400", "02000", "03000", "03306", "03427" }) {
                struct my_processor: public cardano_processor {
                    uint64_t block_cnt = 0;

                    void every_block(const cardano_block_context &/*ctx*/, const cbor_value &/*block_tuple*/)
                    {
                        block_cnt++;
                    }
                };
                uint8_vector chunk;
                read_whole_file(DATA_DIR + "/"s + chunk_id + ".chunk"s, chunk);
                my_processor proc;
                cardano_parser parser(proc);
                cardano_chunk_context chunk_ctx(0);
                parser.parse_chunk(chunk_ctx, chunk);
                expect(proc.block_cnt > 0_u);
            }
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

        "parse_address"_test = [] {
            {
                uint8_vector addr = cardano_parse_address("0xDEADBEAF");
                expect(addr.size() == 4_u);
                expect(addr[0] == 0xDE);
                expect(addr[1] == 0xAD);
                expect(addr[2] == 0xBE);
                expect(addr[3] == 0xAF);
            }
            {
                uint8_t exp[] = {
                    0xf1, 0xc3, 0x7b, 0x1b, 0x5d, 0xc0, 0x66, 0x9f, 0x1d, 0x3c, 0x61, 0xa6, 0xfd, 0xdb, 0x2e, 0x8f,
                    0xde, 0x96, 0xbe, 0x87, 0xb8, 0x81, 0xc6, 0x0b, 0xce, 0x8e, 0x8d, 0x54, 0x2f
                };
                uint8_vector addr = cardano_parse_address("stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5");
                expect(addr.size() == sizeof(exp));
                expect(memcmp(addr.data(), exp, sizeof(exp)) == 0_i);
            }
        };
    };

};
