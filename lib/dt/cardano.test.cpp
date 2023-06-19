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

using namespace boost::ut;
using namespace daedalus_turbo;

static const std::string DATA_DIR = "./data";

suite cardano_processor_test = [] {
    "cardano"_test = [] {
        "every_block"_test = [] {
            struct my_processor: public cardano_processor {
                size_t block_count = 0;

                void every_block(const cardano_block_context &, const cbor_value &, const cbor_array &) {
                    block_count++;
                }
            } proc;
            cardano_parse_file(DATA_DIR + "/03306.chunk", proc);
            expect(proc.block_count == 1078_u);
        };

        "every_tx"_test = [] {
            should("count transactions") = [] {
                struct my_processor: public cardano_processor {
                    size_t tx_count = 0;

                    void every_tx(const cardano_tx_context &, const cbor_value &, uint64_t) {
                        tx_count++;
                    }
                } proc;
                cardano_parse_file(DATA_DIR + "/03306.chunk", proc);
                expect(proc.tx_count == 13302_u);
            };
        };

        "byron transaction inputs are ignored"_test = [] {
            should("see tx inputs") = [] {
                struct my_processor: public cardano_processor {
                    uint64_t tx_in_cnt = 0;

                    void every_tx_input(const cardano_tx_input_context &, const cbor_buffer &, uint64_t) {
                        tx_in_cnt++;
                    }
                } proc;
                cardano_parse_file(DATA_DIR + "/03000.chunk", proc);
                expect(proc.tx_in_cnt == 45834_u);
            };
        };

        "non-byron transaction inputs are not ignored"_test = [] {
            should("sum inputs") = [] {
                struct my_processor: public cardano_processor {
                    uint64_t tx_in_cnt = 0;                    

                    void every_tx_input(const cardano_tx_input_context &, const cbor_buffer &, uint64_t) {
                        tx_in_cnt++;
                    }
                } proc;
                cardano_parse_file(DATA_DIR + "/00000.chunk", proc);
                expect(proc.tx_in_cnt == 0_u);
            };
        };

        "blocks from all epochs"_test = [] {
            for (const auto &chunk_id: { "00000", "01000", "01400", "02000", "03000", "03306", "03427" }) {
                struct my_processor: public cardano_processor {
                    uint64_t block_cnt = 0;

                    void every_block(const cardano_block_context &/*ctx*/, const cbor_value &/*block_tuple*/, const cbor_array &)
                    {
                        block_cnt++;
                    }
                } proc;
                cardano_parse_file(DATA_DIR + "/"s + chunk_id + ".chunk"s, proc);
                expect(proc.block_cnt > 0_u);
            }
        };

        "header_hash"_test = [] {
            struct my_processor: public cardano_processor {
                bool first = true;
                cardano_hash_32 first_hash;
                cardano_hash_32 last_hash;

                void every_block(const cardano_block_context &ctx, const cbor_value &, const cbor_array &) {
                    if (first) {
                        first_hash = ctx.header_hash;
                        first = false;
                    }
                    last_hash = ctx.header_hash;
                }
            } proc;
            cardano_parse_file(DATA_DIR + "/03306.chunk", proc);
            cardano_hash_32 hash_1 { 0x98, 0x92, 0x64, 0xd8, 0x49, 0x3c, 0xea, 0x5f, 0xd7, 0x47, 0x7a, 0x12, 0xa2, 0x82, 0x5a, 0x6a,
                                     0x92, 0x45, 0xaf, 0xac, 0xb6, 0xa8, 0xd2, 0x22, 0xd6, 0x37, 0x0b, 0xec, 0xe2, 0x49, 0x71, 0x56 };
            expect(hash_1 == proc.first_hash);
            cardano_hash_32 hash_2 { 0xef, 0x28, 0x2e, 0x85, 0xa8, 0xef, 0x8a, 0x9c, 0x31, 0xd2, 0x55, 0xc7, 0x36, 0xf5, 0x2a, 0xa0,
                                     0xd5, 0x2b, 0xea, 0x26, 0x02, 0x76, 0xbf, 0x2f, 0xb4, 0xaf, 0x3a, 0xdb, 0x70, 0x0d, 0x0f, 0x1b };
            expect(hash_2 == proc.last_hash);
        };

        "pool_hash"_test = [] {
            struct my_processor: public cardano_processor {
                bool first = true;
                cardano_hash_28 first_hash;
                cardano_hash_28 last_hash;

                void every_block(const cardano_block_context &ctx, const cbor_value &, const cbor_array &) {
                    if (first) {
                        first_hash = ctx.pool_hash;
                        first = false;
                    }
                    last_hash = ctx.pool_hash;
                }
            } proc;
            cardano_parse_file(DATA_DIR + "/03306.chunk", proc);
            cardano_hash_28 hash_1 { 0xfd, 0xc5, 0x54, 0x42, 0xd4, 0xc8, 0x9b, 0xfa, 0x42, 0xbb, 0x62, 0xac, 0x64, 0x0e, 0xd7, 0x10,
                                     0xaf, 0xd6, 0xeb, 0x79, 0x53, 0x1e, 0x6d, 0xbb, 0x84, 0x59, 0xeb, 0x46 };
            expect(hash_1 == proc.first_hash);
            cardano_hash_28 hash_2 { 0x01, 0x2a, 0xbf, 0x0f, 0x0a, 0x65, 0x19, 0x2f, 0xcb, 0xa3, 0xe5, 0xe3, 0x05, 0xfe, 0x13, 0x47,
                                     0x8f, 0x0c, 0xd5, 0x8f, 0x27, 0x18, 0x73, 0xb0, 0xf2, 0x0d, 0xdb, 0x10 };
            expect(hash_2 == proc.last_hash);
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

        "cardano_amount"_test = [] {
            {
                cardano_amount a { 1'010 };
                std::string a_text { "0.001010 ADA" };
                expect(format("{}", a) == a_text);
                std::ostringstream ss;
                ss << a;
                expect(ss.str() == a_text);
            }
            {
                cardano_amount a { 678'900'012'345 };
                std::string a_text { "678900.012345 ADA" };
                expect(format("{}", a) == a_text);
                std::ostringstream ss;
                ss << a;
                expect(ss.str() == a_text);
            }
        };
    };

};
