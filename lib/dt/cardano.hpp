/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_CARDANO_HPP
#define DAEDALUS_TURBO_CARDANO_HPP

#include <cstdint>
#include <array>
#include <functional>
#include <span>
#include <unordered_map>
#include "bech32.hpp"
#include "blake2b.hpp"
#include "cbor.hpp"
#include "util.hpp"

namespace daedalus_turbo {

    using namespace std;

    using cardano_hash_32 = array<uint8_t, 32>;
    using cardano_hash_28 = array<uint8_t, 28>;

    inline uint64_t slot_to_epoch(uint64_t slot) {
        if (slot <= 208 * 21600) {
            return slot / 21600;
        } else {
            return 208 + (slot - 208 * 21600) / 432000;
        }
    }

    inline uint64_t slot_to_epoch_slot(uint64_t slot) {
        if (slot <= 208 * 21600) {
            return slot % 21600;
        } else {
            return (slot - 208 * 21600) % 432000;
        }
    }

    struct cardano_chunk_context {
        uint64_t offset = 0;

        cardano_chunk_context(uint64_t off)
            : offset(off)
        {
        }
    };

    struct cardano_block_context {
        cardano_chunk_context &chunk_ctx;
        uint64_t offset = 0;
        uint64_t fees = 0;
        uint64_t era = 0;
        uint64_t block_number = 0;
        uint64_t slot = 0;
        uint64_t epoch = 0;
        uint8_t pool_hash[28];

        cardano_block_context(cardano_chunk_context &ctx)
            : chunk_ctx(ctx)
        {
        }

        cardano_block_context(cardano_chunk_context &ctx, uint64_t off, uint64_t era_, uint64_t blk_num, uint64_t slot_, uint64_t epoch_)
            : chunk_ctx(ctx), offset(off), era(era_), block_number(blk_num), slot(slot_), epoch(epoch_)
        {
        }
    };

    struct cardano_tx_context {
        cardano_block_context &block_ctx;
        uint64_t offset = 0;
        uint64_t idx = 0;
        uint8_t hash[32];

        cardano_tx_context(cardano_block_context &ctx)
            : block_ctx(ctx)
        {
        }

        cardano_tx_context(cardano_block_context &ctx, uint64_t off, uint64_t idx_, const buffer &tx_hash)
            : block_ctx(ctx), offset(off), idx(idx_)
        {
            if (tx_hash.size() != sizeof(hash)) throw error("incorrectly sized tx hash: %zu bytes!", tx_hash.size());
            memcpy(hash, tx_hash.data(), tx_hash.size());
        }
    };

    struct cardano_tx_cert_context {
        cardano_tx_context &tx_ctx;
        uint16_t cert_idx = 0;

        cardano_tx_cert_context(cardano_tx_context &ctx)
            : tx_ctx(ctx)
        {
        }
    };

    struct cardano_tx_input_context {
        cardano_tx_context &tx_ctx;
        uint16_t in_idx = 0;

        cardano_tx_input_context(cardano_tx_context &ctx)
            : tx_ctx(ctx)
        {
        }
    };

    struct cardano_tx_output_context {
        cardano_tx_context &tx_ctx;
        uint16_t out_idx = 0;

        cardano_tx_output_context(cardano_tx_context &ctx)
            : tx_ctx(ctx)
        {
        }
    };

    using cardano_error = error;
 
    class cardano_processor {
    public:
        void every_chunk(const cardano_chunk_context &/*ctx*/, const buffer &/*chunk*/) {};
        void every_block(const cardano_block_context &/*ctx*/, const cbor_value &/*block_tuple*/) {};
        void every_tx(const cardano_tx_context &/*ctx*/, const cbor_value &/*tx*/, uint64_t /*fees*/) {};
        void every_tx_input(const cardano_tx_input_context &/*ctx*/, const cbor_buffer &/*tx_hash*/, uint64_t /*tx_out_idx*/) {};
        void every_tx_output(const cardano_tx_output_context &/*ctx*/, const cbor_buffer &/*address*/, uint64_t /*amount*/) {};
        void every_tx_withdrawal(const cardano_tx_context &/*ctx*/, const cbor_buffer &/*address*/, uint64_t /*amount*/) {};
    };

    template<typename Processor>
    class cardano_parser {
        Processor &processor;

    public:

        cardano_parser(Processor &processor_)
            : processor(processor_)
        {
        }

        void parse_tx_input(const cardano_tx_input_context &tx_in_ctx, const cbor_value &input)
        {
            const cbor_array &tx_in = input.array();
            switch (tx_in.size()) {
                case 2: {
                    processor.every_tx_input(tx_in_ctx, tx_in[0].buf(), tx_in[1].uint());
                    break;
                }

                default:
                    throw cardano_error("unexpected tx_input format array size is %zu!", tx_in.size());
            }
        }

        uint64_t extract_tx_output_coin(const cbor_value &coin)
        {
            switch (coin.type) {
                case CBOR_UINT:
                    return coin.uint();
                    break;

                case CBOR_ARRAY: {
                    const cbor_array &value = coin.array();
                    if (value.size() != 2) throw error("unexpected size of the value array: %zu!", value.size());
                    return value[0].uint();
                    break;
                }

                default:
                    throw error("unexpected format of the tx output value: CBOR type: %u!", (unsigned)coin.type);
            }
        }

        void parse_tx_output(const cardano_tx_output_context &tx_out_ctx, const cbor_value &output)
        {
            const cbor_buffer *address = nullptr;
            uint64_t amount = 0;
            switch (output.type) {
                case CBOR_ARRAY: {
                    const cbor_array &items = output.array();
                    if (items.size() < 2) throw error("unexpected format of a Cardano transaction output!");
                    address = &items[0].buf();
                    amount = extract_tx_output_coin(items[1]);
                    break;
                }

                case CBOR_MAP: {
                    const cbor_map &items = output.map();
                    for (auto it2 = items.begin(); it2 != items.end(); ++it2) {
                        switch (it2->first.uint()) {
                            case 0:
                                address = &it2->second.buf();
                                break;

                            case 1:
                                amount = extract_tx_output_coin(it2->second);
                                break;
                        }
                    }
                    break;
                }

                default:
                    throw cardano_error("Unsupported transaction output of a CBOR type ", output.type);
            }
            if (address != nullptr) {
                processor.every_tx_output(tx_out_ctx, *address, amount);
            }
        }

        void parse_tx_withdrawal(const cardano_tx_context &tx_ctx, const cbor_buffer &address, uint64_t amount)
        {
            if (amount > 0) {
                processor.every_tx_withdrawal(tx_ctx, address, amount);
            }
        }

        void parse_tx(cardano_tx_context &tx_ctx, const cbor_value &tx)
        {
            const cbor_array *inputs = nullptr;
            const cbor_array *outputs = nullptr;
            const cbor_map *withdrawals = nullptr;
            uint64_t fees = 0;
            if (tx.type == CBOR_ARRAY) {
                const cbor_array &items = tx.array();
                if (items.size() < 2) throw cardano_error("transaction array must have at least two items but has %zu!", items.size());
                inputs = &items[0].array();
                outputs = &items[1].array();
                if (items.size() >= 3) fees = items[2].uint();
            } else if (tx.type == CBOR_MAP) {
                const cbor_map &items = tx.map();
                for (auto it = items.begin(); it != items.end(); ++it) {
                    uint64_t idx = it->first.uint();
                    switch (idx) {
                        case 0:
                            inputs = &it->second.array();
                            break;

                        case 1:
                            outputs = &it->second.array();
                            break;

                        case 2:
                            fees = it->second.uint();
                            break;

                        case 5:
                            withdrawals = &it->second.map();
                            break;
                    }
                }
            } else {
                throw cardano_error("Transaction is neither an array nor a map but a CBOR type %hhu!", tx.type);
            }
            if (inputs != nullptr) {
                cardano_tx_input_context tx_in_ctx(tx_ctx);
                for (tx_in_ctx.in_idx = 0; tx_in_ctx.in_idx < inputs->size(); tx_in_ctx.in_idx++) {
                    parse_tx_input(tx_in_ctx, (*inputs)[tx_in_ctx.in_idx]);
                }
            }
            if (outputs != nullptr) {
                cardano_tx_output_context tx_out_ctx(tx_ctx);
                for (tx_out_ctx.out_idx = 0; tx_out_ctx.out_idx < outputs->size(); tx_out_ctx.out_idx++) {
                    parse_tx_output(tx_out_ctx, (*outputs)[tx_out_ctx.out_idx]);
                }
            }
            if (fees != 0) {
                tx_ctx.block_ctx.fees += fees;
            }
            if (withdrawals != nullptr) {
                for (const auto &wt : *withdrawals) {
                    parse_tx_withdrawal(tx_ctx, wt.first.buf(), wt.second.uint());
                }
            }
            processor.every_tx(tx_ctx, tx, fees);
        }

        void parse_block(cardano_chunk_context &chunk_ctx, const buffer &chunk, const cbor_value &block_tuple)
        {
            cardano_block_context block_ctx(chunk_ctx);
            cardano_tx_context tx_ctx(block_ctx);
            const cbor_array &items = block_tuple.array();
            if (items.size() != 2) throw cardano_error("Unsupported block start record count");
            block_ctx.era = items[0].uint();
            block_ctx.fees = 0;
            block_ctx.offset = chunk_ctx.offset + block_tuple.offset(chunk.data());
            const cbor_array &block = items[1].array();
            switch (block_ctx.era) {
                case 0:
                    return;

                case 1: {
                    if (block.size() < 2) throw cardano_error("Byron block size has less than 2 elements!");
                    const cbor_array &header = block[0].array();
                    if (header.size() < 4) throw cardano_error("Byron block with header size less than 4!");
                    const cbor_array &consensus_data = header[3].array();
                    if (consensus_data.size() < 1) throw cardano_error("Byron consensus_data array must contain elements!");
                    const cbor_array &slotid = consensus_data[0].array();
                    const cbor_buffer &issuer_vkey = consensus_data[1].buf();
                    blake2b_best(block_ctx.pool_hash, sizeof(block_ctx.pool_hash), issuer_vkey.data(), issuer_vkey.size());
                    block_ctx.block_number = 0;
                    block_ctx.slot = slotid[1].uint();
                    block_ctx.epoch = slot_to_epoch(block_ctx.slot);
                    const cbor_array &body = block[1].array();
                    const cbor_array &transactions = body[0].array();
                    for (tx_ctx.idx = 0; tx_ctx.idx < transactions.size(); ++tx_ctx.idx) {
                        const cbor_value &tx = transactions[tx_ctx.idx];
                        tx_ctx.offset = chunk_ctx.offset + tx.offset(chunk.data());
                        blake2b_best(tx_ctx.hash, sizeof(tx_ctx.hash), tx.data, tx.size);
                        // ignore byron transaction since they neither affect stake distribution nor after-shelley wallets
                        // parse_tx(tx_ctx, tx);
                    }
                    break;
                }

                case 2:
                case 3:
                case 4:
                case 5:
                case 6: {
                    const cbor_array &header = block[0].array();
                    const cbor_array &header_body = header[0].array();
                    block_ctx.block_number = header_body[0].uint();
                    block_ctx.slot = header_body[1].uint();
                    block_ctx.epoch = slot_to_epoch(block_ctx.slot);
                    const cbor_buffer &issuer_vkey = header_body[3].buf();
                    blake2b_best(block_ctx.pool_hash, sizeof(block_ctx.pool_hash), issuer_vkey.data(), issuer_vkey.size());
                    const cbor_array &transactions = block[1].array();
                    for (tx_ctx.idx = 0; tx_ctx.idx < transactions.size(); ++tx_ctx.idx) {
                        const cbor_value &tx = transactions[tx_ctx.idx];
                        tx_ctx.offset = chunk_ctx.offset +  tx.offset(chunk.data());
                        blake2b_best(tx_ctx.hash, sizeof(tx_ctx.hash), tx.data, tx.size);
                        parse_tx(tx_ctx, tx);
                    }
                    break;
                }

                default:
                    throw cardano_error("unsupported block era: %u!", block_ctx.era);
            }

            processor.every_block(block_ctx, block_tuple);
        }

        void parse_chunk(cardano_chunk_context &chunk_ctx, const buffer &chunk)
        {
            processor.every_chunk(chunk_ctx, chunk);
            cbor_parser parser(chunk.data(), chunk.size());
            cbor_value block_tuple;
            while (!parser.eof()) {
                parser.read(block_tuple);
                parse_block(chunk_ctx, chunk, block_tuple);
            }
        }
    };

    inline uint8_vector cardano_parse_address(const string_view &addr_sv)
    {
        uint8_vector addr_buf;
        if (addr_sv.substr(0, 2) == "0x"sv) {
            bytes_from_hex(addr_buf, addr_sv.substr(2));
        } else {
            const bech32 addr_bech32(addr_sv);
            addr_buf.resize(addr_bech32.size());
            memcpy(addr_buf.data(), addr_bech32.data(), addr_bech32.size());
        }
        return addr_buf;
    }

}

#endif // !DAEDALUS_TURBO_CARDANO_HPP
