/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
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

// virtual functions of functors?

namespace daedalus_turbo {

    using namespace std;

    class cardano_hash_28: public array<uint8_t, 28> {
    public:
        cardano_hash_28() =default;
        cardano_hash_28(const cardano_hash_28 &h) =default;
        cardano_hash_28(cardano_hash_28 &&h) =default;

        cardano_hash_28(const uint8_t *ptr, size_t sz)
            : array<uint8_t, 28>()
        {
            if (sz != size()) throw error("cardano_hash_28 must be exactly of 28 bytes, but got %zu bytes instead", sz);
            memcpy(data(), ptr, size());
        }

        cardano_hash_28 &operator=(const cardano_hash_28 &h) {
            memcpy(data(), h.data(), h.size());
            return *this;
        }

        bool operator==(const cardano_hash_28 &h) {
            return memcmp(data(), h.data(), size()) == 0;
        }
    };

    typedef pair<cardano_hash_28, int64_t> CardanoBalance;
    typedef unordered_map<cardano_hash_28, int64_t> CardanoBalanceMap;

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
            if (tx_hash.size != sizeof(hash)) throw error("incorrectly sized tx hash: %zu bytes!", tx_hash.size);
            memcpy(hash, tx_hash.data, tx_hash.size);
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
        void every_tx_cert(const cardano_tx_cert_context &/*ctx*/, const cbor_value &/*cert*/) {};
        void every_tx_input(const cardano_tx_input_context &/*ctx*/, const cbor_buffer &/*tx_hash*/, uint64_t /*tx_out_idx*/) {};
        void every_tx_output(const cardano_tx_output_context &/*ctx*/, const cbor_buffer &/*address*/, uint64_t /*amount*/) {};
        void every_tx_withdrawal(const cardano_tx_context &/*ctx*/, const cbor_buffer &/*address*/, uint64_t /*amount*/) {};
    };

    class cardano_parser_error: public error
    {
    };

    template<typename Processor>
    class cardano_parser {
        Processor &processor;

    public:

        cardano_parser(Processor &processor_)
            : processor(processor_)
        {
        }

        void parse_tx_cert(const cardano_tx_cert_context &/*tx_cert_ctx*/, const cbor_value &cert_val)
        {
            const cbor_array &cert = cert_val.array();
            if (cert.size() < 2) throw cardano_error("certificate item must have at least two elements!");
            uint64_t type = cert[0].uint();
            switch (type) {
                case 0:
                case 1:
                case 2: {
                    const cbor_array &stake_cred = cert[1].array();
                    if (stake_cred.size() != 2) throw cardano_error("stake_credential must have exactly two elements!");
                    uint64_t cred_type = stake_cred[0].uint();
                    if (cred_type == 0) {
                        const cbor_buffer &key_hash = stake_cred[1].buf();
                        if (key_hash.size != 28) throw cardano_error("stake key hash must be 28 bytes!");
                        /*
                        uint8_t buf[STAKE_ITEM_SIZE];
                        stake_cert_item item;
                        memcpy(item.stake_hash, key_hash.data, key_hash.size);
                        item.slot = bi.slot;
                        item.tx_idx = tx_idx;
                        item.cert_idx = cert_idx;
                        stake_idx.write(item);
                        */
                    }
                    break;
                }

                case 3:
                case 4: {
                    if (cert[1].type != CBOR_BYTES) throw cardano_error("pool key_hash must be a byte string!");
                    /*
                    const cbor_buffer &pool_hash = cert[1].buffer();
                    uint8_t buf[POOL_ITEM_SIZE];
                    if (pool_hash.size != 28) throw runtime_error("pool hash hash must be 28 bytes!");
                    memcpy(buf, pool_hash.data, 28);
                    memcpy(buf + 28, &tx_offset, 6);
                    memcpy(buf + 28 + 6, &cert_idx, 2);
                    pool_idx.write(buf, sizeof(buf));
                    */
                    break;
                }
            }
        }

        void parse_tx_input(const cardano_tx_input_context &tx_in_ctx, const cbor_value &input)
        {
            const cbor_array &tx_in = input.array();
            switch (tx_in.size()) {
                case 1: {
                    // byron tx - ignore it
                    /*
                    if (tx_in[0].type != CBOR_ARRAY) throw cardano_error("unexpected byron tx input CBOR type: ", tx_in[0].type);
                    const cbor_array &byron_tx_in = tx_in[0].array();
                    if (byron_tx_in.size() != 2) throw cardano_error("unexpected byron tx input array size: ", byron_tx_in.size());
                    if (byron_tx_in[0].type != CBOR_UINT) throw cardano_error("unexpected byron tx input 0 value type: ", byron_tx_in[0].type);
                    uint64_t byron_val_0 = byron_tx_in[0].uint();
                    switch (byron_val_0) {
                        case 0: {
                            if (byron_tx_in[1].type != CBOR_TAG) throw cardano_error("unexpected byron tx input 1 value type: ", byron_tx_in[1].type);
                            const cbor_tag &tx_in_tag = byron_tx_in[1].tag();
                            if (tx_in_tag.first != 24) throw cardano_error("unexpected byron tx input tag value: ", tx_in_tag.first);
                            if (tx_in_tag.second->type != CBOR_BYTES) throw cardano_error("unexpected byron tx input tag data type: ", tx_in_tag.second->type);
                            const cbor_buffer &bytes = tx_in_tag.second->buffer();
                            cbor_parser parser(bytes.data, bytes.size);
                            cbor_value tx_val;
                            parser.readValue(tx_val);
                            if (tx_val.type != CBOR_ARRAY) throw cardano_error("unexpected byron tx item CBOR type: ", tx_val.type);
                            const cbor_array &tx_items = tx_val.array();
                            if (tx_items.size() != 2) throw cardano_error("unexpected byron tx input array size: ", tx_items.size());
                            processor.every_tx_input(tx_in_ctx, tx_items[0].buffer(), tx_items[1].uint());
                            break;
                        }

                        default:
                            throw cardano_error("unexpected byron tx input val 0 value: ", byron_val_0);
                    }*/
                    break;
                }

                case 2: {
                    processor.every_tx_input(tx_in_ctx, tx_in[0].buf(), tx_in[1].uint());
                    break;
                }

                default:
                    throw cardano_error("unexpected tx_input format array size is %zu!", tx_in.size());
            }
        }

        void parse_tx_output(const cardano_tx_output_context &tx_out_ctx, const cbor_value &output)
        {
            const cbor_buffer *address = nullptr;
            // recognize non-ADA transactions as having 0 ADA value
            uint64_t amount = 0;
            switch (output.type) {
                case CBOR_ARRAY: {
                    const cbor_array &items = output.array();
                    if (items.size() < 2) throw error("unexpected format of a Cardano transaction output!");
                    address = &items[0].buf();
                    if (items[1].type == CBOR_UINT) amount = items[1].uint();
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
                                if (it2->second.type == CBOR_UINT) amount = it2->second.uint();
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
            const cbor_array *certs = nullptr;
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
                        case 0: {
                            inputs = &it->second.array();
                            break;
                        }

                        case 1: {
                            outputs = &it->second.array();
                            break;
                        }

                        case 2: {
                            fees = it->second.uint();
                            break;
                        }

                        case 4: {
                            certs = &it->second.array();                
                            break;

                        case 5:
                            withdrawals = &it->second.map();
                            break;
                        }
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
            if (certs != nullptr) {
                cardano_tx_cert_context tx_cert_ctx(tx_ctx);
                for (tx_cert_ctx.cert_idx = 0; tx_cert_ctx.cert_idx < certs->size(); tx_cert_ctx.cert_idx++) {
                    parse_tx_cert(tx_cert_ctx, (*certs)[tx_cert_ctx.cert_idx]);
                }
            }
            if (withdrawals != nullptr) {
                for (const auto &wt : *withdrawals) {
                    parse_tx_withdrawal(tx_ctx, wt.first.buf(), wt.second.uint());
                }
            }
            processor.every_tx(tx_ctx, tx, fees);
        }

        void parse_chunk(cardano_chunk_context &chunk_ctx, const buffer &chunk)
        {
            processor.every_chunk(chunk_ctx, chunk);
            cbor_parser parser(chunk.data, chunk.size);
            cardano_block_context block_ctx(chunk_ctx);
            cardano_tx_context tx_ctx(block_ctx);
            cbor_value block_tuple;
            while (!parser.eof()) {
                parser.readValue(block_tuple);
                const cbor_array &items = block_tuple.array();
                if (items.size() != 2) throw cardano_error("Unsupported block start record count");
                block_ctx.era = items[0].uint();
                block_ctx.fees = 0;
                block_ctx.offset = chunk_ctx.offset + block_tuple.offset(chunk.data);
                const cbor_array &block = items[1].array();
                switch (block_ctx.era) {
                    case 0:
                        continue;

                    case 1: {
                        if (block.size() < 2) throw cardano_error("Byron block size has less than 2 elements!");
                        const cbor_array &header = block[0].array();
                        if (header.size() < 4) throw cardano_error("Byron block with header size less than 4!");
                        const cbor_array &consensus_data = header[3].array();
                        if (consensus_data.size() < 1) throw cardano_error("Byron consensus_data array must contain elements!");
                        const cbor_array &slotid = consensus_data[0].array();
                        const cbor_buffer &issuer_vkey = consensus_data[1].buf();
                        blake2b_best(block_ctx.pool_hash, sizeof(block_ctx.pool_hash), issuer_vkey.data, issuer_vkey.size);
                        block_ctx.block_number = 0;
                        block_ctx.slot = slotid[1].uint();
                        block_ctx.epoch = slot_to_epoch(block_ctx.slot);
                        const cbor_array &body = block[1].array();
                        const cbor_array &transactions = body[0].array();
                        for (tx_ctx.idx = 0; tx_ctx.idx < transactions.size(); ++tx_ctx.idx) {
                            const cbor_value &tx = transactions[tx_ctx.idx];
                            tx_ctx.offset = chunk_ctx.offset + tx.offset(chunk.data);
                            blake2b_best(tx_ctx.hash, sizeof(tx_ctx.hash), tx.data, tx.size);
                            // ignore byron transaction since they neither affect stake distribution nor after-shelley wallets
                            //parse_tx(tx_ctx, tx);
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
                        blake2b_best(block_ctx.pool_hash, sizeof(block_ctx.pool_hash), issuer_vkey.data, issuer_vkey.size);        
                        const cbor_array &transactions = block[1].array();
                        for (tx_ctx.idx = 0; tx_ctx.idx < transactions.size(); ++tx_ctx.idx) {
                            const cbor_value &tx = transactions[tx_ctx.idx];
                            tx_ctx.offset = chunk_ctx.offset +  tx.offset(chunk.data);
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
        }
    };

    inline bin_string cardano_parse_address(const string_view &addr_sv)
    {
        bin_string addr_buf;
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

template<>
struct std::hash<daedalus_turbo::cardano_hash_28> {
    size_t operator()(const daedalus_turbo::cardano_hash_28 &h) const noexcept {
        size_t hash;
        memcpy(&hash, h.data(), sizeof(hash));
        return hash;
    }
};

#endif // !DAEDALUS_TURBO_CARDANO_HPP
