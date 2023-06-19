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
#include "ed25519.hpp"
#include "kes.hpp"
#include "vrf.hpp"
#include "util.hpp"

namespace daedalus_turbo {

    using cardano_hash_32 = blake2b_256_hash;
    using cardano_hash_28 = blake2b_224_hash;
    using cardano_vkey = ed25519_vkey;
    using cardano_vkey_span = std::span<const uint8_t, sizeof(cardano_vkey)>;
    using cardano_signature = ed25519_signature;
    using cardano_kes_signature = kes_signature<6>;
    using cardano_kes_signature_data = std::array<uint8_t, cardano_kes_signature::size()>;
    using cardano_vrf_vkey = vrf_vkey;
    using cardano_vrf_result = vrf_result;
    using cardano_vrf_result_span = std::span<const uint8_t, sizeof(cardano_vrf_result)>;
    using cardano_vrf_proof = vrf_proof;
    using cardano_vrf_proof_span = std::span<const uint8_t, sizeof(cardano_vrf_proof)>;

    struct cardano_amount {
        uint64_t coins;
    };
}

namespace fmt {
    
    template<>
    struct formatter<const daedalus_turbo::cardano_amount> {
        constexpr auto parse(format_parse_context &ctx) -> decltype(ctx.begin()) {
            return ctx.begin();
        }

        template<typename FormatContext>
        auto format(const daedalus_turbo::cardano_amount a, FormatContext &ctx) const -> decltype(ctx.out()) {
            uint64_t ada = a.coins / 1'000'000;
            uint64_t rem = a.coins % 1'000'000;
            return fmt::format_to(ctx.out(), "{}.{:06} ADA", ada, rem);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano_amount>: public formatter<const daedalus_turbo::cardano_amount> {
    };
}

namespace daedalus_turbo {
    
    inline std::ostream &operator<<(std::ostream &os, const cardano_amount a) {
        os << format("{}", a);
        return os;
    }

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
        cardano_hash_32 issuer_vkey;
        cardano_hash_28 pool_hash;
        cardano_hash_32 header_hash;

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
        uint64_t size = 0;
        uint64_t idx = 0;
        uint8_t hash[32];

        cardano_tx_context(cardano_block_context &ctx)
            : block_ctx(ctx)
        {
        }

        cardano_tx_context(cardano_block_context &ctx, uint64_t off, uint64_t sz, uint64_t idx_, const buffer &tx_hash)
            : block_ctx(ctx), offset(off), size(sz), idx(idx_)
        {
            if (tx_hash.size() != sizeof(hash)) throw error_fmt("incorrectly sized tx hash: {} bytes!", tx_hash.size());
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

    using cardano_error = error_fmt;
 
    class cardano_processor {
    public:
        void every_chunk(const cardano_chunk_context &/*ctx*/, const buffer &/*chunk*/) {};
        void every_block(const cardano_block_context &/*ctx*/, const cbor_value &/*block_tuple*/, const cbor_array &/*block*/) {};
        void every_kes_sig(const cardano_block_context &/*ctx*/, const cbor_buffer &/*vkey*/, uint64_t/*seq_no*/, uint64_t/*kes_period*/, const cbor_buffer &/*sig*/,
            const cbor_value &/*header_body*/, const cbor_buffer &/*kes_sig*/) {};
        void every_vrf(const cardano_block_context &/*ctx*/, const cbor_buffer &/*vrf_vkey*/, const cbor_array &/*leader_vrf*/, const cbor_array &/*nonce_vrf*/) {};
        void every_tx(const cardano_tx_context &/*ctx*/, const cbor_value &/*tx*/, uint64_t /*fees*/) {};
        void every_tx_input(const cardano_tx_input_context &/*ctx*/, const cbor_buffer &/*tx_hash*/, uint64_t /*tx_out_idx*/) {};
        void every_tx_output(const cardano_tx_output_context &/*ctx*/, const cbor_buffer &/*address*/, uint64_t /*amount*/) {};
        void every_tx_withdrawal(const cardano_tx_context &/*ctx*/, const cbor_buffer &/*address*/, uint64_t /*amount*/) {};
        void every_tx_update(const cardano_tx_context &/*ctx*/, uint64_t /*epoch*/, const cbor_buffer &/*hash*/, const cbor_map &/*update*/) {};
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
                    throw cardano_error("unexpected tx_input format array size is {}!", tx_in.size());
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
                    if (value.size() != 2) throw cardano_error("unexpected size of the value array: {}!", value.size());
                    return value[0].uint();
                    break;
                }

                default:
                    throw cardano_error("unexpected format of the tx output value: CBOR type: {}!", (unsigned)coin.type);
            }
        }

        void parse_tx_output(const cardano_tx_output_context &tx_out_ctx, const cbor_value &output)
        {
            const cbor_buffer *address = nullptr;
            uint64_t amount = 0;
            switch (output.type) {
                case CBOR_ARRAY: {
                    const cbor_array &items = output.array();
                    if (items.size() < 2) throw cardano_error("unexpected format of a Cardano transaction output!");
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
                    throw cardano_error("Unsupported transaction output of a CBOR type {}", output.type);
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
            const cbor_array *updates = nullptr;
            uint64_t fees = 0;
            if (tx.type == CBOR_ARRAY) {
                const cbor_array &items = tx.array();
                if (items.size() < 2) throw cardano_error("transaction array must have at least two items but has {}!", items.size());
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

                        case 6:
                            updates = &it->second.array();
                            break;
                    }
                }
            } else {
                throw cardano_error("Transaction is neither an array nor a map but a CBOR type {}!", tx.type);
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
            if (updates != nullptr) {
                uint64_t epoch = updates->at(1).uint();
                for (const auto &[hash, update]: updates->at(0).map()) {
                    processor.every_tx_update(tx_ctx, epoch, hash.buf(), update.map());
                }
            }
            processor.every_tx(tx_ctx, tx, fees);
        }

        void parse_op_cert(cardano_block_context &block_ctx, const cbor_value &header_body, const cbor_buffer &kes_sig)
        {
            const auto &op_cert = block_ctx.era < 6 ? header_body.array() : header_body.array().at(8).array();
            size_t op_start_idx = block_ctx.era < 6 ? 9 : 0;
            processor.every_kes_sig(block_ctx, op_cert.at(op_start_idx + 0).buf(), op_cert.at(op_start_idx + 1).uint(),
                op_cert.at(op_start_idx + 2).uint(), op_cert.at(op_start_idx + 3).buf(),
                header_body, kes_sig);
        }

        void parse_vrf(cardano_block_context &ctx, const cbor_array &header_body)
        {
            if (ctx.era < 6) processor.every_vrf(ctx, header_body.at(4).buf(), header_body.at(6).array(), header_body.at(5).array());
            else processor.every_vrf(ctx, header_body.at(4).buf(), header_body.at(5).array(), header_body.at(5).array());
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
                case 0: {
                    if (block.size() < 2) throw cardano_error("Byron EBB block size has less than 2 elements!");
                    const cbor_value &header = block[0];
                    uint8_vector byron_header(header.size + 2);
                    byron_header[0] = 0x82;
                    byron_header[1] = 0x01;
                    memcpy(byron_header.data() + 2, header.data, header.size);
                    blake2b(block_ctx.header_hash, byron_header);
                    const auto &header_items = header.array();
                    if (header_items.size() < 4) throw cardano_error("Byron block with header size less than 4!");
                    const auto &ebbcons_items = header_items[3].array();
                    if (ebbcons_items.size() < 2) throw cardano_error("Byron EBB consensus_data array must contain at least 2 elements!");
                    memset(block_ctx.pool_hash.data(), 0, block_ctx.pool_hash.size());
                    block_ctx.block_number = 0;
                    block_ctx.epoch = ebbcons_items[0].uint();
                    block_ctx.slot = block_ctx.epoch * 21600;
                    break;
                }

                case 1: {
                    if (block.size() < 2) throw cardano_error("Byron block size has less than 2 elements!");
                    const cbor_value &header = block[0];
                    uint8_vector byron_header(header.size + 2);
                    byron_header[0] = 0x82;
                    byron_header[1] = 0x01;
                    memcpy(byron_header.data() + 2, header.data, header.size);
                    blake2b(block_ctx.header_hash, byron_header);
                    const cbor_array &header_items = header.array();
                    if (header_items.size() < 4) throw cardano_error("Byron block with header size less than 4!");
                    const cbor_array &consensus_data = header_items[3].array();
                    if (consensus_data.size() < 1) throw cardano_error("Byron consensus_data array must contain elements!");
                    const cbor_array &slotid = consensus_data[0].array();
                    const auto &issuer_vkey = consensus_data[1].span();
                    //span_memcpy(block_ctx.issuer_vkey, issuer_vkey);
                    blake2b(block_ctx.pool_hash, issuer_vkey);
                    block_ctx.block_number = 0;
                    block_ctx.epoch = slotid[0].uint();
                    block_ctx.slot = block_ctx.epoch * 21600 + slotid[1].uint();
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
                    const cbor_value &header = block[0];
                    blake2b(block_ctx.header_hash, header.raw_span());
                    const cbor_array &header_items = header.array();
                    const cbor_array &header_body = header_items[0].array();
                    block_ctx.block_number = header_body[0].uint();
                    block_ctx.slot = header_body[1].uint();
                    block_ctx.epoch = slot_to_epoch(block_ctx.slot);
                    const auto &issuer_vkey = header_body[3].span();
                    span_memcpy(block_ctx.issuer_vkey, issuer_vkey);
                    blake2b(block_ctx.pool_hash, issuer_vkey);
                    const cbor_array &transactions = block[1].array();
                    for (tx_ctx.idx = 0; tx_ctx.idx < transactions.size(); ++tx_ctx.idx) {
                        const cbor_value &tx = transactions[tx_ctx.idx];
                        tx_ctx.offset = chunk_ctx.offset +  tx.offset(chunk.data());
                        tx_ctx.size = tx.size;
                        blake2b_best(tx_ctx.hash, sizeof(tx_ctx.hash), tx.data, tx.size);
                        parse_tx(tx_ctx, tx);
                    }
                    parse_op_cert(block_ctx, header_items[0], header_items[1].buf());
                    parse_vrf(block_ctx, header_body);
                    break;
                }

                default:
                    throw cardano_error("unsupported block era: {}!", block_ctx.era);
            }

            processor.every_block(block_ctx, block_tuple, block);
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

    inline uint8_vector cardano_parse_address(const std::string_view &addr_sv)
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

    template<typename T>
    inline void cardano_parse_buf(const std::span<const uint8_t> &chunk_data, T &processor)
    {
        cardano_parser parser(processor);
        cardano_chunk_context chunk_ctx(0);
        parser.parse_chunk(chunk_ctx, chunk_data);
    }

    template<typename T>
    inline void cardano_parse_file(const std::string &path, T &processor)
    {
        uint8_vector chunk_data;
        read_whole_file(path, chunk_data);
        cardano_parse_buf(chunk_data, processor);
    }

    template<typename T>
    inline T cardano_parse_file(const std::string &path)
    {
        uint8_vector chunk_data;
        read_whole_file(path, chunk_data);
        T processor;
        cardano_parse_buf(chunk_data, processor);
        return processor;
    }

}

#endif // !DAEDALUS_TURBO_CARDANO_HPP
