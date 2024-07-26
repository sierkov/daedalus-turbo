/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <algorithm>
#include <dt/cardano.hpp>
#include <dt/cli.hpp>
#include <dt/history.hpp>

namespace daedalus_turbo::cli::stake_history {
    struct cmd: command {
        void configure(config &cmd) const override
        {
            cmd.name = "stake-history";
            cmd.desc = "list all transactions referencing a given stake address";
            cmd.args.expect({ "<data-dir>", "<pay-addr>" });
        }

        void run(const arguments &args) const override
        {
            timer t { "reconstruction and serialization", logger::level::debug };
            const auto &data_dir = args.at(0);
            cardano::address_buf addr_raw { args.at(1) };
            if (addr_raw.size() == 28)
                addr_raw.insert(addr_raw.begin(), 0xE1);
            chunk_registry cr { data_dir, chunk_registry::mode::index };
            reconstructor r { cr };
            cardano::address addr { addr_raw.span() };
            const auto id = addr.stake_id();
            _warn_top_stake_key(id.hash);
            std::cout << fmt::format("{}", r.find_history(id));
        }
    private:
        void _warn_top_stake_key(const buffer &addr) const
        {
            // This list was generated when slot 83385606 was at the tip of the blockchain.
            static const std::array<cardano_hash_28, 50> top_stake_keys = {
                cardano_hash_28 { 0x81, 0x72, 0x8e, 0x7e, 0xd4, 0xcf, 0x32, 0x4e, 0x13, 0x23, 0x13, 0x5e, 0x7e, 0x6d, 0x93, 0x1f, 0x01, 0xe3, 0x07, 0x92, 0xd9, 0xcd, 0xf1, 0x71, 0x29, 0xcb, 0x80, 0x6d },
                cardano_hash_28 { 0x1e, 0x78, 0xaa, 0xe7, 0xc9, 0x0c, 0xc3, 0x6d, 0x62, 0x4f, 0x7b, 0x3b, 0xb6, 0xd8, 0x6b, 0x52, 0x69, 0x6d, 0xc8, 0x4e, 0x49, 0x0f, 0x34, 0x3e, 0xba, 0x89, 0x00, 0x5f },
                cardano_hash_28 { 0x52, 0x56, 0x3c, 0x54, 0x10, 0xbf, 0xf6, 0xa0, 0xd4, 0x3c, 0xce, 0xbb, 0x7c, 0x37, 0xe1, 0xf6, 0x9f, 0x5e, 0xb2, 0x60, 0x55, 0x25, 0x21, 0xad, 0xff, 0x33, 0xb9, 0xc2 },
                cardano_hash_28 { 0x7e, 0x9e, 0xde, 0xbd, 0x75, 0xb1, 0x90, 0x8b, 0x72, 0x51, 0x91, 0x86, 0xc9, 0x97, 0xcd, 0x98, 0xe6, 0xd6, 0x2e, 0x56, 0x36, 0xf0, 0xe3, 0xae, 0xa1, 0xee, 0x51, 0x40 },
                cardano_hash_28 { 0xbd, 0x6a, 0x09, 0x6c, 0xbb, 0xa5, 0xe2, 0x59, 0x94, 0x67, 0x98, 0xe9, 0x48, 0x40, 0x3e, 0x2d, 0x2b, 0x3d, 0x9e, 0xa8, 0x8a, 0x12, 0xee, 0x8e, 0x7a, 0xe9, 0x44, 0x97 },
                cardano_hash_28 { 0x41, 0xfe, 0x63, 0xa9, 0x7d, 0x34, 0xa6, 0xf7, 0xa3, 0x70, 0x71, 0xf4, 0xd0, 0xe2, 0x97, 0xc3, 0x95, 0x8b, 0x4f, 0xb7, 0xa2, 0x93, 0x0c, 0xa3, 0x6f, 0x14, 0xf3, 0xca },
                cardano_hash_28 { 0x2d, 0x16, 0x53, 0xc6, 0x88, 0xd7, 0xeb, 0x6e, 0xb2, 0x96, 0x77, 0x3a, 0x19, 0x5f, 0xc4, 0x45, 0x8b, 0x6a, 0x7d, 0x11, 0x1f, 0xfa, 0x0d, 0xcb, 0xa9, 0xa3, 0x18, 0xc3 },
                cardano_hash_28 { 0xb4, 0xf0, 0x5e, 0xcc, 0x9f, 0xd8, 0xc9, 0x06, 0x6e, 0xf7, 0xfd, 0x90, 0x7d, 0xb8, 0x54, 0xc7, 0x6c, 0xaf, 0x64, 0x62, 0xb1, 0x32, 0xce, 0x13, 0x3d, 0xc7, 0xcc, 0x44 },
                cardano_hash_28 { 0xca, 0xb9, 0xc9, 0x54, 0x3b, 0x2d, 0x6a, 0x84, 0xa9, 0x9b, 0x54, 0xad, 0x67, 0xdf, 0xe7, 0xef, 0x13, 0x5e, 0x87, 0xdb, 0x3f, 0xad, 0x70, 0x5d, 0x18, 0x91, 0x61, 0x98 },
                cardano_hash_28 { 0x5c, 0x67, 0x14, 0x94, 0xf5, 0x58, 0x59, 0xa2, 0x16, 0xfe, 0xa3, 0x94, 0xa5, 0xda, 0x07, 0xdd, 0xfa, 0xad, 0x1a, 0x68, 0xd4, 0x21, 0x8f, 0x89, 0xbe, 0x3d, 0xd9, 0xcf },
                cardano_hash_28 { 0x0e, 0x3e, 0xf2, 0x8f, 0x82, 0x54, 0x48, 0x1d, 0x40, 0x3e, 0xb5, 0xd2, 0x6f, 0x11, 0x8d, 0x7b, 0xa0, 0xc0, 0x9e, 0xaf, 0x36, 0xf0, 0xfd, 0x1a, 0x0a, 0xc6, 0x24, 0xa8 },
                cardano_hash_28 { 0x23, 0x01, 0xf8, 0xa2, 0x20, 0x83, 0x78, 0x89, 0xc4, 0xbb, 0x4c, 0x99, 0xe8, 0x65, 0xc6, 0xc7, 0x1d, 0x4a, 0x8e, 0x5d, 0xf2, 0x5f, 0x13, 0x4e, 0xe6, 0xb3, 0x94, 0x94 },
                cardano_hash_28 { 0x4f, 0xa4, 0x6e, 0x41, 0xa1, 0x11, 0x1c, 0x81, 0x6c, 0xa0, 0x31, 0x88, 0xde, 0xe8, 0x34, 0x45, 0xcd, 0x3b, 0x0b, 0x2f, 0xd5, 0xab, 0x7a, 0x18, 0x36, 0x78, 0x36, 0x01 },
                cardano_hash_28 { 0x11, 0x74, 0xbd, 0xa7, 0x0e, 0x3b, 0xa4, 0xe4, 0xeb, 0x64, 0x40, 0x0a, 0x80, 0x2c, 0xb7, 0x58, 0x41, 0x2a, 0xf0, 0x47, 0xa6, 0x89, 0x0c, 0xd6, 0xed, 0x45, 0x22, 0x30 },
                cardano_hash_28 { 0x15, 0xd8, 0xe4, 0x0f, 0xda, 0x2f, 0xcd, 0xa4, 0x96, 0xf6, 0x63, 0xfb, 0xeb, 0x6d, 0x27, 0x15, 0x34, 0xef, 0xb9, 0x84, 0x45, 0xfc, 0xf7, 0x74, 0x64, 0xee, 0xef, 0xbd },
                cardano_hash_28 { 0x71, 0x6f, 0x95, 0x0c, 0x91, 0x4a, 0xfb, 0xd8, 0xb1, 0xa9, 0x5e, 0x2a, 0xd3, 0x5f, 0xba, 0x5b, 0x84, 0xe5, 0x00, 0xd4, 0xea, 0xe8, 0x85, 0x81, 0x52, 0x71, 0x7f, 0xf5 },
                cardano_hash_28 { 0x67, 0x85, 0x09, 0xac, 0xa9, 0x72, 0x49, 0xed, 0xf2, 0x82, 0xcd, 0x59, 0xd7, 0xce, 0x66, 0xbd, 0x9a, 0x5f, 0xb5, 0x5e, 0x4d, 0x99, 0x9e, 0x53, 0x7a, 0x0e, 0x6a, 0x42 },
                cardano_hash_28 { 0x0e, 0x04, 0x5d, 0x73, 0x93, 0x0d, 0x8c, 0xeb, 0xcf, 0xa3, 0x72, 0x83, 0x7c, 0x44, 0x14, 0xad, 0xc9, 0xb6, 0x39, 0x4e, 0x92, 0x60, 0x1e, 0xa1, 0x4d, 0xa4, 0xfd, 0x23 },
                cardano_hash_28 { 0x2c, 0xc8, 0x69, 0x49, 0xa7, 0xb3, 0xcb, 0xf5, 0x74, 0x20, 0x78, 0x52, 0x19, 0x30, 0xb6, 0x55, 0x46, 0x12, 0xad, 0x58, 0x57, 0xb3, 0x62, 0x98, 0x1f, 0xd5, 0xb8, 0xaf },
                cardano_hash_28 { 0x66, 0x3a, 0x8f, 0xb1, 0xc8, 0x8f, 0x7c, 0x15, 0x06, 0x9f, 0xae, 0xbb, 0x39, 0xbd, 0x8b, 0x34, 0xa6, 0xcf, 0x70, 0x55, 0x20, 0x45, 0xda, 0x20, 0x7f, 0x1d, 0x03, 0xbf },
                cardano_hash_28 { 0xc1, 0x9e, 0xee, 0x60, 0x75, 0x8b, 0x01, 0x1e, 0xa1, 0x64, 0x56, 0xfd, 0xd5, 0xe9, 0x2c, 0xa3, 0xd0, 0xb4, 0xa8, 0x75, 0x91, 0xdf, 0x11, 0xd0, 0x85, 0xb8, 0xf1, 0xa7 },
                cardano_hash_28 { 0x17, 0xea, 0xbf, 0x85, 0x72, 0x8a, 0x59, 0x0b, 0x77, 0x85, 0xf2, 0x7d, 0x60, 0xde, 0xa7, 0xd4, 0xbc, 0xb3, 0x56, 0xb4, 0x38, 0xb9, 0xd5, 0x77, 0xa4, 0x55, 0x47, 0xfe },
                cardano_hash_28 { 0xe3, 0x10, 0xd5, 0xe4, 0x3e, 0x36, 0xff, 0x0f, 0xa5, 0x72, 0x06, 0x04, 0x07, 0xcf, 0x16, 0xad, 0x7c, 0x50, 0x2b, 0x58, 0xf3, 0x3e, 0x97, 0xd8, 0xd6, 0x67, 0xa0, 0x9f },
                cardano_hash_28 { 0x24, 0x12, 0xd6, 0x0d, 0x85, 0xf9, 0x62, 0x70, 0x37, 0x1a, 0xcd, 0xef, 0xbd, 0xba, 0x7d, 0x07, 0xc1, 0x57, 0xd5, 0x77, 0xa9, 0x6a, 0x4f, 0x19, 0x18, 0x8c, 0xbb, 0xa3 },
                cardano_hash_28 { 0x3b, 0x97, 0x99, 0xd3, 0xf3, 0x52, 0x29, 0x87, 0x50, 0xa4, 0x7f, 0x1a, 0x68, 0x2d, 0x57, 0x8a, 0xd1, 0xbe, 0x6c, 0x7e, 0x66, 0xf4, 0x67, 0xbe, 0x60, 0x52, 0x1a, 0x67 },
                cardano_hash_28 { 0x28, 0xf1, 0x7f, 0xdd, 0x2d, 0x8b, 0x8f, 0x55, 0x9a, 0xd6, 0x1e, 0x89, 0x9e, 0x31, 0xea, 0xe9, 0x0b, 0x9e, 0x20, 0x9c, 0xbe, 0xdb, 0x1e, 0xe8, 0xa8, 0xc6, 0xc7, 0xd1 },
                cardano_hash_28 { 0x93, 0x48, 0xff, 0x6e, 0xf5, 0x7c, 0x51, 0xe6, 0xf0, 0x0b, 0x60, 0xbf, 0x92, 0xac, 0x06, 0xd0, 0x35, 0xc3, 0x82, 0xcb, 0x29, 0x34, 0x5c, 0x3f, 0xbf, 0xaa, 0x77, 0x0e },
                cardano_hash_28 { 0x61, 0xd8, 0x7a, 0x62, 0x77, 0xd3, 0xd5, 0x85, 0xb2, 0x13, 0x49, 0xf2, 0xa0, 0xb7, 0xf6, 0xce, 0x31, 0xc4, 0x8a, 0x4f, 0x59, 0xd8, 0xcd, 0xda, 0x6e, 0xe4, 0x72, 0x0a },
                cardano_hash_28 { 0xf0, 0x11, 0x6d, 0x91, 0x08, 0x54, 0x8e, 0xf4, 0xb5, 0xcd, 0x2d, 0x5d, 0x64, 0x3a, 0x4d, 0x59, 0xb0, 0x50, 0xa8, 0x9e, 0x12, 0x43, 0x99, 0x40, 0x4d, 0x34, 0x96, 0x04 },
                cardano_hash_28 { 0xda, 0x83, 0xc0, 0x38, 0x8c, 0x2d, 0xd7, 0x60, 0x82, 0xce, 0xd6, 0x61, 0x1d, 0x2f, 0x15, 0xa9, 0x9e, 0xb4, 0xc9, 0x58, 0x23, 0x40, 0x61, 0xb5, 0x4f, 0xa7, 0x4b, 0x8f },
                cardano_hash_28 { 0xe4, 0xcf, 0x67, 0x0d, 0x07, 0xbf, 0xa7, 0x57, 0xda, 0x42, 0x5c, 0x3a, 0xab, 0x5f, 0x24, 0x93, 0x42, 0xe7, 0xd7, 0xb9, 0x32, 0xfa, 0x97, 0x2a, 0xee, 0x18, 0x7c, 0x49 },
                cardano_hash_28 { 0xfe, 0xf7, 0xdc, 0xa3, 0x14, 0x9e, 0x0f, 0x49, 0x70, 0x6e, 0xcb, 0xc7, 0x21, 0x9a, 0xf1, 0x8c, 0x3c, 0x85, 0x93, 0x36, 0xc9, 0xd7, 0x7a, 0xab, 0x8a, 0xd8, 0x9b, 0x22 },
                cardano_hash_28 { 0x72, 0xa6, 0x59, 0x49, 0x22, 0x95, 0x4f, 0xd8, 0x17, 0x56, 0xb9, 0xab, 0x98, 0x44, 0x04, 0x0c, 0x6c, 0x9e, 0x90, 0x48, 0x49, 0x15, 0x53, 0x19, 0x85, 0x97, 0xbf, 0xf1 },
                cardano_hash_28 { 0x80, 0xc6, 0xf0, 0x5c, 0x44, 0x5c, 0x1f, 0x5a, 0x3b, 0x45, 0xfa, 0xbd, 0xc5, 0xce, 0x37, 0x4b, 0x53, 0x5b, 0x6d, 0x4e, 0xfd, 0x1e, 0x5e, 0xb4, 0x40, 0xca, 0x57, 0x2f },
                cardano_hash_28 { 0x51, 0xb2, 0x81, 0x23, 0x3f, 0x86, 0x9b, 0x4f, 0x70, 0x40, 0xf7, 0x21, 0xd4, 0xa4, 0xbe, 0x98, 0x79, 0x08, 0xee, 0xf2, 0xb3, 0xe5, 0xdc, 0x6a, 0x63, 0xbc, 0xff, 0xfd },
                cardano_hash_28 { 0x95, 0x98, 0x5a, 0x0f, 0xcc, 0xc4, 0xd7, 0x5c, 0x8f, 0x87, 0xc3, 0x5f, 0x40, 0x89, 0x8b, 0xf5, 0xe0, 0xb4, 0xfe, 0xb2, 0xeb, 0x98, 0x3a, 0xd5, 0xa1, 0x77, 0xe5, 0x1c },
                cardano_hash_28 { 0x86, 0x81, 0x24, 0x04, 0x05, 0x82, 0xca, 0x81, 0x4b, 0xd5, 0xec, 0xb7, 0x9f, 0x96, 0xba, 0x47, 0x04, 0x3b, 0xac, 0x05, 0x09, 0x5a, 0xa2, 0x14, 0xc9, 0x4e, 0xf4, 0x21 },
                cardano_hash_28 { 0x56, 0x96, 0x90, 0xab, 0xe2, 0xca, 0xcf, 0xa8, 0xde, 0xad, 0x0c, 0x9b, 0x07, 0xec, 0xf6, 0xf0, 0x0c, 0x88, 0x9d, 0x6d, 0x80, 0x9f, 0x16, 0xad, 0x37, 0x08, 0x37, 0x20 },
                cardano_hash_28 { 0x70, 0xd4, 0x8d, 0xf8, 0x3e, 0x68, 0x9a, 0x81, 0xd6, 0xa2, 0xe4, 0xad, 0xfc, 0xd5, 0xe4, 0x76, 0x7a, 0x05, 0xb8, 0x93, 0xd8, 0x16, 0xee, 0x71, 0x7e, 0x09, 0x66, 0xf3 },
                cardano_hash_28 { 0xbb, 0xd9, 0x69, 0x26, 0x42, 0x97, 0x2d, 0x5e, 0x52, 0x91, 0x1f, 0x30, 0xfc, 0xcd, 0x71, 0x1a, 0x08, 0x6b, 0x1f, 0x1d, 0xf7, 0xe1, 0x1f, 0x57, 0xff, 0x75, 0xe2, 0xf6 },
                cardano_hash_28 { 0xa8, 0x1b, 0x66, 0x0d, 0x47, 0x50, 0xab, 0x26, 0xf2, 0xbe, 0x52, 0x73, 0x88, 0xd3, 0x5b, 0x67, 0xdd, 0x1a, 0x36, 0xd9, 0x6e, 0xdd, 0x46, 0xad, 0xbd, 0x43, 0x31, 0xa9 },
                cardano_hash_28 { 0xc0, 0xaf, 0xae, 0x75, 0xb2, 0x32, 0x0b, 0xfd, 0x23, 0x92, 0x79, 0xe9, 0xa5, 0xe0, 0x63, 0x51, 0x11, 0x04, 0x0b, 0xfc, 0xb1, 0x89, 0xa0, 0x8f, 0xe2, 0x08, 0x58, 0x30 },
                cardano_hash_28 { 0x1d, 0x12, 0xa0, 0xf9, 0x31, 0x36, 0x62, 0xe7, 0xfd, 0x73, 0xbc, 0x6f, 0x55, 0x1d, 0xcb, 0x86, 0x6c, 0x98, 0x37, 0x8c, 0xcb, 0x82, 0xd9, 0x3d, 0x29, 0x94, 0x83, 0x9e },
                cardano_hash_28 { 0x9b, 0x79, 0x57, 0x4e, 0x46, 0xf3, 0x71, 0xc5, 0xa6, 0xa7, 0xbd, 0xe4, 0xc3, 0x55, 0xe6, 0x36, 0x43, 0xe6, 0x7c, 0x9d, 0xfb, 0x75, 0xb0, 0x5c, 0x72, 0x95, 0x75, 0x6c },
                cardano_hash_28 { 0x41, 0xb0, 0xd7, 0x79, 0xee, 0xa9, 0xa5, 0xe7, 0xac, 0xa2, 0x33, 0x97, 0x35, 0x29, 0xeb, 0xf1, 0x29, 0x6b, 0xcc, 0x11, 0xe5, 0x2e, 0x1d, 0x55, 0x1b, 0x9e, 0x1e, 0xe4 },
                cardano_hash_28 { 0x86, 0x6a, 0xcc, 0x49, 0xa1, 0x0b, 0x70, 0x29, 0x57, 0xf0, 0x4e, 0x76, 0x83, 0xad, 0x64, 0x46, 0xb3, 0xbb, 0xe7, 0x16, 0x13, 0x24, 0xc3, 0x7c, 0x47, 0x56, 0xe0, 0x33 },
                cardano_hash_28 { 0x95, 0x3d, 0xb8, 0x30, 0x19, 0xc2, 0xc2, 0xad, 0x9d, 0xf6, 0x6b, 0x34, 0x1c, 0x43, 0x69, 0xd6, 0x78, 0x85, 0xef, 0xf9, 0xa1, 0x2d, 0x31, 0xec, 0xb6, 0x04, 0xdb, 0x7b },
                cardano_hash_28 { 0xa8, 0x3f, 0x6c, 0x89, 0xb9, 0x31, 0x25, 0x46, 0xae, 0x08, 0x09, 0x7b, 0xc6, 0xe7, 0x85, 0x90, 0xe6, 0x01, 0xf7, 0x84, 0x16, 0x17, 0x51, 0x49, 0xd6, 0x8f, 0x4f, 0x70 },
                cardano_hash_28 { 0x3d, 0x03, 0x57, 0xce, 0x0a, 0x70, 0xca, 0xf6, 0x30, 0x32, 0xcb, 0x8f, 0x37, 0x22, 0xf3, 0x8f, 0x70, 0x41, 0xb3, 0x70, 0xc4, 0xa9, 0x1f, 0x4d, 0x2d, 0xbd, 0xb7, 0x5f },
                cardano_hash_28 { 0x11, 0x1e, 0x9a, 0x69, 0x8b, 0x7f, 0x8d, 0x63, 0x03, 0x1e, 0x4e, 0xc8, 0x27, 0x56, 0x4e, 0x29, 0x12, 0xad, 0x23, 0xd9, 0x1c, 0x2e, 0x04, 0x8b, 0x99, 0xf2, 0x1c, 0x08 }
            };
            if (addr.size() != top_stake_keys[0].size()) throw error("unexpected address size {} while expected {}!", addr.size(), top_stake_keys[0].size());
            auto it = std::find_if(top_stake_keys.begin(), top_stake_keys.end(),
                [&](const cardano_hash_28 &sk) { return memcmp(sk.data(), addr.data(), addr.size()) == 0; });
            if (it != top_stake_keys.end()) {
                logger::warn("The key {} is in the top {} by the number of transactions!", addr, top_stake_keys.size());
                logger::warn("The history reconstruction can take a minute and longer.");
            }
        }
    };

    static auto instance = command::reg(std::make_shared<cmd>());
}