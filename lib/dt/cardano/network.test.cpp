/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/network.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::cardano::network;

suite cardano_network_suite = [] {
    "cardano::network"_test = [] {
        "segment_info"_test = [] {
            segment_info info { 0x0123ABCD, channel_mode::initiator, protocol::chain_sync, 12345 };
            auto exp = array<uint8_t, 8>::from_hex("0123ABCD00023039");
            buffer act { reinterpret_cast<uint8_t*>(&info), sizeof(info) };
            expect(act == exp) << fmt::format("{} != {}", act, exp);
            expect(info.mode() == channel_mode::initiator) << static_cast<int>(info.mode());
            expect(info.protocol_id() == protocol::chain_sync) << static_cast<int>(info.protocol_id());
            expect(info.payload_size() == 12345);
        };

        "find_tip"_test = [] {
            client c {};
            // run a process cycle without requests to test that successive process calls work
            c.process();
            client::find_response resp {};
            address addr { "relays-new.cardano-mainnet.iohk.io", "3001" };
            c.find_tip(addr, [&](client::find_response &&r) {
                resp = std::move(r);
            });
            c.process();
            expect(resp.addr == addr) << resp.addr.host << resp.addr.port;
            expect(std::holds_alternative<blockchain_point>(resp.res));
            if (std::holds_alternative<blockchain_point>(resp.res)) {
                const auto &point = std::get<blockchain_point>(resp.res);
                auto min_slot = cardano::slot::from_time(std::chrono::system_clock::now() - std::chrono::seconds { 600 });
                expect(point.slot >= min_slot) << point.slot;
                expect(point.height >= 10'000'000) << point.height;
            }
        };

        "find_intersection"_test = [] {
            client c {};
            // run a process cycle without requests to test that successive process calls work
            c.process();
            client::find_response resp {};
            address addr { "relays-new.cardano-mainnet.iohk.io", "3001" };
            blockchain_point_list points {};
            points.emplace_back(cardano::block_hash::from_hex("5B74C3D89844B010020172ACFBFE2F8FC08D895A7CDD5CF77C7BBD853C4CFB79"), 119975873);
            points.emplace_back(cardano::block_hash::from_hex("F1C8E2B970338F3E1FDDF5AF8BD2F3B648B2D5AD4FB98406A51EEA149479C83B"), 116812786);
            c.find_intersection(addr, points, [&](client::find_response &&r) {
                resp = std::move(r);
            });
            c.process();
            expect(resp.addr == addr) << resp.addr.host << resp.addr.port;
            expect(std::holds_alternative<blockchain_point_pair>(resp.res));
            if (std::holds_alternative<blockchain_point_pair>(resp.res)) {
                const auto &[point, tip] = std::get<blockchain_point_pair>(resp.res);
                expect(point.slot == points[0].slot);
                expect(point.hash == points[0].hash);
                auto min_slot = cardano::slot::from_time(std::chrono::system_clock::now() - std::chrono::seconds { 600 });
                expect(tip.slot >= min_slot) << point.slot;
                expect(tip.height >= 10'000'000) << point.height;
            }
        };

        "fetch_blocks"_test = [] {
            client c {};
            // run a process cycle without requests to test that successive process calls work
            client::fetch_response resp {};
            address addr { "relays-new.cardano-mainnet.iohk.io", "3001" };
            blockchain_point from  { cardano::block_hash::from_hex("262C9CDDB771CEBF1A831E31895056BD1134236E594657F3059C2AF667FEACA3"), 120001846 };
            blockchain_point to { cardano::block_hash::from_hex("DCAF9A85D797207CFA3D68E97E277D6F02D420D25BF52005654C4BDCC5E80037"), 120004080 };
            c.fetch_blocks(addr, from, to, [&](client::fetch_response &&r) {
                resp = std::move(r);
            });
            c.process();
            expect(resp.addr == addr) << resp.addr.host << resp.addr.port;
            expect(resp.from == from) << from.slot << from.hash;
            expect(resp.to == to) << to.slot << to.hash;
            expect(std::holds_alternative<block_list>(resp.res));
            if (std::holds_alternative<block_list>(resp.res)) {
                const auto &blocks = std::get<block_list>(resp.res);
                expect(blocks.sizes.size() == 101_ull);
                expect(std::accumulate(blocks.sizes.begin(), blocks.sizes.end(), 0ULL) == 4433711_ull);
                expect(blocks.data.size() == 4433711_ull);
            } else {
                logger::warn("client error: {}", std::get<client::error_msg>(resp.res));
            }
        };
        // get a list of pools from the magic URL
        // select 10 randomly
        // query about tip
        // compare the results
    };
};