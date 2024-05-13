/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/network.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::cardano;
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
        const network::address addr { "relays-new.cardano-mainnet.iohk.io", "3001" };
        client_manager &ccm = client_manager_async::get();
        "find_tip"_test = [&] {
            auto c = ccm.connect(addr);
            // run a process cycle without requests to test that successive process calls work
            c->process();
            client::find_response resp {};
            c->find_tip([&](client::find_response &&r) {
                resp = std::move(r);
            });
            c->process();
            expect(resp.addr == addr) << resp.addr.host << resp.addr.port;
            expect(std::holds_alternative<point>(resp.res));
            if (std::holds_alternative<point>(resp.res)) {
                const auto &pnt = std::get<point>(resp.res);
                auto min_slot = cardano::slot::from_time(std::chrono::system_clock::now() - std::chrono::seconds { 600 });
                expect(pnt.slot >= min_slot) << pnt.slot;
                expect(pnt.height >= 10'000'000) << pnt.height;
            }
        };

        "find_intersection"_test = [&] {
            auto c = ccm.connect(addr);
            // run a process cycle without requests to test that successive process calls work
            c->process();
            client::find_response resp {};
            point_list points {};
            points.emplace_back(cardano::block_hash::from_hex("5B74C3D89844B010020172ACFBFE2F8FC08D895A7CDD5CF77C7BBD853C4CFB79"), 119975873);
            points.emplace_back(cardano::block_hash::from_hex("F1C8E2B970338F3E1FDDF5AF8BD2F3B648B2D5AD4FB98406A51EEA149479C83B"), 116812786);
            c->find_intersection(points, [&](client::find_response &&r) {
                resp = std::move(r);
            });
            c->process();
            expect(resp.addr == addr) << resp.addr.host << resp.addr.port;
            expect(std::holds_alternative<point_pair>(resp.res));
            if (std::holds_alternative<point_pair>(resp.res)) {
                const auto &[point, tip] = std::get<point_pair>(resp.res);
                expect(point.slot == points[0].slot);
                expect(point.hash == points[0].hash);
                auto min_slot = cardano::slot::from_time(std::chrono::system_clock::now() - std::chrono::seconds { 600 });
                expect(tip.slot >= min_slot) << point.slot;
                expect(tip.height >= 10'000'000) << point.height;
            }
        };

        "fetch_blocks"_test = [&] {
            const auto c = ccm.connect(addr);
            // run a process cycle without requests to test that successive process calls work
            block_list blocks {};
            std::optional<std::string> err {};
            const point from  { cardano::block_hash::from_hex("262C9CDDB771CEBF1A831E31895056BD1134236E594657F3059C2AF667FEACA3"), 120001846 };
            const point to { cardano::block_hash::from_hex("AC262A565E7A0190045DE0BE58AC84669C434786A42518BE097F9F0CEC642058"), 120002096 };
            c->fetch_blocks(from, to, [&](client::block_response &&r) {
                if (r.err) {
                    err = std::move(*r.err);
                    return false;
                }
                logger::debug("received block {} {}", r.block->blk->hash(), r.block->blk->slot());
                blocks.emplace_back(std::move(*r.block));
                return true;
            });
            c->process();
            expect(!err) << *err;
            expect(blocks.size() == 10_ull);
        };

        "fetch_headers"_test = [&] {
            auto c = ccm.connect(addr);
            // run a process cycle without requests to test that successive process calls work
            client::header_response resp {};
            point_list points {};
            points.emplace_back(cardano::block_hash::from_hex("5B74C3D89844B010020172ACFBFE2F8FC08D895A7CDD5CF77C7BBD853C4CFB79"), 119975873);
            c->fetch_headers(points, 10, [&](auto &&r) {
                resp = std::move(r);
            });
            c->process();
            expect(resp.addr == addr) << resp.addr.host << resp.addr.port;
            expect(static_cast<bool>(resp.intersect));
            if (resp.intersect)
                expect(*resp.intersect == points.front());
            expect(std::holds_alternative<header_list>(resp.res));
            if (std::holds_alternative<header_list>(resp.res)) {
                const auto &headers = std::get<header_list>(resp.res);
                expect(headers.size() == 10_ull);
                auto prev_slot = points.front().slot;
                for (const auto &hdr: headers) {
                    expect(hdr.slot >= prev_slot);
                    prev_slot = hdr.slot;
                }
            } else {
                logger::warn("client error: {}", std::get<client::error_msg>(resp.res));
            }
        };

        "fetch_headers byron"_test = [&] {
            auto c = ccm.connect(addr);
            point start_point { cardano::block_hash::from_hex("89D9B5A5B8DDC8D7E5A6795E9774D97FAF1EFEA59B2CAF7EAF9F8C5B32059DF4"), 0 };
            const auto [hdrs, tip] = c->fetch_headers_sync(start_point, 1);
            expect(!hdrs.empty());
            expect(hdrs.front().slot == 0);
            expect(hdrs.front().hash == cardano::block_hash::from_hex("F0F7892B5C333CFFC4B3C4344DE48AF4CC63F55E44936196F365A9EF2244134F"));
        };

        "fetch_headers shelley"_test = [&] {
            auto c = ccm.connect(addr);
            point start_point { cardano::block_hash::from_hex("F8084C61B6A238ACEC985B59310B6ECEC49C0AB8352249AFD7268DA5CFF2A457"), 4492799 };
            const auto [hdrs, tip] = c->fetch_headers_sync(start_point, 1);
            expect(!hdrs.empty());
            expect(hdrs.front().slot == 4492800);
            expect(hdrs.front().hash == cardano::block_hash::from_hex("AA83ACBF5904C0EDFE4D79B3689D3D00FCFC553CF360FD2229B98D464C28E9DE"))
                << fmt::format("{}", hdrs.front().hash);
        };

        "fetch_headers from scratch"_test = [&] {
            auto c = ccm.connect(addr);
            // run a process cycle without requests to test that successive process calls work
            client::header_response resp {};
            point_list points {};
            c->fetch_headers(points, 10, [&](auto &&r) {
                resp = std::move(r);
            });
            c->process();
            expect(resp.addr == addr) << resp.addr.host << resp.addr.port;
            expect(!static_cast<bool>(resp.intersect));
            expect(std::holds_alternative<header_list>(resp.res));
            if (std::holds_alternative<header_list>(resp.res)) {
                const auto &headers = std::get<header_list>(resp.res);
                expect(headers.size() == 10_ull);
                uint64_t prev_slot = 0;
                for (const auto &hdr: headers) {
                    expect(hdr.slot >= prev_slot);
                    prev_slot = hdr.slot;
                }
            } else {
                logger::warn("client error: {}", std::get<client::error_msg>(resp.res));
            }
        };
    };
};