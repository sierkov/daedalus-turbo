/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#ifdef _MSC_VER
#   include <SDKDDKVer.h>
#endif
#include <boost/asio.hpp>
#include <dt/cardano/network.hpp>
#include <dt/cbor.hpp>
#include <dt/cbor-encoder.hpp>
#include <dt/logger.hpp>
#include <dt/mutex.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::cardano::network {
    using boost::asio::ip::tcp;

    struct client_async::impl {
        impl(asio::worker &asio_worker): _asio_worker(asio_worker)
        {
        }

        ~impl()
        {
            static constexpr std::chrono::milliseconds sleep_ms { 100 };
            while (_requests.load() > 0) {
                std::this_thread::sleep_for(sleep_ms);
                logger::warn("not all network requests are completed when a client instance is destroyed - waiting");
            }
        }

        void find_intersection_impl(const address &addr, const blockchain_point_list &points, const find_handler &handler)
        {
            ++_requests;
            boost::asio::co_spawn(_asio_worker.io_context(), _find_intersection(addr, points, handler), boost::asio::detached);
        }

        void fetch_headers_impl(const address &addr, const blockchain_point_list &points, const size_t max_blocks, const header_handler &handler)
        {
            ++_requests;
            boost::asio::co_spawn(_asio_worker.io_context(), _fetch_headers(addr, points, max_blocks, handler), boost::asio::detached);
        }

        void fetch_blocks_impl(const address &addr, const blockchain_point &from, const blockchain_point &to, std::optional<size_t> max_blocks, const block_handler &handler)
        {
            ++_requests;
            boost::asio::co_spawn(_asio_worker.io_context(), _fetch_blocks(addr, from, to, max_blocks, handler), boost::asio::detached);
        }

        void process_impl()
        {
            mutex::unique_lock lk { _requests_mutex };
            _requests_cv.wait(lk, [&]{ return _requests.load() == 0; });
        }
    private:
        struct intersect_resp {
            tcp::socket socket;
            std::optional<blockchain_point> intersect {};
            blockchain_point tip {};
        };

        asio::worker &_asio_worker;
        tcp::resolver _resolver { _asio_worker.io_context() };
        alignas(mutex::padding) mutable mutex::unique_lock::mutex_type _requests_mutex {};
        alignas(mutex::padding) std::condition_variable_any _requests_cv {};
        std::atomic_size_t _requests = 0;



        void _decrement_requests()
        {
            if (--_requests == 0)
                _requests_cv.notify_all();
        }

        static boost::asio::awaitable<uint8_vector> _read_response(tcp::socket &socket, protocol protocol_id)
        {
            segment_info recv_info {};
            co_await boost::asio::async_read(socket, boost::asio::buffer(&recv_info, sizeof(recv_info)), boost::asio::use_awaitable);
            uint8_vector recv_payload(recv_info.payload_size());
            co_await boost::asio::async_read(socket, boost::asio::buffer(recv_payload.data(), recv_payload.size()), boost::asio::use_awaitable);
            if (recv_info.mode() != channel_mode::responder || recv_info.protocol_id() != protocol_id) {
                logger::error("unexpected message: mode: {} protocol_id: {} body size: {} body: {}",
                    static_cast<int>(recv_info.mode()), static_cast<uint16_t>(recv_info.protocol_id()), recv_payload.size(), cbor::stringify(recv_payload));
                throw error("unexpected message: mode: {} protocol_id: {}", static_cast<int>(recv_info.mode()), static_cast<uint16_t>(recv_info.protocol_id()));
            }
            co_return recv_payload;
        }

        static boost::asio::awaitable<uint8_vector> _send_request(tcp::socket &socket, protocol protocol_id, const buffer &data)
        {
            if (data.size() >= (1 << 16))
                throw error("payload is larger than allowed: {}!", data.size());
            uint8_vector segment {};
            auto epoch_time = std::chrono::system_clock::now().time_since_epoch();
            auto micros = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::microseconds>(epoch_time).count());
            segment_info send_info { micros, channel_mode::initiator, protocol_id, static_cast<uint16_t>(data.size()) };
            segment << buffer::from(send_info);
            segment << data;
            co_await async_write(socket, boost::asio::const_buffer { segment.data(), segment.size() }, boost::asio::use_awaitable);
            co_return co_await _read_response(socket, protocol_id);
        }

        boost::asio::awaitable<tcp::socket> _connect_and_handshake(address addr)
        {
            auto results = co_await _resolver.async_resolve(addr.host, addr.port, boost::asio::use_awaitable);
            if (results.empty())
                throw error("DNS resolve for {}:{} returned no results!", addr.host, addr.port);
            tcp::socket socket { _asio_worker.io_context() };
            co_await socket.async_connect(*results.begin(), boost::asio::use_awaitable);
            static constexpr uint64_t protocol_ver = 7;
            cbor::encoder enc {};
            enc.array(2)
                .uint(0)
                .map(1)
                    .uint(protocol_ver) // versionNumber
                    .array(2)
                        .uint(764824073) // networkMagic
                        .s_false(); // diffusionMode
            auto resp = co_await _send_request(socket, protocol::handshake, enc.cbor());
            auto resp_cbor = cbor::parse(resp);
            auto &resp_items = resp_cbor.array();
            if (resp_items.at(0).uint() != 1ULL)
                throw error("peer at {}:{} refused the protocol version {}!", addr.host, addr.port, protocol_ver);
            if (resp_items.at(1).uint() != protocol_ver)
                throw error("peer at {}:{} ignored the requested protocol version {}!", addr.host, addr.port, protocol_ver);
            co_return std::move(socket);
        }

        boost::asio::awaitable<intersect_resp>
        _find_intersection_do(const address &addr, const blockchain_point_list &points)
        {
            intersect_resp iresp { co_await _connect_and_handshake(addr) };
            cbor::encoder enc {};
            enc.array(2).uint(4).array(points.size());
            for (const auto &p: points) {
                enc.array(2).uint(p.slot).bytes(p.hash);
            }
            auto resp = co_await _send_request(iresp.socket, protocol::chain_sync, enc.cbor());
            auto resp_cbor = cbor::parse(resp);
            auto &resp_arr = resp_cbor.array();
            switch (resp_arr.at(0).uint()) {
                case 5: {
                    const auto &point = resp_arr.at(1).array();
                    const auto &tip =  resp_arr.at(2).array();
                    iresp.intersect = blockchain_point { point.at(1).buf(), point.at(0).uint() };
                    iresp.tip = blockchain_point { tip.at(0).array().at(1).buf(), tip.at(0).array().at(0).uint(), tip.at(1).uint() };
                    break;
                }
                case 6: {
                    const auto &tip =  resp_arr.at(1).array();
                    iresp.tip = blockchain_point { tip.at(0).array().at(1).buf(), tip.at(0).array().at(0).uint(), tip.at(1).uint() };
                    break;
                }
                default:
                    throw error("unexpected chain_sync message: {}!", resp_arr.at(0).uint());
            }
            co_return iresp;
        }

        boost::asio::awaitable<void> _find_intersection(address addr, const blockchain_point_list points, const find_handler handler)
        {
            try {
                auto iresp = co_await _find_intersection_do(addr, points);
                if (iresp.intersect)
                    handler(find_response { std::move(addr), blockchain_point_pair { *iresp.intersect, iresp.tip } });
                else
                    handler(find_response { std::move(addr), iresp.tip });
                _decrement_requests();
            } catch (const std::exception &ex) {
                handler(find_response { std::move(addr), fmt::format("query_tip error: {}", ex.what()) });
                _decrement_requests();
            } catch (...) {
                handler(find_response { std::move(addr), "query_tip unknown error!" });
                _decrement_requests();
            }
        }

        static boost::asio::awaitable<block_list> _receive_blocks(tcp::socket &socket, uint8_vector parse_buf, std::optional<size_t> max_blocks)
        {
            block_list blocks {};
            for (;;) {
                while (!parse_buf.empty()) {
                    try {
                        auto resp_cbor = cbor::parse(parse_buf);
                        auto &resp_items = resp_cbor.array();
                        switch (resp_items.at(0).uint()) {
                            case 4: {
                                const auto &buf = resp_items.at(1).tag().second->buf();
                                block_parsed bp {};
                                bp.data = std::make_unique<uint8_vector>(buf);
                                bp.cbor = std::make_unique<cbor_value>(cbor::parse(*bp.data));
                                bp.blk = cardano::make_block(*bp.cbor, 0);
                                blocks.emplace_back(std::move(bp));
                                if (max_blocks && blocks.size() >= *max_blocks)
                                    co_return blocks;
                                break;
                            }
                            case 5: {
                                co_return blocks;
                            }
                            default:
                                throw error("unexpected chain_sync message: {}!", resp_items.at(0).uint());
                        }
                        parse_buf.erase(parse_buf.begin(), parse_buf.begin() + resp_cbor.size);
                    } catch (const cbor_incomplete_data_error &) {
                        // exit the while loop and wait for more data
                        break;
                    }
                }
                parse_buf << co_await _read_response(socket, protocol::block_fetch);
            }
        }

        boost::asio::awaitable<void> _fetch_blocks(address addr, const blockchain_point from, const blockchain_point to,
            std::optional<size_t> max_blocks, const block_handler handler)
        {
            try {
                auto socket = co_await _connect_and_handshake(addr);
                cbor::encoder enc {};
                enc.array(3).uint(0);
                enc.array(2).uint(from.slot).bytes(from.hash);
                enc.array(2).uint(to.slot).bytes(to.hash);
                auto resp = co_await _send_request(socket, protocol::block_fetch, enc.cbor());
                auto resp_cbor = cbor::parse(resp);
                auto &resp_items = resp_cbor.array();
                switch (resp_items.at(0).uint()) {
                    case 2: {
                        resp.erase(resp.begin(), resp.begin() + resp_cbor.size);
                        auto blocks = co_await _receive_blocks(socket, std::move(resp), max_blocks);
                        handler(block_response { std::move(addr), std::move(from), std::move(to), std::move(blocks) });
                        break;
                    }
                    case 3: {
                        handler(block_response { std::move(addr), std::move(from), std::move(to), "fetch_blocks do not have all requested blocks!" });
                        break;
                    }
                    default:
                        throw error("unexpected chain_sync message: {}!", resp_items.at(0).uint());
                }
                _decrement_requests();
            } catch (const std::exception &ex) {
                handler(block_response { std::move(addr), std::move(from), std::move(to),fmt::format("fetch_blocks error: {}", ex.what()) });
                _decrement_requests();
            } catch (...) {
                handler(block_response { std::move(addr), std::move(from), std::move(to), "fetch_blocks unknown error!" });
                _decrement_requests();
            }
        }

        boost::asio::awaitable<void> _fetch_headers(address addr, const blockchain_point_list points, const size_t max_blocks, const header_handler handler)
        {
            try {
                header_list headers {};
                auto iresp = co_await _find_intersection_do(addr, points);
                cbor::encoder msg_req_next {};
                msg_req_next.array(1).uint(0);
                while (headers.size() < max_blocks) {
                    auto parse_buf = co_await _send_request(iresp.socket, protocol::chain_sync, msg_req_next.cbor());
                    auto resp_cbor = cbor::parse(parse_buf);
                    const auto &resp_items = resp_cbor.array();
                    if (resp_items.at(0).uint() == 1) // MsgAwaitReply
                        break;
                    if (resp_items.at(0).uint() == 3) {
                        const auto &point = resp_items.at(1).array();
                        const auto &tip =  resp_items.at(2).array();
                        std::optional<blockchain_point> intersect {};
                        if (!point.empty())
                            intersect = blockchain_point { point.at(1).buf(), point.at(0).uint() };
                        iresp.tip = blockchain_point { tip.at(0).array().at(1).buf(), tip.at(0).array().at(0).uint(), tip.at(1).uint() };
                        if (iresp.intersect == intersect)
                            continue;
                        break;
                    }
                    if (resp_items.at(0).uint() != 2) // !MsgRollForward
                        throw error("unexpected chain_sync message: {}!", resp_items.at(0).uint());
                    const auto &hdr_items = resp_items.at(1).array();
                    const auto &tip =  resp_items.at(2).array();
                    iresp.tip = blockchain_point { tip.at(0).array().at(1).buf(), tip.at(0).array().at(0).uint(), tip.at(1).uint() };
                    auto era = hdr_items.at(0).uint();
                    cbor::encoder block_tuple {};
                    if (era == 0) {
                        auto hdr_era = hdr_items.at(1).array().at(0).array().at(0).uint();
                        block_tuple.array(2).uint(hdr_era).array(1);
                        const auto &hdr_buf = hdr_items.at(1).array().at(1).tag().second->buf();
                        std::copy(hdr_buf.begin(), hdr_buf.end(), std::back_inserter(block_tuple.cbor()));
                    } else {
                        block_tuple.array(2).uint(era).array(1);
                        const auto &hdr_buf = hdr_items.at(1).tag().second->buf();
                        std::copy(hdr_buf.begin(), hdr_buf.end(), std::back_inserter(block_tuple.cbor()));
                    }
                    auto hdr_cbor = cbor::parse(block_tuple.cbor());
                    auto blk = cardano::make_block(hdr_cbor, 0);
                    auto blk_hash = blk->hash();
                    auto blk_slot = blk->slot();
                    auto blk_height = blk->height();
                    headers.emplace_back(blk_hash, blk_slot, blk_height);
                    if (blk_hash == iresp.tip.hash)
                        break;
                }
                handler(header_response { std::move(addr), iresp.intersect, iresp.tip, std::move(headers) });
                _decrement_requests();
            } catch (const std::exception &ex) {
                handler(header_response { .addr=std::move(addr), .res=fmt::format("fetch_headers error: {}", ex.what()) });
                _decrement_requests();
            } catch (...) {
                handler(header_response { .addr=std::move(addr), .res="fetch_headers unknown error!" });
                _decrement_requests();
            }
        }
    };

    client_async &client_async::get()
    {
        static client_async c {};
        return c;
    }

    client_async::client_async(asio::worker &asio_worker): _impl { std::make_unique<impl>(asio_worker) }
    {
    }

    client_async::~client_async() =default;

    void client_async::_find_intersection_impl(const address &addr, const blockchain_point_list &points, const find_handler &handler)
    {
        _impl->find_intersection_impl(addr, points, handler);
    }

    void client_async::_fetch_headers_impl(const address &addr, const blockchain_point_list &points, const size_t max_blocks, const header_handler &handler)
    {
        _impl->fetch_headers_impl(addr, points, max_blocks, handler);
    }

    void client_async::_fetch_blocks_impl(const address &addr, const blockchain_point &from, const blockchain_point &to, std::optional<size_t> max_blocks, const block_handler &handler)
    {
        _impl->fetch_blocks_impl(addr, from, to, max_blocks, handler);
    }

    void client_async::_process_impl()
    {
        _impl->process_impl();
    }
}