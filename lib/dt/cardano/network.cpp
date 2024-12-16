/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#ifdef _MSC_VER
#   include <SDKDDKVer.h>
#endif
#include <condition_variable>
#include <boost/asio.hpp>
#include <dt/cardano/network.hpp>
#include <dt/cbor.hpp>
#include <dt/cbor/encoder.hpp>
#include <dt/logger.hpp>
#include <dt/mutex.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::cardano::network {
    using boost::asio::ip::tcp;

    struct client_connection::impl {
        impl(const address &addr, const cardano::config &cfg, asio::worker &asio_worker)
            : _addr { addr }, _protocol_magic { json::value_to<uint64_t>(cfg.byron_genesis.at("protocolConsts").at("protocolMagic"))  },
                _asio_worker(asio_worker)
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

        void find_intersection_impl(const point_list &points, const find_handler &handler)
        {
            ++_requests;
            boost::asio::co_spawn(_asio_worker.io_context(), _find_intersection(points, handler), boost::asio::detached);
        }

        void fetch_headers_impl(const point_list &points, const size_t max_blocks, const header_handler &handler)
        {
            ++_requests;
            boost::asio::co_spawn(_asio_worker.io_context(), _fetch_headers(points, max_blocks, handler), boost::asio::detached);
        }

        void fetch_blocks_impl(const point &from, const point &to, const block_handler &handler)
        {
            ++_requests;
            boost::asio::co_spawn(_asio_worker.io_context(), _fetch_blocks(from, to, handler), boost::asio::detached);
        }

        void process_impl(scheduler *sched)
        {
            static constexpr std::chrono::milliseconds wait_period { 100 };
            for (;;) {
                {
                    mutex::unique_lock lk { _requests_mutex };
                    if (_requests_cv.wait_for(lk, wait_period, [&]{ return _requests.load() == 0; }))
                        break;
                }
                if (sched)
                    sched->process_once();
            }

        }

        void reset_impl()
        {
            mutex::unique_lock lk { _requests_mutex };
            const auto num_reqs = _requests.load();
            if (num_reqs > 0)
                throw error(fmt::format("a client instances can be reset only when there are no active requests but there are: {}", num_reqs));
            _conn.reset();
        }
    private:
        struct perf_stats {
            std::atomic<std::chrono::system_clock::time_point> last_report_time = std::chrono::system_clock::now();
            std::atomic_size_t bytes = 0;

            void report(asio::worker &asio_w, const size_t bytes_downloaded)
            {
                const auto new_bytes = bytes.fetch_add(bytes_downloaded, std::memory_order_relaxed) + bytes_downloaded;
                for (;;) {
                    const auto now = std::chrono::system_clock::now();
                    auto prev_time = last_report_time.load(std::memory_order_relaxed);
                    if (prev_time + std::chrono::seconds { 5 } > now)
                        break;
                    if (last_report_time.compare_exchange_strong(prev_time, now, std::memory_order_relaxed, std::memory_order_relaxed)) {
                        const double duration = std::chrono::duration_cast<std::chrono::duration<double>>(now - prev_time).count();
                        asio_w.internet_speed_report(static_cast<double>(new_bytes) * 8 / 1'000'000 / duration);
                        bytes.fetch_sub(new_bytes, std::memory_order_relaxed);
                        break;
                    }
                }
            }
        };

        const address _addr;
        const uint64_t _protocol_magic;
        asio::worker &_asio_worker;
        tcp::resolver _resolver { _asio_worker.io_context() };
        std::optional<tcp::socket> _conn {};
        alignas(mutex::padding) mutable mutex::unique_lock::mutex_type _requests_mutex {};
        alignas(mutex::padding) std::condition_variable_any _requests_cv {};
        std::atomic_size_t _requests = 0;
        perf_stats _stats {};

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
                throw error(fmt::format("unexpected message: mode: {} protocol_id: {}", static_cast<int>(recv_info.mode()), static_cast<uint16_t>(recv_info.protocol_id())));
            }
            co_return recv_payload;
        }

        static boost::asio::awaitable<uint8_vector> _send_request(tcp::socket &socket, protocol protocol_id, const buffer &data)
        {
            if (data.size() >= (1 << 16))
                throw error(fmt::format("payload is larger than allowed: {}!", data.size()));
            uint8_vector segment {};
            auto epoch_time = std::chrono::system_clock::now().time_since_epoch();
            auto micros = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::microseconds>(epoch_time).count());
            segment_info send_info { micros, channel_mode::initiator, protocol_id, static_cast<uint16_t>(data.size()) };
            segment << buffer::from(send_info);
            segment << data;
            co_await async_write(socket, boost::asio::const_buffer { segment.data(), segment.size() }, boost::asio::use_awaitable);
            co_return co_await _read_response(socket, protocol_id);
        }

        boost::asio::awaitable<tcp::socket> _connect_and_handshake()
        {
            auto results = co_await _resolver.async_resolve(_addr.host, _addr.port, boost::asio::use_awaitable);
            if (results.empty())
                throw error(fmt::format("DNS resolve for {}:{} returned no results!", _addr.host, _addr.port));
            tcp::socket socket { _asio_worker.io_context() };
            co_await socket.async_connect(*results.begin(), boost::asio::use_awaitable);
            static constexpr uint64_t protocol_ver = 13;
            cbor::encoder enc {};
            enc.array(2)
                    .uint(0)
                    .map(1)
                    .uint(protocol_ver) // versionNumber
                    .array(4)
                    .uint(_protocol_magic) // networkMagic
                    .s_false() // initiatorOnlyDiffusionMode
                    .uint(0)   // peerSharing
                    .s_false(); // diffusionMode
            auto resp = co_await _send_request(socket, protocol::handshake, enc.cbor());
            auto resp_cbor = cbor::parse(resp);
            auto &resp_items = resp_cbor.array();
            if (resp_items.at(0).uint() != 1ULL)
                throw error(fmt::format("peer at {}:{} refused the protocol version {}: {}!", _addr.host, _addr.port, protocol_ver, resp_cbor));
            if (resp_items.at(1).uint() != protocol_ver)
                throw error(fmt::format("peer at {}:{} ignored the requested protocol version {}!", _addr.host, _addr.port, protocol_ver));
            co_return socket;
        }

        boost::asio::awaitable<intersection_info>
        _find_intersection_do(const point_list &points)
        {
            if (!_conn)
                _conn = co_await _connect_and_handshake();
            intersection_info isect {};
            cbor::encoder enc {};
            enc.array(2).uint(4).array(points.size());
            for (const auto &p: points) {
                enc.array(2).uint(p.slot).bytes(p.hash);
            }
            auto resp = co_await _send_request(*_conn, protocol::chain_sync, enc.cbor());
            auto resp_cbor = cbor::parse(resp);
            auto &resp_arr = resp_cbor.array();
            switch (resp_arr.at(0).uint()) {
                case 5: {
                    const auto &pnt = resp_arr.at(1).array();
                    const auto &tip =  resp_arr.at(2).array();
                    isect.isect = point { pnt.at(1).buf(), pnt.at(0).uint() };
                    isect.tip = point { tip.at(0).array().at(1).buf(), tip.at(0).array().at(0).uint(), tip.at(1).uint() };
                    break;
                }
                case 6: {
                    const auto &tip =  resp_arr.at(1).array();
                    isect.tip = point { tip.at(0).array().at(1).buf(), tip.at(0).array().at(0).uint(), tip.at(1).uint() };
                    break;
                }
                default:
                    throw error(fmt::format("unexpected chain_sync message: {}!", resp_arr.at(0).uint()));
            }
            co_return isect;
        }

        boost::asio::awaitable<void> _find_intersection(const point_list points, const find_handler handler)
        {
            try {
                const auto isect = co_await _find_intersection_do(points);
                if (isect.isect)
                    handler(find_response { _addr, point_pair { *isect.isect, isect.tip } });
                else
                    handler(find_response { _addr, isect.tip });
                _decrement_requests();
            } catch (const std::exception &ex) {
                handler(find_response { _addr, fmt::format("query_tip error: {}", ex.what()) });
                _decrement_requests();
                _conn.reset();
            } catch (...) {
                handler(find_response { _addr, "query_tip unknown error!" });
                _decrement_requests();
                _conn.reset();
            }
        }

        static boost::asio::awaitable<void> _receive_blocks(tcp::socket &socket, uint8_vector parse_buf, const block_handler &handler)
        {
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
                                if (!handler(block_response { std::move(bp) }))
                                    co_return;
                                break;
                            }
                            case 5: {
                                co_return;
                            }
                            default:
                                throw error(fmt::format("unexpected chain_sync message: {}!", resp_items.at(0).uint()));
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

        // block_handler must be a copy so that the handler is owned by the coroutine!
        boost::asio::awaitable<void> _fetch_blocks(const point from, const point to, const block_handler handler)
        {
            try {
                if (!_conn)
                    _conn = co_await _connect_and_handshake();
                cbor::encoder enc {};
                enc.array(3).uint(0);
                enc.array(2).uint(from.slot).bytes(from.hash);
                enc.array(2).uint(to.slot).bytes(to.hash);
                auto resp = co_await _send_request(*_conn, protocol::block_fetch, enc.cbor());
                auto resp_cbor = cbor::parse(resp);
                auto &resp_items = resp_cbor.array();
                switch (resp_items.at(0).uint()) {
                    case 2: {
                        resp.erase(resp.begin(), resp.begin() + resp_cbor.size);
                        co_await _receive_blocks(*_conn, std::move(resp), [&](block_response &&blk) {
                            if (blk.block)
                                _stats.report(_asio_worker, blk.block->data->size());
                            return handler(std::move(blk));
                        });
                        break;
                    }
                    case 3: {
                        handler(block_response { {}, "fetch_blocks do not have all requested blocks!" });
                        break;
                    }
                    default:
                        throw error(fmt::format("unexpected chain_sync message: {}!", resp_items.at(0).uint()));
                }
                _decrement_requests();
            } catch (const std::exception &ex) {
                handler(block_response { {}, fmt::format("fetch_blocks error: {}", ex.what()) });
                _decrement_requests();
                _conn.reset();
            } catch (...) {
                handler(block_response { {}, "fetch_blocks unknown error!" });
                _decrement_requests();
                _conn.reset();
            }
        }

        boost::asio::awaitable<void> _fetch_headers(const point_list points, const size_t max_blocks, const header_handler handler)
        {
            try {
                header_list headers {};
                auto isect = co_await _find_intersection_do(points);
                cbor::encoder msg_req_next {};
                msg_req_next.array(1).uint(0);
                while (headers.size() < max_blocks) {
                    auto parse_buf = co_await _send_request(*_conn, protocol::chain_sync, msg_req_next.cbor());
                    auto resp_cbor = cbor::parse(parse_buf);
                    const auto &resp_items = resp_cbor.array();
                    if (resp_items.at(0).uint() == 1) // MsgAwaitReply
                        break;
                    if (resp_items.at(0).uint() == 3) {
                        const auto &pnt = resp_items.at(1).array();
                        const auto &tip =  resp_items.at(2).array();
                        std::optional<point> intersect {};
                        if (!pnt.empty())
                            intersect = point { pnt.at(1).buf(), pnt.at(0).uint() };
                        isect.tip = point { tip.at(0).array().at(1).buf(), tip.at(0).array().at(0).uint(), tip.at(1).uint() };
                        if (isect.isect == intersect)
                            continue;
                        break;
                    }
                    if (resp_items.at(0).uint() != 2) // !MsgRollForward
                        throw error(fmt::format("unexpected chain_sync message: {}!", resp_items.at(0).uint()));
                    const auto &hdr_items = resp_items.at(1).array();
                    const auto &tip =  resp_items.at(2).array();
                    isect.tip = point { tip.at(0).array().at(1).buf(), tip.at(0).array().at(0).uint(), tip.at(1).uint() };
                    auto era = hdr_items.at(0).uint();
                    cbor::encoder block_tuple {};
                    if (era == 0) {
                        auto hdr_era = hdr_items.at(1).array().at(0).array().at(0).uint();
                        block_tuple.array(2).uint(hdr_era).array(1);
                        const auto &hdr_buf = hdr_items.at(1).array().at(1).tag().second->buf();
                        std::copy(hdr_buf.begin(), hdr_buf.end(), std::back_inserter(block_tuple.cbor()));
                    } else {
                        block_tuple.array(2).uint(era + 1).array(1);
                        const auto &hdr_buf = hdr_items.at(1).tag().second->buf();
                        std::copy(hdr_buf.begin(), hdr_buf.end(), std::back_inserter(block_tuple.cbor()));
                    }
                    auto hdr_cbor = cbor::parse(block_tuple.cbor());
                    auto blk = cardano::make_block(hdr_cbor, 0);
                    auto blk_hash = blk->hash();
                    auto blk_slot = blk->slot();
                    auto blk_height = blk->height();
                    headers.emplace_back(blk_hash, blk_slot, blk_height);
                    if (blk_hash == isect.tip.hash)
                        break;
                }
                handler(header_response { _addr, isect.isect, isect.tip, std::move(headers) });
                _decrement_requests();
            } catch (const std::exception &ex) {
                handler(header_response { .addr=_addr, .res=fmt::format("fetch_headers error: {}", ex.what()) });
                _decrement_requests();
                _conn.reset();
            } catch (...) {
                handler(header_response { .addr=_addr, .res="fetch_headers unknown error!" });
                _decrement_requests();
                _conn.reset();
            }
        }
    };

    client_connection::client_connection(const address &addr, const cardano::config &cfg, asio::worker &asio_worker)
        : client { addr }, _impl { std::make_unique<impl>(addr, cfg, asio_worker) }
    {
    }

    client_connection::~client_connection() =default;

    void client_connection::_find_intersection_impl(const point_list &points, const find_handler &handler)
    {
        _impl->find_intersection_impl(points, handler);
    }

    void client_connection::_fetch_headers_impl(const point_list &points, const size_t max_blocks, const header_handler &handler)
    {
        _impl->fetch_headers_impl(points, max_blocks, handler);
    }

    void client_connection::_fetch_blocks_impl(const point &from, const point &to, const block_handler &handler)
    {
        _impl->fetch_blocks_impl(from, to, handler);
    }

    void client_connection::_process_impl(scheduler *sched)
    {
        _impl->process_impl(sched);
    }

    void client_connection::_reset_impl()
    {
        _impl->reset_impl();
    }

    client_manager_async &client_manager_async::get()
    {
        static client_manager_async m {};
        return m;
    }

    std::unique_ptr<client> client_manager_async::_connect_impl(const address &addr, const cardano::config &cfg, asio::worker &asio_worker)
    {
        return std::make_unique<client_connection>(addr, cfg, asio_worker);
    }
}