/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_NETWORK_HPP
#define DAEDALUS_TURBO_CARDANO_NETWORK_HPP

#ifdef _MSC_VER
#   include <SDKDDKVer.h>
#endif
#include <boost/asio.hpp>
#include <dt/asio.hpp>
#include <dt/cardano.hpp>
#include <dt/cbor.hpp>
#include <dt/cbor-encoder.hpp>
#include <dt/logger.hpp>
#include <dt/mutex.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::cardano::network {
    using boost::asio::ip::tcp;

    enum class protocol: uint16_t {
        handshake = 0,
        chain_sync = 2,
        block_fetch = 3,
        tx_submission = 4,
        keep_alive = 8
    };

    enum class channel_mode: uint8_t {
        initiator = 0,
        responder = 1
    };

    struct segment_info {
        explicit segment_info() =default;

        explicit segment_info(uint32_t time, channel_mode mode, protocol pid, uint16_t size)
            : _time_us { host_to_net(time) }, _meta { host_to_net(_mode(mode) | _protocol_id(pid) | static_cast<uint32_t>(size) ) }
        {
        }

        channel_mode mode() const
        {
            auto host_meta = net_to_host(_meta);
            return (host_meta >> 31) & 1 ? channel_mode::responder : channel_mode::initiator;
        }

        protocol protocol_id() const
        {
            auto host_meta = net_to_host(_meta);
            auto pid = static_cast<uint16_t>((host_meta >> 16) & 0x7FFF);
            return static_cast<protocol>(pid);
        }

        uint16_t payload_size() const
        {
            auto host_meta = net_to_host(_meta);
            return static_cast<uint16_t>(host_meta & 0xFFFF);
        }
    private:
        static uint32_t _mode(channel_mode m)
        {
            return m == channel_mode::responder ? 1U << 31U : 0U;
        }

        static uint32_t _protocol_id(protocol protocol_id)
        {
            return (static_cast<uint32_t>(protocol_id) & 0x7FFFU) << 16U;
        }

        uint32_t _time_us = 0;
        uint32_t _meta = 0;
    };
    static_assert(sizeof(segment_info) == 8);

    struct blockchain_point {
        cardano::block_hash hash {};
        cardano::slot slot {};
        uint64_t height = 0;

        bool operator==(const auto &o) const
        {
            return hash == o.hash && slot == o.slot;
        }
    };
    using blockchain_point_pair = std::pair<blockchain_point, blockchain_point>;
    using blockchain_point_list = std::vector<blockchain_point>;

    struct address {
        std::string host {};
        std::string port {};

        bool operator==(const auto &o) const
        {
            return host == o.host && port == o.port;
        }

        bool operator<(const auto &o) const
        {
            if (host == o.host)
                return port < o.port;
            return host < o.host;
        }
    };

    struct block_parsed {
        std::unique_ptr<uint8_vector> data {};
        std::unique_ptr<cbor_value> cbor {};
        std::unique_ptr<cardano::block_base> blk {};
    };
    using block_list = std::vector<block_parsed>;
    using header_list = std::vector<blockchain_point>;

    struct client {
        using error_msg = std::string;

        struct find_response {
            address addr{};
            std::variant<blockchain_point_pair, blockchain_point, error_msg> res{
                    "No response or error has yet been assigned"};
        };
        using find_handler = std::function<void(find_response &&)>;

        struct block_response {
            address addr{};
            blockchain_point from{};
            blockchain_point to{};
            std::variant<block_list, error_msg> res{};
        };
        using block_handler = std::function<void(block_response &&)>;

        struct header_response {
            address addr{};
            std::optional<blockchain_point> intersect{};
            std::optional<blockchain_point> tip{};
            std::variant<header_list, error_msg> res{};
        };
        using header_handler = std::function<void(header_response &&)>;

        virtual ~client() = default;

        void find_tip(const address &addr, const find_handler &handler) {
            blockchain_point_list empty{};
            _find_intersection_impl(addr, empty, handler);
        }

        void find_intersection(const address &addr, const blockchain_point_list &points, const find_handler &handler) {
            _find_intersection_impl(addr, points, handler);
        }

        void fetch_headers(const address &addr, const blockchain_point_list &points, const size_t max_blocks,
                           const header_handler &handler) {
            _fetch_headers_impl(addr, points, max_blocks, handler);
        }

        std::pair<header_list, blockchain_point> fetch_headers_sync(const address &addr, const blockchain_point_list &points, const size_t max_blocks)
        {
            client::header_response iresp {};
            fetch_headers(addr, points, max_blocks, [&](auto &&r) {
                iresp = r;
            });
            process();
            if (std::holds_alternative<client::error_msg>(iresp.res))
                throw error("fetch_headers error: {}", std::get<client::error_msg>(iresp.res));
            if (!iresp.tip)
                throw error("no tip information received!");
            const auto &headers = std::get<header_list>(iresp.res);
            if (headers.empty())
                throw error("received and empty header list");
            return std::make_pair(std::move(headers), std::move(*iresp.tip));
        }

        std::pair<header_list, blockchain_point> fetch_headers_sync(const address &addr, const std::optional<blockchain_point> &local_tip, const size_t max_blocks)
        {
            blockchain_point_list points {};
            if (local_tip)
                points.emplace_back(*local_tip);
            return fetch_headers_sync(addr, points, max_blocks);
        }

        void fetch_blocks(const address &addr, const blockchain_point &from, const blockchain_point &to,
                          std::optional<size_t> max_blocks, const block_handler &handler) {
            _fetch_blocks_impl(addr, from, to, max_blocks, handler);
        }

        block_list fetch_blocks_sync(const address &addr, const blockchain_point &from, const blockchain_point &to,
                                         std::optional<size_t> max_blocks)
        {
            block_response resp {};
            fetch_blocks(addr, from, to, max_blocks, [&resp] (auto &&r){
                resp = std::move(r);
            });
            process();
            if (std::holds_alternative<client::error_msg>(resp.res))
                throw error("fetch_blocks error: {}", std::get<client::error_msg>(resp.res));
            block_list blocks { std::move(std::get<block_list>(resp.res)) };
            if (blocks.empty())
                throw error("received and empty header list");
            return blocks;
        }

        void process()
        {
            _process_impl();
        }
    private:
        virtual void _find_intersection_impl(const address &/*addr*/, const blockchain_point_list &/*points*/, const find_handler &/*handler*/)
        {
            throw error("cardano::network::client::_find_intersection_impl not implemented!");
        }

        virtual void _fetch_headers_impl(const address &/*addr*/, const blockchain_point_list &/*points*/, const size_t /*max_blocks*/, const header_handler &/*handler*/)
        {
            throw error("cardano::network::client::_fetch_headers_impl not implemented!");
        }

        virtual void _fetch_blocks_impl(const address &/*addr*/, const blockchain_point &/*from*/, const blockchain_point &/*to*/, std::optional<size_t> /*max_blocks*/, const block_handler &/*handler*/)
        {
            throw error("cardano::network::client::_fetch_blocks_impl not implemented!");
        }

        virtual void _process_impl()
        {
            throw error("cardano::network::client::_process_impl not implemented!");
        }
    };

    struct client_async: client {
        static client_async &get()
        {
            static client_async c {};
            return c;
        }

        explicit client_async(asio::worker &asio_worker=asio::worker::get()): _asio_worker { asio_worker }
        {
        }

        ~client_async() override
        {
            static constexpr std::chrono::milliseconds sleep_ms { 100 };
            while (_requests.load() > 0) {
                std::this_thread::sleep_for(sleep_ms);
                logger::warn("not all network requests are completed when a client instance is destroyed - waiting");
            }
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

        void _find_intersection_impl(const address &addr, const blockchain_point_list &points, const find_handler &handler) override
        {
            ++_requests;
            boost::asio::co_spawn(_asio_worker.io_context(), _find_intersection(addr, points, handler), boost::asio::detached);
        }

        void _fetch_headers_impl(const address &addr, const blockchain_point_list &points, const size_t max_blocks, const header_handler &handler) override
        {
            ++_requests;
            boost::asio::co_spawn(_asio_worker.io_context(), _fetch_headers(addr, points, max_blocks, handler), boost::asio::detached);
        }

        void _fetch_blocks_impl(const address &addr, const blockchain_point &from, const blockchain_point &to, std::optional<size_t> max_blocks, const block_handler &handler) override
        {
            ++_requests;
            boost::asio::co_spawn(_asio_worker.io_context(), _fetch_blocks(addr, from, to, max_blocks, handler), boost::asio::detached);
        }

        void _process_impl() override
        {
            mutex::unique_lock lk { _requests_mutex };
            _requests_cv.wait(lk, [&]{ return _requests.load() == 0; });
        }

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
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::cardano::network::blockchain_point>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "({}, {})", v.hash, v.slot);
        }
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_NETWORK_HPP