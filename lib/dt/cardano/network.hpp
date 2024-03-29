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
#include <dt/cardano/common.hpp>
#include <dt/cbor.hpp>
#include <dt/cbor-encoder.hpp>
#include <dt/logger.hpp>
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

    struct block_list {
        uint8_vector data {};
        std::vector<size_t> sizes {};
    };

    struct client {
        using error_msg = std::string;

        struct find_response {
            address addr {};
            std::variant<blockchain_point_pair, blockchain_point, error_msg> res { "No response or error has yet been assigned" };
        };
        using find_handler = std::function<void(find_response &&)>;

        struct fetch_response {
            address addr {};
            blockchain_point from {};
            blockchain_point to {};
            std::variant<block_list, error_msg> res {};
        };
        using fetch_handler = std::function<void(fetch_response &&)>;

        explicit client() =default;

        void find_tip(const address &addr, const find_handler &handler)
        {
            blockchain_point_list empty {};
            boost::asio::co_spawn(_ioc, _find_intersection(addr, empty, handler), boost::asio::detached);
        }

        void find_intersection(const address &addr, const blockchain_point_list &points, const find_handler &handler)
        {
            boost::asio::co_spawn(_ioc, _find_intersection(addr, points, handler), boost::asio::detached);
        }

        void fetch_blocks(const address &addr, const blockchain_point &from, const blockchain_point &to, const fetch_handler &handler)
        {
            boost::asio::co_spawn(_ioc, _fetch_blocks(addr, from, to, handler), boost::asio::detached);
        }

        void process()
        {
            try {
                if (_ioc.stopped())
                    _ioc.restart();
                _ioc.run();
            } catch (const std::exception &ex) {
                logger::error("network error: {}", ex.what());
                throw;
            } catch (...) {
                logger::error("unkown error while running a network client");
                throw;
            }
        }
    private:
        boost::asio::io_context _ioc {};
        tcp::resolver _resolver { _ioc };

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
            segment_info recv_info {};
            co_await boost::asio::async_read(socket, boost::asio::buffer(&recv_info, sizeof(recv_info)), boost::asio::use_awaitable);
            if (recv_info.mode() != channel_mode::responder || recv_info.protocol_id() != protocol_id)
                throw error("unexpected message: mode: {} protocol_id: {}", static_cast<int>(recv_info.mode()), static_cast<uint16_t>(recv_info.protocol_id()));
            uint8_vector recv_payload(recv_info.payload_size());
            co_await boost::asio::async_read(socket, boost::asio::buffer(recv_payload.data(), recv_payload.size()), boost::asio::use_awaitable);
            co_return recv_payload;
        }

        boost::asio::awaitable<tcp::socket> _connect_and_handshake(address addr)
        {
            auto results = co_await _resolver.async_resolve(addr.host, addr.port, boost::asio::use_awaitable);
            if (results.empty())
                throw error("DNS resolve for {}:{} returned no results!", addr.host, addr.port);
            tcp::socket socket { _ioc };
            co_await socket.async_connect(*results.begin(), boost::asio::use_awaitable);
            cbor::encoder enc {};
            enc.array(2)
                .uint(0)
                .map(1)
                    .uint(7) // versionNumber
                    .array(2)
                        .uint(764824073) // networkMagic
                        .s_false(); // diffusionMode
            auto resp = co_await _send_request(socket, protocol::handshake, enc.cbor());
            co_return std::move(socket);
        }

        boost::asio::awaitable<void> _find_intersection(address addr, const blockchain_point_list points, const find_handler handler)
        {
            try {
                auto socket = co_await _connect_and_handshake(addr);
                cbor::encoder enc {};
                enc.array(2).uint(4).array(points.size());
                for (const auto &p: points) {
                    enc.array(2).uint(p.slot).bytes(p.hash);
                }
                auto resp = co_await _send_request(socket, protocol::chain_sync, enc.cbor());
                auto resp_cbor = cbor::parse(resp);
                auto &resp_arr = resp_cbor.array();
                switch (resp_arr.at(0).uint()) {
                    case 5: {
                        const auto &point = resp_arr.at(1).array();
                        const auto &tip =  resp_arr.at(2).array();
                        handler(find_response { std::move(addr),
                            blockchain_point_pair {
                                blockchain_point { point.at(1).buf(), point.at(0).uint() },
                                blockchain_point { tip.at(0).array().at(1).buf(), tip.at(0).array().at(0).uint(), tip.at(1).uint() }
                            }
                        });
                        break;
                    }
                    case 6: {
                        const auto &tip =  resp_arr.at(1).array();
                        handler(find_response { std::move(addr),
                            blockchain_point { tip.at(0).array().at(1).buf(), tip.at(0).array().at(0).uint(), tip.at(1).uint() }
                        });
                        break;
                    }
                    default:
                        throw error("unexpected chain_sync message: {}!", resp_arr.at(0).uint());
                }
            } catch (const std::exception &ex) {
                handler(find_response { std::move(addr), fmt::format("query_tip error: {}", ex.what()) });
            } catch (...) {
                handler(find_response { std::move(addr), "query_tip unknown error!" });
            }
        }

        static boost::asio::awaitable<block_list> _receive_blocks(tcp::socket &socket, uint8_vector parse_buf)
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
                                blocks.sizes.emplace_back(buf.size() );
                                blocks.data.reserve(blocks.data.size() + buf.size());
                                std::copy(buf.begin(), buf.end(), std::back_inserter(blocks.data));
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
                segment_info recv_info {};
                co_await boost::asio::async_read(socket, boost::asio::buffer(&recv_info, sizeof(recv_info)), boost::asio::use_awaitable);
                if (recv_info.mode() != channel_mode::responder || recv_info.protocol_id() != protocol::block_fetch)
                    throw error("unexpected message: mode: {} protocol_id: {}", static_cast<int>(recv_info.mode()), static_cast<uint16_t>(recv_info.protocol_id()));
                uint8_vector recv_payload(recv_info.payload_size());
                co_await boost::asio::async_read(socket, boost::asio::buffer(recv_payload.data(), recv_payload.size()), boost::asio::use_awaitable);
                parse_buf << recv_payload;
            }
        }

        boost::asio::awaitable<void> _fetch_blocks(address addr, const blockchain_point from, const blockchain_point to, const fetch_handler handler)
        {
            try {
                auto socket = co_await _connect_and_handshake(addr);
                cbor::encoder enc {};
                enc.array(3).uint(0).array(2).uint(from.slot).bytes(from.hash).array(2).uint(to.slot).bytes(to.hash);
                auto resp = co_await _send_request(socket, protocol::block_fetch, enc.cbor());
                auto resp_cbor = cbor::parse(resp);
                auto &resp_items = resp_cbor.array();
                switch (resp_items.at(0).uint()) {
                    case 2: {
                        resp.erase(resp.begin(), resp.begin() + resp_cbor.size);
                        auto blocks = co_await _receive_blocks(socket, std::move(resp));
                        handler(fetch_response { std::move(addr), std::move(from), std::move(to), std::move(blocks) });
                        break;
                    }
                    case 3: {
                        handler(fetch_response { std::move(addr), std::move(from), std::move(to), "fetch_blocks do not have all requested blocks!" });
                        break;
                    }
                    default:
                        throw error("unexpected chain_sync message: {}!", resp_items.at(0).uint());
                }
            } catch (const std::exception &ex) {
                handler(fetch_response { std::move(addr), std::move(from), std::move(to),fmt::format("fetch_blocks error: {}", ex.what()) });
            } catch (...) {
                handler(fetch_response { std::move(addr), std::move(from), std::move(to), "fetch_blocks unknown error!" });
            }
        }
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_NETWORK_HPP