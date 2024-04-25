/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_NETWORK_HPP
#define DAEDALUS_TURBO_CARDANO_NETWORK_HPP

#include <dt/asio.hpp>
#include <dt/cardano.hpp>
#include <dt/cbor.hpp>
#include <dt/cbor-encoder.hpp>
#include <dt/logger.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::cardano::network {
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

        struct intersection_info {
            blockchain_point tip {};
            std::optional<blockchain_point> isect {};
        };

        struct find_response {
            address addr{};
            std::variant<blockchain_point_pair, blockchain_point, error_msg> res{"No response or error has yet been assigned"};
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

        blockchain_point find_tip_sync(const address &addr)
        {
            find_response iresp {};
            _find_intersection_impl(addr, {}, [&](auto &&r) { iresp = std::move(r); });
            process();
            if (std::holds_alternative<error_msg>(iresp.res))
                throw error("find_tip error: {}", std::get<error_msg>(iresp.res));
            if (std::holds_alternative<blockchain_point>(iresp.res))
                return std::get<blockchain_point>(iresp.res);
            if (std::holds_alternative<blockchain_point_pair>(iresp.res))
                return std::get<blockchain_point_pair>(iresp.res).second;
            throw error("internal error: find_tip received an unsupported response type");
        }

        intersection_info find_intersection_sync(const address &addr, const blockchain_point_list &points)
        {
            find_response iresp {};
            _find_intersection_impl(addr, points, [&](auto &&r) { iresp = std::move(r); });
            process();
            if (std::holds_alternative<error_msg>(iresp.res))
                throw error("find_intersection error: {}", std::get<error_msg>(iresp.res));
            if (std::holds_alternative<blockchain_point>(iresp.res))
                return { std::get<blockchain_point>(iresp.res) };
            if (std::holds_alternative<blockchain_point_pair>(iresp.res)) {
                auto &&[isect, tip] = std::get<blockchain_point_pair>(iresp.res);
                return { std::move(tip), std::move(isect) };
            }
            throw error("internal error: find_intersection received an unsupported response type");
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
                throw error("received an empty header list");
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
        static client_async &get();
        explicit client_async(asio::worker &asio_worker=asio::worker::get());
        ~client_async() override;
    private:
        struct impl;
        std::unique_ptr<impl> _impl;

        void _find_intersection_impl(const address &addr, const blockchain_point_list &points, const find_handler &handler) override;
        void _fetch_headers_impl(const address &addr, const blockchain_point_list &points, const size_t max_blocks, const header_handler &handler) override;
        void _fetch_blocks_impl(const address &addr, const blockchain_point &from, const blockchain_point &to, std::optional<size_t> max_blocks, const block_handler &handler) override;
        void _process_impl() override;
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