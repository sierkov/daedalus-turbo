/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PEER_SELECTION_HPP
#define DAEDALUS_TURBO_PEER_SELECTION_HPP

#include <chrono>
#include <random>
#include <boost/container/flat_set.hpp>
#include <dt/config.hpp>
#include <dt/http/download-queue.hpp>
#include <dt/cardano/network.hpp>
#include <dt/json.hpp>

namespace daedalus_turbo {
    // flat_set has random access iterator making random selection easy
    using turbo_peer_list = boost::container::flat_set<std::string>;
    using cardano_peer_list = boost::container::flat_set<cardano::network::address>;

    struct peer_selection {
        static constexpr size_t max_retries = 10;

        virtual ~peer_selection() =default;

        std::string next_turbo()
        {
            return _next_turbo_impl();
        }

        cardano::network::address next_cardano()
        {
            return _next_cardano_impl();
        }
    private:
        virtual std::string _next_turbo_impl() =0;
        virtual cardano::network::address _next_cardano_impl() =0;
    };

    struct peer_selection_simple: peer_selection {
        static peer_selection_simple &get()
        {
            static peer_selection_simple ps {};
            return ps;
        }

        explicit peer_selection_simple() =default;
    private:
        turbo_peer_list _turbo_hosts {};
        cardano_peer_list _cardano_hosts {};
        std::default_random_engine _rnd { static_cast<unsigned>(std::chrono::system_clock::now().time_since_epoch().count()) };

        bool _update_peers_from(const std::string &host)
        {
            try {
                const auto j_peers = http::download_queue_async::get().fetch_json(fmt::format("http://{}/peers.json", host)).as_object();
                for (const auto &j_host: j_peers.at("hosts").as_array()) {
                    _turbo_hosts.emplace(std::string { static_cast<std::string_view>(j_host.as_string()) });
                }
                return true;
            } catch (const std::exception &ex) {
                logger::warn("connecting to turbo peer {} failed: {}", host, ex.what());
            }
            return false;
        }

        std::string _next_turbo_impl() override
        {
            if (_turbo_hosts.empty()) {
                const auto j_turbo_hosts = configs_dir::get().at("turbo").at("hosts").as_array();
                for (const auto &j_host: j_turbo_hosts) {
                    if (_update_peers_from(json::value_to<std::string>(j_host)))
                        break;
                }
                if (_turbo_hosts.empty())
                    throw error("The list of turbo hosts cannot be empty!");
            }
            std::uniform_int_distribution<size_t> dist { 0, _turbo_hosts.size() - 1 };
            for (size_t retry = 0; retry < max_retries; ++retry) {
                const auto ri = dist(_rnd);
                // ensure that only live hosts are returned
                if (const std::string host = *(_turbo_hosts.begin() + ri); _update_peers_from(host))
                    return host;
            }
            throw error(fmt::format("failed to find a working turbo host after {} attempts", max_retries));
        }

        cardano::network::address _next_cardano_impl() override
        {
            if (_cardano_hosts.empty()) {
                const auto j_cardano_hosts = configs_dir::get().at("topology").at("bootstrapPeers").as_array();
                for (const auto &j_host: j_cardano_hosts) {
                    _cardano_hosts.emplace(
                        json::value_to<std::string>(j_host.at("address")),
                        std::to_string(json::value_to<uint64_t>(j_host.at("port")))
                    );
                }
                if (_cardano_hosts.empty())
                    throw error("The list of cardano hosts cannot be empty!");
            }
            std::uniform_int_distribution<size_t> dist { 0, _cardano_hosts.size() - 1 };
            const auto ri = dist(_rnd);
            return *(_cardano_hosts.begin() + ri);
        }
    };
}

#endif // !DAEDALUS_TURBO_PEER_SELECTION_HPP