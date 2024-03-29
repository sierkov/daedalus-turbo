/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PEER_SELECTION_HPP
#define DAEDALUS_TURBO_PEER_SELECTION_HPP

#include <chrono>
#include <random>
#include <boost/container/flat_set.hpp>
#include <dt/http/download-queue.hpp>
#include <dt/cardano/network.hpp>
#include <dt/json.hpp>

namespace daedalus_turbo {
    struct peer_selection {
        static constexpr size_t max_retries = 10;

        // flast_set has random access iterator making random selection easy
        using turbo_peer_list = boost::container::flat_set<std::string>;
        using cardano_peer_list = boost::container::flat_set<cardano::network::address>;

        static peer_selection &get()
        {
            static peer_selection ps {};
            return ps;
        }

        explicit peer_selection()
        {
            auto j_cardano_hosts = json::load("./etc/cardano.json").at("hosts").as_array();
            for (const auto &j_host: j_cardano_hosts) {
                _cardano_hosts.emplace(std::string { static_cast<std::string_view>(j_host.as_string()) }, "3001");
            }
            if (_cardano_hosts.empty())
                throw error("The list of cardano hosts cannot be empty!");
            auto j_turbo_hosts = json::load("./etc/turbo.json").at("hosts").as_array();
            for (const auto &j_host: j_turbo_hosts) {
                std::string host { static_cast<std::string_view>(j_host.as_string()) };
                if (_update_peers_from(host))
                    break;
            }
            if (_turbo_hosts.empty())
                throw error("The list of turbo hosts cannot be empty!");
        }

        const turbo_peer_list &all_turbo() const
        {
            return _turbo_hosts;
        }

        std::string next_turbo()
        {
            std::uniform_int_distribution<size_t> dist { 0, _turbo_hosts.size() - 1 };
            for (size_t retry = 0; retry < max_retries; ++retry) {
                auto ri = dist(_rnd);
                std::string host = *(_turbo_hosts.begin() + ri);
                // ensure that only live hosts are returned
                if (_update_peers_from(host))
                    return host;
            }
            throw error("failed to find a working turbo host after {} attempts", max_retries);
        }

        cardano::network::address next_cardano()
        {
            std::uniform_int_distribution<size_t> dist { 0, _cardano_hosts.size() - 1 };
            auto ri = dist(_rnd);
            return *(_cardano_hosts.begin() + ri);
        }
    private:
        turbo_peer_list _turbo_hosts {};
        cardano_peer_list _cardano_hosts {};
        std::default_random_engine _rnd { static_cast<unsigned>(std::chrono::system_clock::now().time_since_epoch().count()) };

        bool _update_peers_from(const std::string &host)
        {
            try {
                auto j_peers = http::fetch_json(fmt::format("http://{}/peers.json", host)).as_object();
                for (const auto &j_host: j_peers.at("hosts").as_array()) {
                    _turbo_hosts.emplace(std::string { static_cast<std::string_view>(j_host.as_string()) });
                }
                return true;
            } catch (const std::exception &ex) {
                logger::warn("connecting to turbo peer {} failed: {}", host, ex.what());
            }
            return false;
        }
    };
}

#endif // !DAEDALUS_TURBO_PEER_SELECTION_HPP