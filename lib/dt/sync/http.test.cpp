/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <boost/url.hpp>
#include <dt/sync/http.hpp>
#include <dt/test.hpp>
#include <dt/validator.hpp>

using namespace daedalus_turbo;

namespace {
    struct cardano_client_mock: cardano::network::client {
    private:
        void _find_intersection_impl(const cardano::network::address &addr, const cardano::network::blockchain_point_list &points, const find_handler &handler) override
        {
            if (points.empty())
                throw error("cardano::network::client::_find_intersection_impl: unsupported parameters!");
            handler(find_response { addr, cardano::network::blockchain_point_pair { points.front(), points.front() } } );
        }

        void _process_impl() override
        {
        }
    };

    struct download_queue_mock: http::download_queue {
        using response_map = std::map<std::string, std::string>;

        download_queue_mock(const std::string &data_dir, response_map &&responses)
            : _data_dir(data_dir), _responses { std::move(responses) }
        {
        }
    private:
        const std::string _data_dir;
        response_map _responses;
        std::atomic_size_t _num_err = 0;

        void _download_impl(const std::string &url, const std::string &save_path, uint64_t /*priority*/, const std::function<void(download_queue::result &&)> &handler) override
        {
            static std::string chunk_prefix { "/compressed/chunk/" };
            boost::url_view uri { url };
            download_queue::result res { url, save_path };
            std::filesystem::remove(save_path);
            std::string path = uri.path();
            auto last_slash_pos = path.find_last_of('/');
            std::string filename { last_slash_pos != path.npos ? path.substr(last_slash_pos + 1) : "" };
            std::string filename_path = fmt::format("{}/{}", _data_dir, filename);
            if (_responses.contains(path)) {
                std::filesystem::copy_file(_data_dir + "/" + _responses.at(path), save_path);
            } else if (!filename.empty() && std::filesystem::exists(filename_path)) {
                std::filesystem::copy_file(filename_path, save_path);
            } else {
                ++_num_err;
                res.error = fmt::format("unknown url: {}", url);
            }
            if (std::filesystem::exists(save_path))
                res.size = std::filesystem::file_size(save_path);
            handler(std::move(res));
        }

        bool _process_ok_impl(bool /*report_progress*/, scheduler */*sched*/) override
        {
            return _num_err.load() == 0;
        }

        speed_mbps _internet_speed_impl() override
        {
            return speed_mbps {};
        }
    };
}

suite sync_http_suite = [] {
    "sync::http"_test = [] {
        const std::string data_dir { "./tmp/sync-http-test" };
        "success"_test = [&] {
            std::filesystem::remove_all(data_dir);
            validator::incremental cr { data_dir };
            download_queue_mock::response_map responses {};
            responses.emplace("/chain.json", "chain.json");
            responses.emplace("/epoch-0-7C6901C6346781C2BC5CBC49577490E336C2545C320CE4A61605BC71A9C5BED0.json", "epoch-0.json");
            download_queue_mock dq { "./data/sync-http/success", std::move(responses) };
            cardano_client_mock cnc {};
            sync::http::syncer syncer { cr, dq, cnc };
            expect(cr.max_slot() == 0_ull);
            syncer.sync();
            expect(cr.max_slot() == 19_ull);
            expect(cr.valid_end_offset() == cr.num_bytes()) << cr.valid_end_offset() << cr.num_bytes();
        };
        "failure"_test = [&] {
            std::filesystem::remove_all(data_dir);
            validator::incremental cr { data_dir };
            download_queue_mock::response_map responses {};
            responses.emplace("/chain.json", "chain.json");
            responses.emplace("/epoch-0-7C6901C6346781C2BC5CBC49577490E336C2545C320CE4A61605BC71A9C5BED0.json", "epoch-0.json");
            download_queue_mock dq { "./data/sync-http/failure", std::move(responses) };
            cardano_client_mock cnc {};
            sync::http::syncer syncer { cr, dq, cnc };
            expect(cr.max_slot() == 0_ull);
            expect(throws([&] { syncer.sync(); }));
            expect(cr.max_slot() == 9_ull);
            expect(cr.valid_end_offset() == cr.num_bytes()) << cr.valid_end_offset() << cr.num_bytes();
        };
    };
};