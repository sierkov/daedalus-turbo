/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SYNC_MOCKS_HPP
#define DAEDALUS_TURBO_SYNC_MOCKS_HPP

#include <random>
#include <boost/url.hpp>
#include <dt/cardano/block-producer.hpp>
#include <dt/cardano/network.hpp>
#include <dt/http/download-queue.hpp>

namespace daedalus_turbo::sync {
    using namespace daedalus_turbo::cardano;
    using namespace daedalus_turbo::cardano::network;

    enum class failure_type {
        prev_hash,
        slot_no
        /*kes_seq_no,
        kes_signature,
        vrf_signature,
        leadership_eligibility,
        block_body_hash,*/
    };

    struct mock_chain_config {
        size_t height = 9;
        std::optional<uint64_t> failure_height = {};
        failure_type failure_type = failure_type::prev_hash;
        configs_mock::map_type cfg {};
    };

     struct mock_chain {
         configs_mock cfg;
         cardano::config cardano_cfg { cfg };
         uint8_vector data {};
         block_list blocks {};
         block_hash data_hash {};
         optional_point tip {};

         mock_chain(configs_mock &&cfg_): cfg { std::move(cfg_) }
         {
         }

         mock_chain(mock_chain &&o)
            : cfg { std::move(o.cfg) }, cardano_cfg { cfg }, data { std::move(o.data) },
                blocks { std::move(o.blocks) }, data_hash { std::move(o.data_hash) },
                tip { std::move(o.tip) }
         {
         }

         mock_chain() =delete;
         mock_chain(const mock_chain &) =delete;
    };

    struct cardano_client_mock: cardano::network::client {
        cardano_client_mock(const network::address &addr, const buffer &raw_data)
                : client { addr }, _raw_data { raw_data }
        {
            cbor_parser p { _raw_data };
            while (!p.eof()) {
                auto &val = _cbor.emplace_back(std::make_unique<cbor_value>());
                p.read(*val);
                _blocks.emplace_back(cardano::make_block(*val, val->data - _raw_data.data()));
            }
            if (_blocks.empty())
                throw error("test chain cannot be empty!");
        }
    private:
        using cbor_val_list = std::vector<std::unique_ptr<cbor_value>>;
        using block_list = std::vector<std::unique_ptr<cardano::block_base>>;

        uint8_vector _raw_data {};
        cbor_val_list _cbor {};
        block_list _blocks {};

        std::optional<block_list::const_iterator> _find_intersection(const point_list &points)
        {
            for (const auto &p: points) {
                for (auto it = _blocks.begin(); it != _blocks.end(); ++it) {
                    if ((*it)->hash() == p.hash)
                        return it;
                }
            }
            return {};
        }

        void _find_intersection_impl(const point_list &points, const find_handler &handler) override
        {
            const auto intersection = _find_intersection(points);
            const point tip { _blocks.back()->hash(), _blocks.back()->slot(), _blocks.back()->height() };
            if (intersection) {
                const point isect { (**intersection)->hash(), (**intersection)->slot(), (**intersection)->height() };
                handler(find_response { _addr, point_pair { isect, tip } });
            } else {
                handler(find_response { _addr, tip });
            }
        }

        void _fetch_headers_impl(const point_list &points, const size_t max_blocks, const header_handler &handler) override
        {
            const auto intersection = _find_intersection(points);
            header_response resp { _addr };
            resp.tip = point { _blocks.back()->hash(), _blocks.back()->slot() };
            header_list headers {};
            if (intersection) {
                resp.intersect = point { (**intersection)->hash(), (**intersection)->slot() };
                for (auto it = std::next(*intersection); it != _blocks.end() && headers.size() < max_blocks; ++it)
                    headers.emplace_back((*it)->hash(), (*it)->slot(), (*it)->height());
            } else {
                for (auto it = _blocks.begin(); it != _blocks.end() && headers.size() < max_blocks; ++it)
                    headers.emplace_back((*it)->hash(), (*it)->slot(), (*it)->height());
            }
            resp.res = std::move(headers);
            handler(std::move(resp));
        }

        void _fetch_blocks_impl(const point &from, const point &to, const block_handler &handler) override
        {
            std::optional<block_list::const_iterator> intersection {};
            for (auto it = _blocks.begin(); it != _blocks.end(); ++it) {
                if ((*it)->hash() == from.hash) {
                    intersection = it;
                    break;
                }
            }
            if (!intersection) {
                handler(block_response { {}, error_msg { "The requested from block is unknown!" } });
                return;
            }
            for (auto it = *intersection; it != _blocks.end(); ++it) {
                block_parsed bp {};
                bp.data = std::make_unique<uint8_vector>((*it)->raw_data());
                bp.cbor = std::make_unique<cbor_value>(cbor::parse(*bp.data));
                bp.blk = cardano::make_block(*bp.cbor, (*it)->offset());
                if (!handler({ std::move(bp) }) || (*it)->hash() == to.hash)
                    break;
            }
        }

        void _process_impl(scheduler */*sched*/) override
        {
        }

        void _reset_impl() override
        {
        }
    };

    struct cardano_client_manager_mock: client_manager {
        explicit cardano_client_manager_mock(const buffer data): _raw_data { data }
        {
        }

        explicit cardano_client_manager_mock(const std::string &path): _raw_data { file::read(path) }
        {
        }

        explicit cardano_client_manager_mock(const std::vector<std::string> &paths): _raw_data{ file::read_all(paths) }
        {
        }
    private:
        uint8_vector _raw_data;

        std::unique_ptr<client> _connect_impl(const network::address &addr, const cardano::config &/*cfg*/, asio::worker &/*asio_worker*/) override
        {
            return std::make_unique<cardano_client_mock>(addr, _raw_data);
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

        size_t _cancel_impl(const cancel_predicate &/*pred*/) override
        {
            // all requests are executed immediately so there is nothing to cancel
            return 0;
        }

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

    extern mock_chain gen_chain(const mock_chain_config &mock_cfg={});
    extern void write_turbo_metadata(const std::string &www_dir, const mock_chain &chain, const ed25519::skey &sk);
}

#endif // !DAEDALUS_TURBO_SYNC_MOCKS_HPP