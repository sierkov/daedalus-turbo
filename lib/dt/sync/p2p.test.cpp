/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/sync/p2p.hpp>
#include <dt/test.hpp>
#include <dt/validator.hpp>

namespace {
    using namespace daedalus_turbo;
    using namespace daedalus_turbo::cardano::network;

    struct cardano_client_mock: cardano::network::client {
        explicit cardano_client_mock(const std::string &path)
            : _raw_data { file::read(path) }
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

        void _fetch_headers_impl(const address &addr, const blockchain_point_list &points, const size_t max_blocks, const header_handler &handler) override
        {
            std::optional<block_list::const_iterator> intersection {};
            for (const auto &p: points) {
                for (auto it = _blocks.begin(); it != _blocks.end(); ++it) {
                    if ((*it)->hash() == p.hash) {
                        intersection = it;
                        break;
                    }
                }
            }
            header_response resp { addr };
            resp.tip = blockchain_point { _blocks.back()->hash(), _blocks.back()->slot() };
            header_list headers {};
            if (intersection) {
                resp.intersect = blockchain_point { (**intersection)->hash(), (**intersection)->slot() };
                for (auto it = std::next(*intersection); it != _blocks.end() && headers.size() < max_blocks; ++it)
                    headers.emplace_back((*it)->hash(), (*it)->slot(), (*it)->height());
            } else {
                for (auto it = _blocks.begin(); it != _blocks.end() && headers.size() < max_blocks; ++it)
                    headers.emplace_back((*it)->hash(), (*it)->slot(), (*it)->height());
            }
            resp.res = std::move(headers);
            handler(std::move(resp));
        }

        void _fetch_blocks_impl(const address &addr, const blockchain_point &from, const blockchain_point &to, std::optional<size_t> max_blocks, const block_handler &handler) override
        {
            std::optional<block_list::const_iterator> intersection {};
            for (auto it = _blocks.begin(); it != _blocks.end(); ++it) {
                if ((*it)->hash() == from.hash) {
                    intersection = it;
                    break;
                }
            }
            if (!intersection)
                return handler(block_response { addr, from, to, error_msg { "The requested from block is unknown!" } });
            cardano::network::block_list blocks {};
            for (auto it = *intersection; it != _blocks.end() && blocks.size() < max_blocks; ++it) {
                block_parsed bp {};
                bp.data = std::make_unique<uint8_vector>((*it)->raw_data());
                bp.cbor = std::make_unique<cbor_value>(cbor::parse(*bp.data));
                bp.blk = cardano::make_block(*bp.cbor, (*it)->offset());
                blocks.emplace_back(std::move(bp));
            }
            handler(block_response { addr, from, to, std::move(blocks) });
        }

        void _process_impl() override
        {
        }
    };
}

suite sync_p2p_suite = [] {
    "sync::p2p"_test = [] {
        const std::string data_dir { "./tmp/sync-p2p-test" };
        "success"_test = [&] {
            std::filesystem::remove_all(data_dir);
            validator::incremental cr { data_dir };
            cardano_client_mock cnc { "./data/sync-http/success/D0AAE92BCD98E5C43D7729B8B3DFDA6007D606B3CC58868FEBAD6C6ACF8B4575.zstd" };
            sync::p2p::syncer s { cr, cnc };
            s.sync();
            expect(cr.max_slot() == 9_ull);
            expect(cr.valid_end_offset() == 654757_ull);
        };
    };
};