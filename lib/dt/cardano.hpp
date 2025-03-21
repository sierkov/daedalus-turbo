/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_HPP
#define DAEDALUS_TURBO_CARDANO_HPP

#include <cstdint>
#include <dt/cardano/byron/block.hpp>
#include <dt/cardano/shelley/block.hpp>
#include <dt/cardano/mary/block.hpp>
#include <dt/cardano/alonzo/block.hpp>
#include <dt/cardano/babbage/block.hpp>
#include <dt/cardano/conway/block.hpp>

namespace daedalus_turbo::cardano {
    struct header_container {
        using value_type = std::variant<byron::boundary_block_header, byron::block_header, shelley::block_header, mary::block_header, alonzo::block_header, babbage::block_header, conway::block_header>;

        // prohibit copying and moving
        // since the nested value refers to the parent by a const reference
        header_container() =delete;
        header_container(const header_container &) =delete;
        header_container(header_container &&) =default;

        header_container(cbor::zero2::value &v, const config &cfg=cardano::config::get()):
            header_container { v.array(), v, cfg }
        {
        }

        const block_header_base &operator*() const
        {
            return std::visit([](const auto &v) -> const block_header_base & {
                return v;
            }, _val);
        }

        const block_header_base *operator->() const
        {
            return std::visit([](const auto &v) -> const block_header_base * {
                return &v;
            }, _val);
        }
    private:
        const uint8_t _era;
        const value_type _val;
        const buffer _raw;

        static value_type _make(const uint8_t era, cbor::zero2::value &hdr_body, const config &cfg)
        {
            switch (era) {
                case 0: return value_type { byron::boundary_block_header { era, hdr_body, cfg } };
                case 1: return byron::block_header { era, hdr_body, cfg };
                case 2: return shelley::block_header { era, hdr_body, cfg };
                case 3:
                case 4: return mary::block_header { era, hdr_body, cfg };
                case 5: return alonzo::block_header { era, hdr_body, cfg };
                case 6: return babbage::block_header { era, hdr_body, cfg };
                case 7: return conway::block_header { era, hdr_body, cfg };
                default:
                    throw cardano_error(fmt::format("unsupported era {}!", era));
            }
        }

        header_container(cbor::zero2::array_reader &it, cbor::zero2::value &v, const config &cfg=cardano::config::get()):
            _era { narrow_cast<uint8_t>(it.read().uint()) },
            _val { _make(_era, it.read().array().read(), cfg) },
            _raw { v.data_raw() }
        {
        }
    };

    struct parsed_block {
        uint8_vector data;
        block_container blk;

        parsed_block(const buffer bytes, const cardano::config &cfg=cardano::config::get()):
            data { bytes },
            blk { 0, cbor::zero2::parse(data).get(), cfg }
        {   
        }
    };

    extern header_container make_header(cbor::zero2::value &block_tuple, const config &cfg=cardano::config::get());
}

#endif // !DAEDALUS_TURBO_CARDANO_HPP