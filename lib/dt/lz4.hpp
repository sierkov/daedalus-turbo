/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_LZ4_HPP
#define DAEDALUS_TURBO_LZ4_HPP

extern "C" {
#   include <lz4/lz4hc.h>
};

#include "util.hpp"

namespace daedalus_turbo {

    inline void lz4_compress(uint8_vector &compressed, const uint8_vector &orig)
    {
        compressed.resize(LZ4_compressBound(orig.size()) + sizeof(uint64_t));
        uint64_t *orig_data_size = reinterpret_cast<uint64_t *>(compressed.data());
        *orig_data_size = orig.size();
        uint8_t *compressed_data = compressed.data() + sizeof(uint64_t);
        const int compressed_size = LZ4_compress_HC(reinterpret_cast<const char *>(orig.data()), reinterpret_cast<char *>(compressed_data), orig.size(), compressed.size(), LZ4HC_CLEVEL_MIN);
        if (compressed_size <= 0) throw error("Internal erorr: LZ4 compression failed!");
        compressed.resize(compressed_size + sizeof(uint64_t));
    }

    inline void lz4_decompress(uint8_vector &out, const uint8_vector &compressed)
    {
        const uint64_t *orig_data_size = reinterpret_cast<const uint64_t*>(compressed.data());
        const uint8_t *compressed_data = compressed.data() + sizeof(uint64_t);
        out.resize(*orig_data_size);
        const int decompressed_size = LZ4_decompress_safe(reinterpret_cast<const char *>(compressed_data), reinterpret_cast<char *>(out.data()), compressed.size() - sizeof(uint64_t), out.size());
        if (decompressed_size <= 0) throw error("Internal error: LZ4 decompression failed! error: %d", decompressed_size);
        if ((uint64_t)decompressed_size != *orig_data_size) throw error("Internal error: decompressed size %d != orig size %llu!", decompressed_size, *orig_data_size);
    }

}

#endif // !DAEDALUS_TURBO_LZ4_HPP