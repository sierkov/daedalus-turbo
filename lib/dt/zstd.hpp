/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_ZSTD_HPP
#define DAEDALUS_TURBO_ZSTD_HPP

extern "C" {
#   include <zstd.h>
};

#include "util.hpp"

namespace daedalus_turbo {

    inline void zstd_compress(uint8_vector &compressed, const uint8_vector &orig, int level=22)
    {
        compressed.resize(ZSTD_compressBound(orig.size()) + sizeof(uint64_t));
        uint64_t *orig_data_size = reinterpret_cast<uint64_t *>(compressed.data());
        *orig_data_size = orig.size();
        uint8_t *compressed_data = compressed.data() + sizeof(uint64_t);
        const size_t compressed_size = ZSTD_compress(reinterpret_cast<void *>(compressed_data), compressed.size() - sizeof(uint64_t), reinterpret_cast<const void *>(orig.data()), orig.size(), level);
        if (ZSTD_isError(compressed_size)) throw error_fmt("zstd compression error: {}", ZSTD_getErrorName(compressed_size));
        compressed.resize(compressed_size + sizeof(uint64_t));
    }

    inline void zstd_decompress(uint8_vector &out, const uint8_vector &compressed)
    {
        const uint64_t *orig_data_size = reinterpret_cast<const uint64_t*>(compressed.data());
        const uint8_t *compressed_data = compressed.data() + sizeof(uint64_t);
        out.resize(*orig_data_size);
        const size_t decompressed_size = ZSTD_decompress(reinterpret_cast<void *>(out.data()), out.size(), reinterpret_cast<const void *>(compressed_data), compressed.size() - sizeof(uint64_t));
        if (ZSTD_isError(decompressed_size)) throw error_fmt("zstd decompression error: {}", ZSTD_getErrorName(decompressed_size));
        if ((uint64_t)decompressed_size != *orig_data_size) throw error_fmt("Internal error: decompressed size {} != orig size {}!", decompressed_size, *orig_data_size);
    }

}

#endif // !DAEDALUS_TURBO_ZSTD_HPP