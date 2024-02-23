/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ZSTD_HPP
#define DAEDALUS_TURBO_ZSTD_HPP

extern "C" {
#   include <zstd.h>
#   include <zstd_errors.h>
};
#include "util.hpp"

namespace daedalus_turbo::zstd {
    static constexpr size_t max_zstd_buffer = static_cast<size_t>(1) << 28;

    inline void compress(uint8_vector &compressed, const buffer &orig, int level=22)
    {
        if (orig.size() > max_zstd_buffer)
            throw error("data size {} is greater than the maximum allowed: {}!", orig.size(), max_zstd_buffer);
        compressed.resize(ZSTD_compressBound(orig.size()) + sizeof(uint64_t));
        uint64_t *orig_data_size = reinterpret_cast<uint64_t *>(compressed.data());
        *orig_data_size = orig.size();
        uint8_t *compressed_data = compressed.data() + sizeof(uint64_t);
        const size_t compressed_size = ZSTD_compress(reinterpret_cast<void *>(compressed_data), compressed.size() - sizeof(uint64_t), reinterpret_cast<const void *>(orig.data()), orig.size(), level);
        if (ZSTD_isError(compressed_size))
            throw error("zstd compression error: {}", ZSTD_getErrorName(compressed_size));
        compressed.resize(compressed_size + sizeof(uint64_t));
    }

    template<typename T>
    concept Resizable = requires(T a) {
        { a.resize(22) };
    };

    template<Resizable T>
    void _check_size(T &out, size_t new_size)
    {
        if (sizeof(out[0]) != 1)
            error("target buffer must 1-byte items but has {}-byte!", sizeof(out[0]));
        if (out.size() != new_size)
            out.resize(new_size);
    }

    template<typename T>
    void _check_size(T &out, size_t new_size)
    {
        if (sizeof(out[0]) != 1)
            error("target buffer must 1-byte items but has {}-byte!", sizeof(out[0]));
        if (out.size() != new_size)
            throw error("target buffer must have {} bytes but has {}!", new_size, out.size());
    }

    inline uint64_t decompressed_size(const buffer &compressed)
    {
        if (compressed.size() < sizeof(uint64_t))
            throw error("compressed buffer is too small!");
        return *reinterpret_cast<const uint64_t*>(compressed.data());
    }

    template<typename T>
    inline void decompress(T &out, const buffer &compressed)
    {
        const uint64_t orig_data_size = decompressed_size(compressed);
        if (orig_data_size > max_zstd_buffer)
            throw error("recorded original data size {} is greater than the maximum allowed: {}!", orig_data_size, max_zstd_buffer);
        const uint8_t *compressed_data = compressed.data() + sizeof(uint64_t);
        _check_size(out, orig_data_size);
        const size_t decompressed_size = ZSTD_decompress(reinterpret_cast<void *>(out.data()), out.size(), reinterpret_cast<const void *>(compressed_data), compressed.size() - sizeof(uint64_t));
        if (ZSTD_isError(decompressed_size)) 
            throw error("zstd decompression error: {}", ZSTD_getErrorName(decompressed_size));
        if ((uint64_t)decompressed_size != out.size())
            throw error("Internal error: decompressed size {} != expected output size {}!", decompressed_size, out.size());
    }

    struct stream_decompressor {
        stream_decompressor(): _ctx { ZSTD_createDCtx() }, _buf(ZSTD_DStreamInSize())
        {
            if (_ctx == nullptr)
                throw error("Failed to create ZSTD decompression context!");
        }

        ~stream_decompressor()
        {
            if (_ctx != nullptr)
                ZSTD_freeDCtx(_ctx);
        }

        template<typename T>
        uint64_t read_start(uint8_vector &out, T &read_stream)
        {
            uint64_t stream_size = 0;
            read_stream.read(&stream_size, sizeof(stream_size));
            read_stream.read(_buf.data(), _buf.size());
            out.resize(ZSTD_DStreamOutSize());
            ZSTD_inBuffer input = { _buf.data(), _buf.size(), 0 };
            ZSTD_outBuffer output = { out.data(), out.size(), 0 };
            size_t ret = ZSTD_initDStream(_ctx);
            if (ZSTD_isError(ret))
                throw error("zstd decompression init error: {}", ZSTD_getErrorName(ret));
            ret = ZSTD_decompressStream(_ctx, &output, &input);
            if (ZSTD_isError(ret))
                throw error("zstd decompression error: {}", ZSTD_getErrorName(ret));
            if (ret > out.size())
                throw error("decompressed size: {} is greater than the buffer size: {}!", ret, out.size());
            out.resize(output.pos);
            return stream_size;
        }
    private:
        ZSTD_DCtx *_ctx = nullptr;
        uint8_vector _buf;
    };
}

#endif // !DAEDALUS_TURBO_ZSTD_HPP