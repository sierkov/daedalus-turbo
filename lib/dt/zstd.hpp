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

    struct compress_context {
        explicit compress_context(): _ctx { ZSTD_createCCtx() }
        {
            if (_ctx == nullptr)
                throw error("failed to create ZSTD compression context!");
        }

        ~compress_context()
        {
            if (_ctx != nullptr)
                ZSTD_freeCCtx(_ctx);
        }

        ZSTD_CCtx* get() const
        {
            return _ctx;
        }

        void reset()
        {
            auto res = ZSTD_CCtx_reset(_ctx, ZSTD_reset_session_only);
            if (ZSTD_isError(res))
                throw error("ZSTD: failed to reset a compression context: {}", ZSTD_getErrorName(res));
        }

        void set_level(size_t level)
        {
            auto res = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_compressionLevel, level);
            if (ZSTD_isError(res))
                throw error("ZSTD: failed to change the compression level to {}: {}", level, ZSTD_getErrorName(res));
        }
    private:
        ZSTD_CCtx* _ctx;
    };

    struct decompress_context {
        decompress_context(): _ctx { ZSTD_createDCtx() }
        {
            if (_ctx == nullptr)
                throw error("failed to create ZSTD decompression context!");
        }

        ~decompress_context()
        {
            if (_ctx != nullptr)
                ZSTD_freeDCtx(_ctx);
        }

        ZSTD_DCtx* get() const
        {
            return _ctx;
        }

        void reset()
        {
            auto res = ZSTD_DCtx_reset(_ctx, ZSTD_reset_session_only);
            if (ZSTD_isError(res))
                throw error("ZSTD: failed to reset a compression context: {}", ZSTD_getErrorName(res));
        }
    private:
        ZSTD_DCtx* _ctx;
    };

    inline void compress(uint8_vector &compressed, const buffer &orig, int level=22)
    {
        if (orig.size() > max_zstd_buffer)
            throw error("data size {} is greater than the maximum allowed: {}!", orig.size(), max_zstd_buffer);
        compressed.resize(ZSTD_compressBound(orig.size()));
        thread_local compress_context ctx {};
        ctx.reset();
        ctx.set_level(level);
        const size_t compressed_size = ZSTD_compress2(ctx.get(), compressed.data(), compressed.size(), reinterpret_cast<const void *>(orig.data()), orig.size());
        if (ZSTD_isError(compressed_size))
            throw error("zstd compression error: {}", ZSTD_getErrorName(compressed_size));
        compressed.resize(compressed_size);
    }

    inline uint8_vector compress(const buffer &orig, int level=22)
    {
        uint8_vector res {};
        compress(res, orig, level);
        return res;
    }

    template<typename T>
    concept Resizable = requires(T a) {
        { a.resize(22) };
    };

    template<Resizable T>
    void _check_out_size(T &out, size_t new_size)
    {
        if (sizeof(out[0]) != 1)
            error("target buffer must 1-byte items but has {}-byte!", sizeof(out[0]));
        if (out.size() != new_size)
            out.resize(new_size);
    }

    template<typename T>
    void _check_out_size(T &out, size_t new_size)
    {
        if (sizeof(out[0]) != 1)
            error("target buffer must 1-byte items but has {}-byte!", sizeof(out[0]));
        if (out.size() != new_size)
            throw error("target buffer must have {} bytes but has {}!", new_size, out.size());
    }

    inline uint64_t decompressed_size(const buffer &compressed)
    {
        auto sz = ZSTD_getFrameContentSize(compressed.data(), compressed.size());
        switch (sz) {
            case ZSTD_CONTENTSIZE_UNKNOWN:
                throw error("ZSTD content size is unknown!");
            case ZSTD_CONTENTSIZE_ERROR:
                throw error("ZSTD could not extract the content size from a compressed frame!");
            default:
                return sz;
        }
    }

    template<typename T>
    void decompress(T &out, const buffer &compressed)
    {
        const uint64_t orig_data_size = decompressed_size(compressed);
        if (orig_data_size > max_zstd_buffer)
            throw error("recorded original data size {} is greater than the maximum allowed: {}!", orig_data_size, max_zstd_buffer);
        _check_out_size(out, orig_data_size);
        thread_local decompress_context ctx {};
        ctx.reset();
        const size_t decompressed_size = ZSTD_decompressDCtx(ctx.get(), reinterpret_cast<void *>(out.data()), out.size(), compressed.data(), compressed.size());
        if (ZSTD_isError(decompressed_size)) 
            throw error("zstd decompression error: {}", ZSTD_getErrorName(decompressed_size));
        if ((uint64_t)decompressed_size != out.size())
            throw error("Internal error: decompressed size {} != expected output size {}!", decompressed_size, out.size());
    }

    inline uint8_vector decompress(const buffer &compressed)
    {
        uint8_vector out {};
        decompress(out, compressed);
        return out;
    }
}

#endif // !DAEDALUS_TURBO_ZSTD_HPP