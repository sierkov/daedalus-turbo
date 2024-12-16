/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ZSTD_STREAM_HPP
#define DAEDALUS_TURBO_ZSTD_STREAM_HPP

extern "C" {
#   include <zstd.h>
#   include <zstd_errors.h>
};
#include <dt/file.hpp>

namespace daedalus_turbo::zstd {
    struct read_stream {
        read_stream(const std::string &path):
            _fs { path },
            _zstd_ds { ZSTD_createDStream() },
            _in_buf(ZSTD_DStreamInSize()),
            _zstd_in_buf { _in_buf.data(), 0, 0 }
        {
            if (!_zstd_ds) [[unlikely]]
                throw error("failed to allocate a ZSTD decompression stream!");
            if (const auto res = ZSTD_initDStream(_zstd_ds); ZSTD_isError(res)) [[unlikely]]
                throw error(fmt::format("failed to create a ZSTD decompression stream: {}", ZSTD_getErrorName(res)));
        }

        ~read_stream()
        {
            if (_zstd_ds)
                ZSTD_freeDStream(_zstd_ds);
        }

        size_t try_read(const std::span<uint8_t> buf)
        {
            if (buf.empty()) [[unlikely]]
                throw error("zstd::read_stream: cannot read into an empty buffer!");
            ZSTD_outBuffer ob { buf.data(), buf.size(), 0 };
            for (;;) {
                if (_zstd_in_buf.pos == _zstd_in_buf.size) {
                    _zstd_in_buf.size = _fs.try_read(std::span { _in_buf.data(), _in_buf.size() });
                    if (!_zstd_in_buf.size) [[unlikely]]
                        return ob.pos;
                    _zstd_in_buf.pos = 0;
                }
                const auto res = ZSTD_decompressStream(_zstd_ds, &ob, &_zstd_in_buf);
                if (ZSTD_isError(res)) [[unlikely]]
                    throw error(fmt::format("zstd::read_stream: decompression failed: {}", ZSTD_getErrorName(res)));
                if (ob.pos == ob.size)
                    return ob.size;
            }
        }
    private:
        file::read_stream _fs;
        ZSTD_DStream* _zstd_ds = nullptr;
        uint8_vector _in_buf;
        ZSTD_inBuffer _zstd_in_buf;
    };
}

#endif // !DAEDALUS_TURBO_ZSTD_HPP