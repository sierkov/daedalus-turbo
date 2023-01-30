/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_CHUNK_REGISTRY_HPP
#define DAEDALUS_TURBO_CHUNK_REGISTRY_HPP

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <map>
#include <string>
#include <sstream>

#include "cbor.hpp"
#include "lz4.hpp"

namespace daedalus_turbo {
    using namespace std;

    struct chunk_info {
        string id;
        string path;
        uint64_t size;
        bool lz4;

        chunk_info(const filesystem::path &aPath, uint64_t aSize, bool lz4_)
            : id(aPath.stem().string()), path(aPath.string()), size(aSize), lz4(lz4_)
        {
        }
    };

    typedef map<uint64_t, chunk_info> chunk_map;

    constexpr size_t MAX_READ_SIZE = 256 * 1024; // Assume the largest block is 256KB - a multiple of the current limit of 88KB

    class chunk_registry {
        bool lz4;
        chunk_map _chunks;
        uint64_t _size_bytes;
        uint8_vector _read_buffer;

    public:

        chunk_registry(const string &path, bool lz4_=false)
            : lz4(lz4_)
        {
            set<filesystem::path> sortedChunks;
            for (const auto &entry : filesystem::directory_iterator(path)) {
                if (lz4) {
                    if (entry.path().extension() != ".lz4") continue;
                } else {
                    if (entry.path().extension() != ".chunk") continue;
                }
                sortedChunks.insert(entry.path());
            }
            uint64_t offset = 0;
            for (const auto &path : sortedChunks) {
                uint64_t size;
                if (lz4) {
                    ifstream is(path, ios::binary);
                    if (!is) throw sys_error("failed to open for reading: %s", path.c_str());
                    is.read(reinterpret_cast<char *>(&size), sizeof(size));
                    is.close();
                } else {
                    size = filesystem::file_size(path);
                }
                
                _chunks.insert(chunk_map::value_type(offset, chunk_info(path, size, lz4)));
                offset += size;
            }
            _size_bytes = offset;
        }

        chunk_map::const_iterator begin() const {
            return _chunks.begin();
        }

        chunk_map::const_iterator end() const {
            return _chunks.end();
        }

        size_t num_chunks() const {
            return _chunks.size();
        }

        size_t num_bytes() const {
            return _size_bytes;
        }

        chunk_map::const_iterator find_chunk(uint64_t offset) {
            if (offset >= _size_bytes) throw runtime_error("the requested offset is outside of the allowed bounds");
            chunk_map::const_iterator it = _chunks.lower_bound(offset);
            if (it == _chunks.end()) {
                it = prev(it);
                if (offset + 1 > it->first + it->second.size) throw runtime_error("no relevant chunk was found!");
            }
            if (offset < it->first) {
                if (it == _chunks.begin()) throw runtime_error("no relevant chunk was found!");
                it--;
            }
            return it;
        }

        const string find_chunk_name(uint64_t offset) {
            auto it = find_chunk(offset);
            return it->second.path;
        }

        size_t read(uint64_t offset, cbor_value &value, const size_t read_size=MAX_READ_SIZE, const size_t read_scale_factor=2) {
            return read(offset, value, _read_buffer, read_size, read_scale_factor);
        }

        size_t read(uint64_t offset, cbor_value &value, uint8_vector &read_buffer, const size_t max_read_size=MAX_READ_SIZE, const size_t read_scale_factor=2) {
            if (offset + 1 > _size_bytes) throw runtime_error("the requested byte range is outside of the allowed bounds");
            size_t read_attempts = 0;
            auto chunk_it = find_chunk(offset);
            if (chunk_it->first + chunk_it->second.size < offset + 1) throw runtime_error("the requested chunk is too small to provide the requested number of bytes");
            if (chunk_it->second.lz4) {
                uint8_vector compressed;
                read_whole_file(chunk_it->second.path, compressed);
                lz4_decompress(read_buffer, compressed);
                size_t read_offset = offset - chunk_it->first;
                cbor_parser parser(read_buffer.data() + read_offset, read_buffer.size() - read_offset);
                parser.read(value);
            } else {
                ifstream is(chunk_it->second.path, ios::binary);
                if (!is) {
                    stringstream ss;
                    ss << "Can't open file " << chunk_it->second.path;
                    throw runtime_error(ss.str());
                }
                size_t read_size = chunk_it->second.size - (offset - chunk_it->first);
                if (read_size > max_read_size) read_size = max_read_size;
                bool ok = false;
                while (!ok) {
                    try {
                        read_attempts++;
                        read_buffer.resize(read_size);
                        is.seekg(offset - chunk_it->first, ios::beg);
                        is.read(reinterpret_cast<char *>(read_buffer.data()), read_size);
                        cbor_parser parser(read_buffer.data(), read_size);
                        parser.read(value);
                        if (value.size > read_size) throw error("internal error: read value: %zu is larger than it must be: %zu!", value.size, read_size);
                        ok = true;
                    } catch (cbor_incomplete_data_error &ex) {
                        if (read_size < MAX_READ_SIZE) {
                            read_size *= read_scale_factor;
                            if (read_size > MAX_READ_SIZE) read_size = MAX_READ_SIZE;
                        } else {
                            throw;
                        }
                    }
                }
            }
            return read_attempts;
        }
    };
}

#endif // !DAEDALUS_TURBO_CHUNK_REGISTRY_HPP
