/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_BECH32_HPP
#define DAEDALUS_TURBO_BECH32_HPP

#include <array>
#include <algorithm>
#include <cctype>
#include <string_view>
#include "util.hpp"

namespace daedalus_turbo {

    using namespace std;

    class bech32 {
        uint8_t _sz;
        uint8_t _buf[57];
        static constexpr char _sep = '1';
        static constexpr array<const string_view, 7> _known_prefixes = { "addr"sv, "addr_test"sv, "addr_vk"sv, "script"sv, "stake"sv, "stake_test"sv, "stake_vk"sv };

        static uint8_t decode_char(char k) {
            switch (tolower(k)) {
                case 'q': return 0;
                case 'p': return 1;
                case 'z': return 2;
                case 'r': return 3;
                case 'y': return 4;
                case '9': return 5;
                case 'x': return 6;
                case '8': return 7;

                case 'g': return 8 + 0;
                case 'f': return 8 + 1;
                case '2': return 8 + 2;
                case 't': return 8 + 3;
                case 'v': return 8 + 4;
                case 'd': return 8 + 5;
                case 'w': return 8 + 6;
                case '0': return 8 + 7;

                case 's': return 16 + 0;
                case '3': return 16 + 1;
                case 'j': return 16 + 2;
                case 'n': return 16 + 3;
                case '5': return 16 + 4;
                case '4': return 16 + 5;
                case 'k': return 16 + 6;
                case 'h': return 16 + 7;

                case 'c': return 24 + 0;
                case 'e': return 24 + 1;
                case '6': return 24 + 2;
                case 'm': return 24 + 3;
                case 'u': return 24 + 4;
                case 'a': return 24 + 5;
                case '7': return 24 + 6;
                case 'l': return 24 + 7;
            }
            throw error("Unsupported Bech32 data char: '%c'", k);
        }

        static uint32_t polymod(const vector<uint8_t> &vals)
        {
            static array<uint32_t, 5> gen { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
            uint32_t chk = 1;
            for (auto v : vals) {
                uint32_t b = (chk >> 25);
                chk = (chk & 0x1ffffff) << 5 ^ v;
                for (size_t i = 0; i < gen.size(); ++i) {
                    chk ^=  (b >> i) & 1 ? gen[i] : 0;
                }
            }
            return chk;
        }

        static vector<uint8_t> expand(const string_view &prefix, const vector<uint8_t> &data)
        {
            vector<uint8_t> x;
            for (auto k: prefix) x.push_back(tolower(k) >> 5);
            x.push_back(0);
            for (auto k: prefix) x.push_back(tolower(k) & 31);
            for (auto k: data) x.push_back(k);
            return x;
        }

        static bool verify(const string_view &prefix, const vector<uint8_t> &data)
        {
            return polymod(expand(prefix, data)) == 1;
        }

    public:

        bech32(const string_view &sv, bool check_prefix=false)
        {
            auto sep_pos = sv.find(_sep);
            if (sep_pos == sv.npos) throw error("Can't find Bech32 separator '%c' in '%s'", _sep, string(sv).c_str());
            const string_view &prefix = sv.substr(0, sep_pos);
            if (check_prefix) {
                if (find(_known_prefixes.begin(), _known_prefixes.end(), prefix) == _known_prefixes.end()) {
                    throw error("unsupported Bech32 prefix: %s!", string(prefix).c_str());
                }
            }

            const string_view &data = sv.substr(sep_pos + 1);
            vector<uint8_t> u5_data;
            for (auto k: data) u5_data.push_back(decode_char(k));
            if (u5_data.size() < 6) throw error("bech32 data part must be at least 6 characters long: %s", string(data).c_str());
            if (!verify(prefix, u5_data)) throw error("bech32 checksum verification failed: %s", string(data).c_str());

            uint32_t acc = 0;
            uint32_t bits = 0;
            _sz = 0;
            memset(_buf, 0, sizeof(_buf));
            for (size_t i = 0; i < u5_data.size() - 6; ++i) {
                uint8_t v = u5_data[i];
                acc <<= 5;
                acc |= v;
                bits += 5;
                while (bits >= 8) {
                    bits -= 8;
                    if (_sz >= sizeof(_buf)) throw error("bech32 payload must not exceed 57 bytes! %s", string(data).c_str());
                    _buf[_sz++] = (acc >> bits) & 0xFF;
                }
            }
            if (bits > 0) {
                if (bits >= 5) throw error("should not contain incomplete bytes with more than filled 5 bits: %s", string(data).c_str());
                if ((acc & ((1 << bits) - 1)) != 0) throw error("all the bits in the incomplete byte must be 0: %s", string(data).c_str());
            }
        }

        size_t size() const
        {
            return _sz;
        }

        const uint8_t *data() const
        {
            return _buf;
        }

        const buffer buf() const
        {
            return buffer(_buf, _sz);
        }

    };

}

#endif // !DAEDALUS_TURBO_BECH32_HPP
