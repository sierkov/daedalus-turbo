/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <iostream>
#include <dt/cardano.hpp>
#include <dt/history.hpp>

using namespace std;
using namespace daedalus_turbo;

int main(int argc, char **argv) {
    if (argc < 4) {
        cerr << "Usage: search-index <chain-dir> <index-dir> <stake-address> [--lz4]" << endl;
        return 1;
    }
    const string db_path = argv[1];
    const string idx_path = argv[2];
    uint8_vector addr_buf = cardano_parse_address(string_view(argv[3], strlen(argv[3])));
    bool lz4 = false;
    for (int i = 4; i < argc; ++i) {
        const string_view arg_i(argv[i], strlen(argv[i]));
        if (arg_i == "--lz4"sv) {
            lz4 = true;
        } else {
            cerr << "Error: unsupported command-line argument: " << arg_i << endl;
            return 1;
        }
    }
    reconstructor r(db_path, idx_path, lz4);
    switch (addr_buf.size()) {
        case 28:
            cout << r.reconstruct_raw_addr(addr_buf);
            break;

        case 29:
            cout << r.reconstruct(addr_buf);
            break;

        default:
            throw error("expected a stake key of 28 or 29 bytes but got: %zu!", addr_buf.size());
    }
    return 0;
}
