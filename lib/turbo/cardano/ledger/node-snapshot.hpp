#pragma once

#include <filesystem>
#include <turbo/cardano/ledger/node-output.hpp>

namespace turbo::cardano::ledger::node_snapshot {
    struct reference {
        std::filesystem::path path;
        uint64_t epoch;
        uint64_t slot;
    };
    struct state_info {
        point tip;
        uint64_t era;
        uint64_t epoch;
    };
    std::vector<reference> discover(const std::filesystem::path &, uint64_t from, uint64_t to);
    state_info inspect(buffer state);
    // Owns the reference state once; tables are opened only after it agrees.
    class reader {
    public:
        explicit reader(const std::filesystem::path &);
        const state_info &info() const { return _info; }
        void compare(buffer state, const txo_map &) const;
        void compare(const reader &) const;
    private:
        std::filesystem::path _path;
        uint8_vector _state;
        state_info _info;
        uint32_t _checksum;
        void verify_tables(uint32_t crc) const;
    };
    uint32_t write_tables(const std::filesystem::path &, const txo_map &);
    uint32_t checksum(const std::filesystem::path &);
    void write_meta(const std::filesystem::path &, uint32_t state_crc, uint32_t tables_crc);
    void write_meta(const std::filesystem::path &);
    void verify(const std::filesystem::path &);
    // Throws at the first differing component, retaining its nested CBOR path.
    void compare(const std::filesystem::path &expected, const std::filesystem::path &actual);
}
