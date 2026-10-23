#pragma once

#include <turbo/cardano/common/types.hpp>
#include <turbo/cbor/compare.hpp>

namespace turbo::cardano::ledger::node_snapshot {
    // Node 11.1.3 V2InMemory packed UTxO records (Shelley through Conway).
    stake_pointer normalize_pointer(const stake_pointer &);
    uint8_vector pack_output(const tx_out_data &);
    tx_out_data unpack_output(buffer, uint64_t era);
    uint8_vector pack_input(const tx_out_ref &);
    tx_out_ref unpack_input(buffer);
    cbor::diff_list compare_outputs(buffer expected, buffer actual, uint64_t era);
}
