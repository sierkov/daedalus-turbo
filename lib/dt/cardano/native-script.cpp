/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/format.hpp>
#include <dt/cardano/native-script.hpp>

namespace daedalus_turbo::cardano::native_script {
    optional_error_string validate(const cbor::value &script, const uint64_t slot, const set<key_hash> &vkeys)
    {
        switch (const auto typ = script.at(0).uint(); typ) {
            case 0:
                if (const auto &req_vkey = script.at(1).buf(); !vkeys.contains(req_vkey)) [[unlikely]]
                    return fmt::format("required key {} didn't sign the transaction", req_vkey);
                break;
            case 1:
                for (const auto &sub_script: script.at(1).array()) {
                    if (const auto err = validate(sub_script, slot, vkeys); err)
                        return err;
                }
                break;
            case 2: {
                bool any_ok = false;
                for (const auto &sub_script: script.at(1).array()) {
                    if (!validate(sub_script, slot, vkeys))
                        any_ok = true;
                }
                if (!any_ok) [[unlikely]]
                    return fmt::format("no child script has been successful!");
                break;
            }
            case 3: {
                const auto min_ok = script.at(1).uint();
                uint64_t num_ok = 0;
                for (const auto &sub_script: script.at(2).array()) {
                    if (!validate(sub_script, slot, vkeys))
                        ++num_ok;
                }
                if (num_ok < min_ok) [[unlikely]]
                    return fmt::format("only {} child scripts succeed while {} are required!", num_ok, min_ok);
                break;
            }
            case 4:
                if (const auto invalid_before = script.at(1).uint(); slot < invalid_before)
                    return fmt::format("invalid before {} while the current slot is {}!", invalid_before, slot);
                break;
            case 5:
                if (const auto invalid_after = script.at(1).uint(); slot >= invalid_after)
                    return fmt::format("invalid after {} while the current slot is {}!", invalid_after, slot);
                break;
            default:
                return fmt::format("unsupported native script type {}", typ);
        }
        return {};
    }
}
