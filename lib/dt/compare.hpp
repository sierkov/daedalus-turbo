/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_COMPARE_HPP
#define DAEDALUS_TURBO_COMPARE_HPP

#include <string>
#include <dt/logger.hpp>

namespace daedalus_turbo {
    template<typename ExpDist, typename ActDist>
    void compare_dists(const std::string &name, const ExpDist &expected, const ActDist &actual)
    {
        logger::trace("{} expected items: {} actual items: {} size diff: {}",
            name, expected.size(), actual.size(), static_cast<int64_t>(actual.size()) - static_cast<int64_t>(expected.size()));
        size_t diffs = 0;
        for (const auto &[id, exp_val]: expected) {
            if (!actual.contains(id)) {
                logger::trace("{} missing item: {} val: {}", name, id, exp_val);
                ++diffs;
                continue;
            }
            const auto &act_val = actual.at(id);
            if (exp_val != act_val) {
                logger::trace("{} item: {} expected: {} actual: {}", name, id, exp_val, act_val);
                ++diffs;
            }
        }
        // do an inverse check to detect extra elements
        for (const auto &[id, act_val]: actual) {
            if (!expected.contains(id)) {
                logger::trace("{} extra item: {} val: {}", name, id, act_val);
                ++diffs;
            }
        }
        if (diffs == 0)
            logger::info("{} {} items match", name, expected.size());
        else
            logger::warn("{} has {} differences - see the details in the log file", name, diffs);
    }

    template<typename T>
    concept ConvertibleToInt = requires(T a)
    {
        static_cast<int64_t>(a);
    };

    template<ConvertibleToInt T>
    bool compare_values(const std::string &name, const T &expected, const T &actual, const bool verbose=true)
    {
        const bool res = expected == actual;
        if (!res) {
            logger::warn("{} mismatch node: {} dt: {} diff: {}", name, expected, actual,
                static_cast<int64_t>(actual) - static_cast<int64_t>(expected));
        } else if (verbose) {
            logger::info("{} values match", name);
        }
        return res;
    }

    template<typename T>
    bool compare_values(const std::string &name, const T &expected, const T &actual, const bool verbose=true)
    {
        const bool res = expected == actual;
        if (!res) {
            logger::warn("{} mismatch node: {} dt: {}", name, expected, actual);
        } else if (verbose) {
            logger::info("{} values match", name);
        }
        return res;
    }
}

#endif // !DAEDALUS_TURBO_CONFIG_HPP