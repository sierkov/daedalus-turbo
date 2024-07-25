/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_VALIDATOR_POOL_RANK_HPP
#define DAEDALUS_TURBO_VALIDATOR_POOL_RANK_HPP

#include <cmath>
#include <vector>
#include <zpp_bits.h>
#include <dt/error.hpp>
#include <dt/rational.hpp>

namespace daedalus_turbo::validator::pool_rank {
    using sample_list = std::vector<double>;
    using likelihood_list = std::vector<float>;
    using likelihood_prior = std::optional<std::reference_wrapper<const likelihood_list>>;

    inline const sample_list &samples()
    {
        static sample_list s {};
        if (s.empty()) {
            for (size_t i = 0; i < 100; ++i)
                s.emplace_back((static_cast<double>(i) + 0.5) / 100.0);
        }
        return s;
    }

    inline double leader_probability(const double active_slot_k, const double rel_stake, const double d)
    {
        if (active_slot_k <= 0.0 || active_slot_k > 1.0)
            throw error("active_slot_k is out of range: {}", active_slot_k);
        if (rel_stake < 0.0 || rel_stake > 1.0)
            throw error("rel_stake is out of range: {}", active_slot_k);
        if (d < 0.0 || d > 1.0)
            throw error("d is out of range: {}", active_slot_k);
        return (1.0 - std::pow(1.0 - active_slot_k, rel_stake)) * (1.0 - d);
    }

    inline float likelihood(const uint64_t num_blocks, const uint64_t epoch_slots, const double t, const double x)
    {
        if (!epoch_slots)
            throw error("epoch slots can't be zero!");
        if (num_blocks > epoch_slots)
            throw error("num blocks cannot be greater than the number of epoch slots: {}!", epoch_slots);
        if (t < 0.0 || t > 1.0)
            throw error("block producing probability is out of the allowed range: {}!", t);
        if (x < 0.0 || x > 1.0)
            throw error("evaluated hit rate is out of the allowed range: {}!", x);
        const uint64_t m = epoch_slots - num_blocks;
        return static_cast<double>(num_blocks) * std::log(x) + static_cast<double>(m) * std::log(1.0 - t * x);
    }

    inline void normalize(likelihood_list &lks)
    {
        if (!lks.empty()) {
            const auto min = *std::ranges::min_element(lks);
            for (auto &l: lks)
                l -= min;
        }
    }

    inline likelihood_list likelihoods(const size_t num_blocks, const uint64_t epoch_slots,
        const double rel_stake, const double active_slot_k, const double d,
        const likelihood_prior prior={})
    {
        likelihood_list lks {};
        const auto &positions = samples(); // samples cannot be empty!
        const auto t = leader_probability(active_slot_k, rel_stake, d);
        for (const auto x: positions)
            lks.emplace_back(likelihood(num_blocks, epoch_slots, t, x));
        if (prior) {
            const auto &prior_lks = prior->get();
            if (prior_lks.size() != lks.size())
                throw error("prior size {} does not match the sample size: {}!", prior_lks.size(), lks.size());
            normalize(lks);
            for (size_t i = 0; i < lks.size(); ++i)
                lks[i] = static_cast<float>(0.9F * prior_lks[i]) + lks[i];
        }
        normalize(lks);
        return lks;
    }
}

#endif // !DAEDALUS_TURBO_VALIDATOR_POOL_RANK_HPP