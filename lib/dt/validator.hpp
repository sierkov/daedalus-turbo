/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_VALIDATOR_HPP
#define DAEDALUS_TURBO_VALIDATOR_HPP

#include <dt/indexer.hpp>

namespace daedalus_turbo::validator {
    extern indexer::indexer_map default_indexers(const std::string &data_dir, scheduler &sched=scheduler::get());
    using tail_relative_stake_map = std::map<cardano::slot, double>;

    struct incremental: indexer::incremental {
        incremental(indexer::indexer_map &&indexers, const std::string &data_dir, bool on_the_go=true, bool strict=true, scheduler &sched=scheduler::get(), file_remover &fr=file_remover::get());
        ~incremental() override;
        cardano::amount unspent_reward(const cardano::stake_ident &id) const;
        tail_relative_stake_map tail_relative_stake() const;
    protected:
        void _truncate_impl(uint64_t max_end_offset) override;
        uint64_t _valid_end_offset_impl() override;
        void _start_tx_impl() override;
        void _prepare_tx_impl() override;
        void _rollback_tx_impl() override;
        void _commit_tx_impl() override;
        chunk_info _parse(uint64_t offset, const std::string &rel_path,
            const buffer &raw_data, size_t compressed_size, const block_processor &extra_proc) const override;
        void _on_slice_ready(uint64_t first_epoch, uint64_t last_epoch, const indexer::merger::slice &slice) override;
    private:
        struct impl;
        friend impl;
        std::unique_ptr<impl> _impl;

        chunk_info _parent_parse(uint64_t offset, const std::string &rel_path,
            const buffer &raw_data, size_t compressed_size, const block_processor &extra_proc) const;
        void _parent_on_slice_ready(uint64_t first_epoch, uint64_t last_epoch, const indexer::merger::slice &slice);
        void _parent_truncate_impl(uint64_t max_end_offset);
        uint64_t _parent_valid_end_offset_impl();
        void _parent_start_tx_impl();
        void _parent_prepare_tx_impl();
        void _parent_rollback_tx_impl();
        void _parent_commit_tx_impl();
    };
}

#endif // !DAEDALUS_TURBO_VALIDATOR_HPP