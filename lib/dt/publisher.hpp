/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PUBLISHER_HPP
#define DAEDALUS_TURBO_PUBLISHER_HPP

#include <memory>
#include <string>
#include <dt/chunk-registry.hpp>
#include <dt/ed25519.hpp>
#include <dt/file-remover.hpp>

namespace daedalus_turbo {
    struct  publisher {
        publisher(chunk_registry &cr, const std::string &node_path, const buffer &sk, size_t zstd_max_level=22, file_remover &fr=file_remover::get());
        ~publisher();
        size_t size() const;
        void publish();
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif // !DAEDALUS_TURBO_PUBLISHER_HPP