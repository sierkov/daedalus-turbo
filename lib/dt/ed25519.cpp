/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/ed25519.hpp>
#include <dt/mutex.hpp>

namespace daedalus_turbo::ed25519 {
    struct sodium_initializer {
        sodium_initializer() {
            if (sodium_init() == -1)
                throw error("Failed to initialize libsodium!");
        }
    };

    void ensure_initialized()
    {
        // will be initialized on the first call, after that do nothing
        static sodium_initializer init {};
    }            
}