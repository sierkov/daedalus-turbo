/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/ed25519.hpp>
#include <dt/mutex.hpp>

namespace daedalus_turbo::ed25519 {
    alignas(mutex::padding) static std::mutex m {};
    static bool sodium_ready = false;

    void init()
    {
        if (!sodium_ready) {
            std::scoped_lock lk { m };
            // checking again since another thread could have already started initializing the logger
            if (!sodium_ready) {
                if (sodium_init() == -1)
                    throw error("Failed to initialize libsodium!");
                sodium_ready = true;
            }
        }
    }            
}