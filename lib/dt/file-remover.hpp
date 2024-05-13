/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_FILE_REMOVER_HPP
#define DAEDALUS_TURBO_FILE_REMOVER_HPP

#include <chrono>
#include <dt/container.hpp>
#include <dt/file.hpp>
#include <dt/logger.hpp>

namespace daedalus_turbo {
    struct file_remover {
        using deleted_list = std::vector<std::string>;

        static file_remover &get()
        {
            static file_remover fr {};
            return fr;
        }

        explicit file_remover() =default;

        [[nodiscard]] size_t size() const
        {
            return _removable.size();
        }

        void mark(const std::string &path, const std::chrono::time_point<std::chrono::system_clock> &when=std::chrono::system_clock::now())
        {
            if (auto [it, created] = _removable.emplace(path, when); !created)
                it->second = when;
        }

        void unmark(const std::string &path)
        {
            _removable.erase(path);
        }

        void remove(const std::chrono::seconds &delay=std::chrono::seconds { 0 })
        {
            const auto delete_point = std::chrono::system_clock::now() - delay;
            for (auto it = _removable.begin(); it != _removable.end(); ) {
                if (it->second < delete_point) {
                    _remove(it->first, fmt::format("deref: when: {} delete_point: {}",
                        it->second.time_since_epoch().count(), delete_point.time_since_epoch().count()));
                    it = _removable.erase(it);
                } else {
                    ++it;
                }
            }
        }

        void remove_old_files(const std::filesystem::path &dir_path, const std::chrono::seconds &lifespan=std::chrono::seconds { 86400 }) const
        {
            const auto file_now = std::chrono::file_clock::now();
            for (auto &entry: std::filesystem::directory_iterator(dir_path)) {
                const auto file_age = std::chrono::duration_cast<std::chrono::seconds>(file_now - entry.last_write_time());
                if (entry.is_regular_file() && file_age > lifespan) {
                    const auto path = entry.path().string();
                    _remove(path, fmt::format("dir/older than {} sec; age: {} sec", lifespan.count(), file_age.count()));
                }
            }
        }
    private:
        using time_point = std::chrono::time_point<std::chrono::system_clock>;

        map<std::string, time_point> _removable {};

        static void _remove(const std::string &path, const std::string &note) {
            logger::debug("removing obsolete file: {} note: {}", path, note);
            std::filesystem::remove(path);
        }
    };
}

#endif // !DAEDALUS_TURBO_FILE_REMOVER_HPP