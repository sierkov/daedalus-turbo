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

        size_t size() const
        {
            return _removable.size();
        }

        void mark(const std::string &path, const std::chrono::time_point<std::chrono::system_clock> &when=std::chrono::system_clock::now())
        {
            _removable.emplace(path, when);
        }

        void unmark(const std::string &path)
        {
            _removable.erase(path);
        }

        void remove(const std::chrono::seconds &delay=std::chrono::seconds { 0 })
        {
            auto delete_point = std::chrono::system_clock::now() - delay;
            for (auto it = _removable.begin(); it != _removable.end(); ) {
                if (it->second < delete_point) {
                    _remove(it->first, fmt::format("deref and older than {} sec", delay.count()));
                    it = _removable.erase(it);
                } else {
                    ++it;
                }
            }
        }

        void remove_old_files(const std::filesystem::path &dir_path, const std::chrono::seconds &lifespan=std::chrono::seconds { 86400 }) const
        {
            auto file_now = std::chrono::file_clock::now();
            for (auto &entry: std::filesystem::directory_iterator(dir_path)) {
                auto file_age = std::chrono::duration_cast<std::chrono::seconds>(file_now - entry.last_write_time());
                if (entry.is_regular_file() && file_age > lifespan) {
                    auto path = entry.path().string();
                    _remove(path, fmt::format("dir/older than {} sec; age: {} sec", lifespan.count(), file_age.count()));
                }
            }
        }
    private:
        using time_point = std::chrono::time_point<std::chrono::system_clock>;

        map<std::string, time_point> _removable {};

        static void _remove(const std::string &path, const std::string &note) {
            logger::trace("removing obsolete file: {} note: {}", path, note);
            std::filesystem::remove(path);
        }
    };
}

#endif // !DAEDALUS_TURBO_FILE_REMOVER_HPP