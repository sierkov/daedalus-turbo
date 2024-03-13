/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PROGRESS_HPP
#define DAEDALUS_TURBO_PROGRESS_HPP

#include <map>
#include <dt/format.hpp>
#include <dt/mutex.hpp>

namespace daedalus_turbo {
    struct progress {
        using state_map = std::map<std::string, double>;

        struct info {
            size_t total = 0;
            size_t active = 0;
            size_t completed = 0;
            size_t failed = 0;
        };

        static progress &get()
        {
            static progress p {}; // C++ standard guarantees a thread-safe initialization on the first call
            return p;
        }

        void init(const std::string &name)
        {
            _update(name, 0.0);
        }

        void update(const std::string &name, const uint64_t current, const uint64_t max)
        {
            auto value = current < max ? current : max;
            auto pct_value = max == 0 ? 1.0 : static_cast<double>(value) / max;
            _update(name, pct_value);
        }

        void done(const std::string &name)
        {
            _update(name, 1.0);
        }

        void retire(const std::string &name)
        {
            std::scoped_lock lk { _state_mutex };
            _state.erase(name);
        }

        void inform(std::ostream &stream=std::cerr)
        {
            std::string str {};
            {
                std::scoped_lock lk { _state_mutex };
                for (const auto &[name, val]: _state)
                    str += fmt::format("{}: {:0.3f}% ", name, val * 100);
            }
            // adjust for the invisible whitespace
            if (str.size() > _max_str)
                _max_str = str.size();
            stream << fmt::format("{:<{}}\r", str, _max_str);
        }

        state_map copy() const
        {
            state_map state_copy {};
            {
                std::scoped_lock lk { _state_mutex };
                state_copy = _state;
            }
            return state_copy;
        }
    private:
        alignas(mutex::padding) mutable std::mutex _state_mutex {};
        state_map _state {};
        size_t _max_str = 0;

        void _update(const std::string &name, const double value)
        {
            std::scoped_lock lk { _state_mutex };
            auto [it, created] = _state.try_emplace(name, value);
            if (!created && value > it->second)
                it->second = value;
        }
    };

    struct progress_guard {
        progress_guard(const std::initializer_list<std::string> &names): _names { names }, _progress { progress::get() }
        {
            for (const auto &name: _names)
                _progress.init(name);
        }

        ~progress_guard()
        {
            for (const auto &name: _names)
                _progress.retire(name);
        }
    private:
        const std::vector<std::string> _names;
        progress &_progress;
    };
}

#endif // !DAEDALUS_TURBO_PROGRESS_HPP