#pragma once
#ifndef DAEDALUS_TURBO_PARALLEL_ENCODER_HPP
#define DAEDALUS_TURBO_PARALLEL_ENCODER_HPP
/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <algorithm>
#include <functional>
#include <vector>
#include <dt/common/bytes.hpp>
#include <dt/common/file.hpp>
#include <dt/parallel/encoder.hpp>
#include <dt/progress.hpp>
#include <dt/scheduler.hpp>
#include <dt/timer.hpp>

namespace daedalus_turbo::parallel {
    template<typename ENC>
    struct encoder {
        using encode_func = std::function<uint8_vector(ENC)>;
        using init_func = std::function<ENC()>;

        explicit encoder(const init_func &init_fn=[]{ return ENC {}; }):
            _init_fn { init_fn }
        {
        }

        [[nodiscard]] size_t size() const
        {
            return _tasks.size();
        }

        void add(const encode_func &t)
        {
            _tasks.emplace_back(t);
            _buffers.emplace_back();
        }

        void run(scheduler &sched, const std::string &task_group, int prio=1000, bool report_progress=false)
        {
            sched.wait_all_done(task_group, _tasks.size(),
                [&] {
                    for (size_t i = 0; i < _tasks.size(); ++i) {
                        sched.submit_void(task_group, prio, [this, i] {
                            if constexpr (std::is_same_v<ENC, void>) {
                                _buffers[i] = _tasks[i]();
                            } else {
                                _buffers[i] = _tasks[i](_init_fn());
                            }
                        });
                    }
                },
                [this, &task_group, report_progress](auto &&, auto done, auto errs) {
                    if (report_progress)
                        progress::get().update(task_group, done - errs, _tasks.size());
                }
            );
        }

        void save(const std::string &path, bool headers=false) const
        {
            const auto tmp_path = fmt::format("{}.tmp", path);
            timer t { fmt::format("writing serialized data to {}", path), logger::level::debug };
            {
                file::write_stream ws { tmp_path };
                // first write the block sizes to allow parallel load
                if (headers) {
                    ws.write(buffer::from<size_t>(_buffers.size()));
                    for (const auto &buf: _buffers)
                        ws.write(buffer::from<size_t>(buf.size()));
                }
                // then write the actual data
                for (const auto &buf: _buffers)
                    ws.write(buf);
            }
            // ensures the correct file exists only if the whole saving procedure is successful
            std::filesystem::rename(tmp_path, path);
        }

        [[nodiscard]] uint8_vector flat() const
        {
            uint8_vector res {};
            res.reserve(std::accumulate(_buffers.begin(), _buffers.end(), size_t { 0 }, [](const auto sum, const auto &b) { return sum + b.size(); }));
            for (const auto &buf: _buffers)
                res << buf;
            return res;
        }
    private:
        init_func _init_fn;
        std::vector<encode_func> _tasks {};
        std::vector<uint8_vector> _buffers {};
    };
}

#endif //!DAEDALUS_TURBO_PARALLEL_ORDERED_CONSUMER_HPP