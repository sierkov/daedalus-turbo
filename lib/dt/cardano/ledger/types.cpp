/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/ledger/types.hpp>
#include <dt/cardano/shelley.hpp>
#include <dt/progress.hpp>
#include <dt/scheduler.hpp>
#include <dt/timer.hpp>

namespace daedalus_turbo::cardano::ledger {
    parallel_decoder::parallel_decoder(const std::string &path): _data { file::read_raw(path) }
    {
        const auto num_bufs = _data.span().subbuf(0, sizeof(size_t)).to<size_t>();
        size_t next_offset = (num_bufs + 1) * sizeof(size_t);
        for (size_t i = 0; i < num_bufs; ++i) {
            const auto buf_size = _data.span().subbuf((i + 1) * sizeof(size_t), sizeof(size_t)).to<size_t>();
            _buffers.emplace_back(_data.span().subbuf(next_offset, buf_size));
            next_offset += buf_size;
        }
    }

    size_t parallel_decoder::size() const
    {
        return _buffers.size();
    }

    buffer parallel_decoder::at(const size_t idx) const
    {
        return _buffers.at(idx);
    }

    void parallel_decoder::add(const decode_func &t)
    {
        _tasks.emplace_back(t);
    }

    void parallel_decoder::on_done(const done_func &f)
    {
        _on_done.emplace_back(f);
    }

    void parallel_decoder::run(scheduler &sched, const std::string &task_group, const int prio, const bool report_progress)
    {
        if (_tasks.size() != _buffers.size()) [[unlikely]]
            throw error(fmt::format("was expecting {} items in the serialized data but got {}!", _buffers.size(), _tasks.size()));
        sched.wait_all_done(task_group, _buffers.size(),
            [&] {
                for (size_t i = 0; i < _buffers.size(); ++i) {
                    sched.submit_void(task_group, _buffers[i].size() * prio / _data.size(), [&, i] { _tasks[i](_buffers[i]); } );
                }
            },
            [this, &task_group, report_progress](auto &&, auto done, auto errs) {
                if (report_progress)
                    progress::get().update(task_group, done - errs, _tasks.size());
            }
        );
        for (const auto &f: _on_done)
            f();
    }

    size_t parallel_serializer::size() const
    {
        return _tasks.size();
    }

    void parallel_serializer::add(const encode_func &t)
    {
        _tasks.emplace_back(t);
        _buffers.emplace_back();
    }

    void parallel_serializer::run(scheduler &sched, const std::string &task_group, const int prio, const bool report_progress)
    {
        sched.wait_all_done(task_group, _tasks.size(),
            [&] {
                for (size_t i = 0; i < _tasks.size(); ++i) {
                    sched.submit_void(task_group, prio, [this, i] {
                        _buffers[i] = _tasks[i]();
                    });
                }
            },
            [this, &task_group, report_progress](auto &&, auto done, auto errs) {
                if (report_progress)
                    progress::get().update(task_group, done - errs, _tasks.size());
            }
        );
    }

    void parallel_serializer::save(const std::string &path, const bool headers) const
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

    uint8_vector parallel_serializer::flat() const
    {
        uint8_vector res {};
        for (const auto &buf: _buffers)
            res << buf;
        return res;
    }
}
