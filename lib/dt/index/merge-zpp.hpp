/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_MERGE_ZPP_HPP
#define DAEDALUS_TURBO_INDEX_MERGE_ZPP_HPP

#include <dt/container.hpp>
#include <dt/index/io.hpp>
#include <dt/zpp-stream.hpp>

namespace daedalus_turbo::index {
     template<typename T>
     size_t merge_zpp(const std::string &out_path, const vector<std::string> &chunks)
     {
         vector<zpp_stream::read_stream> inputs {};
         inputs.reserve(chunks.size());
         for (const auto &path: chunks)
             inputs.emplace_back(path);
         zpp_stream::write_stream out { out_path };
         merge_queue<T> items_to_consider {};
         for (size_t i = 0; i < inputs.size(); ++i) {
             auto &in = inputs[i];
             if (!in.eof())
                 items_to_consider.emplace(in.read<T>(), i);
         }
         size_t num_recs = 0;
         while (items_to_consider.size() > 0) {
             merge_item next = std::move(items_to_consider.top());
             items_to_consider.pop();
             out.write(next.val);
             ++num_recs;
             auto &in = inputs[next.stream_idx];
             if (!in.eof()) {
                 next.val = in.template read<T>();
                 items_to_consider.emplace(std::move(next));
             }
         }
         return num_recs;
    }
}

#endif //!DAEDALUS_TURBO_INDEX_MERGE_ZPP_HPP