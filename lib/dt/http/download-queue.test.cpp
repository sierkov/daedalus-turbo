/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/http/download-queue.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;
using namespace daedalus_turbo::http;

suite http_download_queue_suite = [] {
    const std::string tmp_dir { "./tmp/test-download-queue-ng" };
    std::filesystem::create_directories(tmp_dir);
    "http::download_queue"_test = [&] {
        "parallel download"_test = [&] {
            download_queue dlq {};
            size_t num_errors = 0;
            size_t num_oks = 0;
            auto handler = [&](auto &&res) {
                const auto &r = std::any_cast<download_queue::result>(res);
                if (r.error)
                    ++num_errors;
                else
                    ++num_oks;
            };
            for (size_t epoch = 0; epoch <= 447; ++epoch)
                dlq.download(fmt::format("http://turbo1.daedalusturbo.org/epoch-{}.json", epoch), fmt::format("{}/epoch-{}.json", tmp_dir, epoch), 0, handler);
            dlq.process();
            expect(num_errors == 0_u);
            expect(num_oks == 448_u);
        };
        "retry on recoverable errors"_test = [&] {
            download_queue dlq {};
            size_t num_errors = 0;
            size_t num_oks = 0;
            auto handler = [&](auto &&res) {
                const auto &r = std::any_cast<download_queue::result>(res);
                if (r.error)
                    ++num_errors;
                else
                    ++num_oks;
            };
            dlq.download("http://turbo1.daedalusturbo.org/epoch-unknown.json", tmp_dir + "/epoch-unknown", 0, handler);
            expect(dlq.process_ok() == false);
            expect(num_errors == 1_u);
            expect(num_oks == 0_u);
        };
        "empty queue finishes"_test = [] {
            download_queue dlq {};
            expect(dlq.process_ok());
        };
    };
};