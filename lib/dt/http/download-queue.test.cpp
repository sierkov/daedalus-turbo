/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/http/download-queue.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;
using namespace daedalus_turbo::http;

suite http_download_queue_suite = [] {
    "http::download_queue"_test = [] {
        "parallel download"_test = [] {
            scheduler sched {};
            download_queue dlq { sched };
            dlq.start();
            size_t num_errors = 0;
            size_t num_oks = 0;
            auto handler = [&](auto &&res) {
                const auto &[url, body, error] = std::any_cast<download_queue::result>(res);
                if (!error.empty())
                    ++num_errors;
                else
                    ++num_oks;
            };
            for (size_t epoch = 0; epoch <= 447; ++epoch)
                dlq.download(fmt::format("http://turbo1.daedalusturbo.org/epoch-{}.json", epoch), handler);
            dlq.complete();
            sched.process();
            expect(num_errors == 0_u);
            expect(num_oks == 448_u);
        };
        "retry on recoverable errors"_test = [] {
            scheduler sched {};
            download_queue dlq { sched };
            dlq.start();
            size_t num_errors = 0;
            size_t num_oks = 0;
            auto handler = [&](auto &&res) {
                const auto &[url, body, error] = std::any_cast<download_queue::result>(res);
                if (!error.empty())
                    ++num_errors;
                else
                    ++num_oks;
            };
            dlq.download("http://turbo1.daedalusturbo.org/epoch-unknown.json", handler);
            dlq.complete();
            sched.process();
            // despite 3 retries, only the most recent error shall be reported
            expect(num_errors == 1_u);
            expect(num_oks == 0_u);
        };
        "empty queue finishes"_test = [] {
            scheduler sched {};
            download_queue dlq { sched };
            dlq.start();
            dlq.complete();
            sched.process();
            expect(true);
        };
    };
};
