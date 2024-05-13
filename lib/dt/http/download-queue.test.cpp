/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/config.hpp>
#include <dt/http/download-queue.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::http;

suite http_download_queue_suite = [] {
    const std::string tmp_dir { "./tmp/test-download-queue-ng" };
    std::filesystem::create_directories(tmp_dir);
    "http::download_queue"_test = [&] {
        "parallel download"_test = [&] {
            download_queue_async dlq {};
            std::atomic_size_t num_errors = 0;
            std::atomic_size_t num_oks = 0;
            auto handler = [&](auto &&r) {
                if (r.error)
                    ++num_errors;
                else
                    ++num_oks;
            };
            for (size_t i = 0; i < 32; ++i)
                dlq.download("http://turbo1.daedalusturbo.org/chain.json", fmt::format("{}/chain-{}.json", tmp_dir, i), 0, handler);
            dlq.process();
            expect(num_errors.load() == 0_u);
            expect(num_oks.load() == 32_u);
        };
        "retry on recoverable errors"_test = [&] {
            download_queue_async dlq {};
            std::atomic_size_t num_errors = 0;
            std::atomic_size_t num_oks = 0;
            auto handler = [&](auto &&r) {
                if (r.error)
                    ++num_errors;
                else
                    ++num_oks;
            };
            dlq.download("http://turbo1.daedalusturbo.org/epoch-unknown.json", tmp_dir + "/epoch-unknown", 0, handler);
            expect(!dlq.process_ok());
            expect(num_errors.load() == 1_u);
            expect(num_oks.load() == 0_u);
        };
        "empty queue finishes"_test = [] {
            download_queue_async dlq {};
            expect(dlq.process_ok());
        };
        "fetch_json_signed"_test = [] {
            download_queue_async dlq {};
            const auto vk = ed25519_vkey::from_hex(static_cast<std::string_view>(configs_dir::get().at("turbo").at("vkey").as_string()));
            const auto j_chain = dlq.fetch_json_signed("http://turbo1.daedalusturbo.org/chain.json", vk).as_object();
            expect(!j_chain.at("epochs").as_array().empty());
        };
        "destructor cancels tasks"_test = [&] {
            {
                download_queue_async dlq {};
                for (size_t i = 0; i < 32; ++i)
                    dlq.download("http://turbo1.daedalusturbo.org/chain.json", fmt::format("{}/chain-{}.json", tmp_dir, i), 0, [](auto &&) {});
                // do not call process and destroy the queue
                // should cancel the tasks and quit
            }
            expect(true);
        };
    };
};