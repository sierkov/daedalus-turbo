/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_HTTP_API_HPP
#define DAEDALUS_TURBO_HTTP_API_HPP

#include <memory>
#include <string>
#include <dt/scheduler.hpp>

namespace daedalus_turbo::http_api {
    struct server {
        server(const std::string &data_dir, const bool ignore_requirements=false, scheduler &sched=scheduler::get());
        ~server();
        void serve(const std::string &ip, uint16_t port);
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif // !DAEDALUS_TURBO_HTTP_API_HPP