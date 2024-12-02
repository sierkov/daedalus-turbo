/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ASIO_HPP
#define DAEDALUS_TURBO_ASIO_HPP

#include <functional>
#include <memory>
#include <string>

namespace boost::asio {
    struct io_context;
}

namespace daedalus_turbo::asio {
    struct speed_mbps {
        double current = 0.0;
        double max = 0.0;
    };

    struct worker {
        using action_type = std::function<void()>;

        static worker &get();
        explicit worker();
        ~worker();
        void add_before_action(const std::string &name, const action_type &act);
        void del_before_action(const std::string &name);
        void add_after_action(const std::string &name, const action_type &act);
        void del_after_action(const std::string &name);
        boost::asio::io_context &io_context();
        void internet_speed_report(double);
        speed_mbps internet_speed() const;
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif // !DAEDALUS_TURBO_ASIO_HPP
