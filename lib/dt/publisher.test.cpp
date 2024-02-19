/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/publisher.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite publisher_suite = [] {
    "publisher"_test = [] {
        scheduler sched {};
        const std::string node_path { "./data"s };
        const std::string dist_path { "./tmp/www"s };
        if (std::filesystem::exists(dist_path))
            std::filesystem::remove_all(dist_path);
        chunk_registry cr { sched, dist_path };
        cr.init_state(false);
        publisher p { sched, cr, node_path, true, 3 };
        p.publish();
        expect(p.size() == 29_ull);
        expect(std::filesystem::exists(dist_path + "/chain.json"));
        expect(std::filesystem::exists(dist_path + "/epoch-412.json"));
        expect(std::filesystem::exists(dist_path + "/epoch-413.json"));
    };
};