/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/publisher.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite publisher_suite = [] {
    "publisher"_test = [] {
        const std::string node_path { "./data" };
        const std::string dist_path { "./tmp/www" };
        if (std::filesystem::exists(dist_path))
            std::filesystem::remove_all(dist_path);
        chunk_registry cr { dist_path, false };
        publisher p { cr, node_path, 3 };
        p.publish();
        expect(p.size() == 29_ull);
        expect(std::filesystem::exists(dist_path + "/chain.json"));
        expect(std::filesystem::exists(dist_path + "/epoch-412-F2C09FD9B3D9A5D488924C8864284730236DBAD0D3F8140998210C6218852A5E.json"));
        expect(std::filesystem::exists(dist_path + "/epoch-413-69AB9C82E7C4EDF5DADD494054CEB3B340EC037699D9ED503C0DD0CA699C9467.json"));
        auto api_info = json::load(dist_path + "/api.json");
        expect(api_info.at("version").as_int64() == 1_ll);
    };
};