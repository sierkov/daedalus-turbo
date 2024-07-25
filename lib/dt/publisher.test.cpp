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
        chunk_registry cr { dist_path, chunk_registry::mode::store };
        cr.config().shelley_start_slot(4'492'800);
        ed25519::skey sk {};
        ed25519::vkey vk {};
        ed25519::create(sk, vk);
        publisher p { cr, node_path, sk, 3 };
        p.publish();
        test_same(30, p.size());
        expect(std::filesystem::exists(dist_path + "/chain.json"));
        expect(std::filesystem::exists(dist_path + "/epoch-412-F2C09FD9B3D9A5D488924C8864284730236DBAD0D3F8140998210C6218852A5E.json"));
        expect(std::filesystem::exists(dist_path + "/epoch-413-69AB9C82E7C4EDF5DADD494054CEB3B340EC037699D9ED503C0DD0CA699C9467.json"));
        const auto meta = json::load_signed(dist_path + "/chain.json", vk);
        test_same(meta.at("api").at("version").as_int64(), 3);
        const auto peers = json::load_signed(dist_path + "/peers.json", vk).as_object();
        expect(peers.at("hosts").as_array().size() >= 2);
    };
};