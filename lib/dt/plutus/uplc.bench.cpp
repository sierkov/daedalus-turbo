/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/plutus/uplc.hpp>
#include <dt/benchmark.hpp>

using namespace daedalus_turbo;

suite plutus_uplc_suite = [] {
    "plutus::uplc"_test = [] {
        const auto paths = file::files_with_ext(install_path("./data/plutus/conformance/example"), ".uplc");
        benchmark("uplc parse speed", 1e6, 5, [&] {
            uint64_t total_size = 0;
            for (const auto &path: paths) {
              try {
                  auto bytes = file::read(path.string());
                  total_size += bytes.size();
                  plutus::allocator alloc {};
                  plutus::uplc::script s { alloc, std::move(bytes) };
              } catch (...) {
                  const auto exp_path = (path.parent_path() / (path.stem().string() + ".uplc.expected")).string();
                  if (std::filesystem::exists(exp_path)) {
                      const std::string exp_res { file::read(exp_path).str() };
                      if (exp_res == "parse error")
                          continue;
                  }
                  throw error("unable to parse script: {}", path);
              }
            }
            return total_size;
        });
    };
};