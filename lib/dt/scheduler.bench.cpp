#include <filesystem>
#include <boost/ut.hpp>
#include <dt/benchmark.hpp>
#include <dt/lz4.hpp>
#include <dt/scheduler.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

const string DATA_DIR = "./data"s;

suite scheduler_bench_suite = [] {
    "scheduler"_test = [] {
        size_t num_iter = 3;
        size_t data_multiple = 20;
        "micro_tasks_default"_test = [num_iter, data_multiple] {
            vector<bin_string> chunks;
            bin_string buf;
            for (const auto &entry: filesystem::directory_iterator(DATA_DIR)) {
                if (entry.path().extension() != ".chunk") continue;
                read_whole_file(entry.path().string(), buf);
                chunks.push_back(buf);
            }
            double throughput = benchmark_throughput("scheduler/default progress update", num_iter, [data_multiple, &chunks]() {
                size_t total_size = 0;
                scheduler s;
                for (size_t i = 0; i < data_multiple; ++i) {
                    for (const auto &chunk: chunks) {
                        s.submit(
                            "lz4_compress", 0,
                            [&chunk]() {
                                bin_string tmp;
                                lz4_compress(tmp, chunk);
                                return true;
                            }
                        );
                        total_size += chunk.size();
                    }
                }    
                s.process();
                return total_size;
            });
            expect(throughput >= 200'000'000.0_d);
        };
    };
};
