
C_FLAGS := -W -Wall
LD_DEPS := 3rdparty/blake2/blake2b.o 3rdparty/lz4/lz4.o 3rdparty/lz4/lz4hc.o
LD_FLAGS := $(LD_DEPS)

ifdef DEBUG
	C_FLAGS := $(C_FLAGS) -g
else
	C_FLAGS := $(C_FLAGS) -O3
endif
ifdef PROFILE
	C_FLAGS := $(C_FLAGS) -pg -g
endif
ifdef OPT
	C_FLAGS := $(C_FLAGS) -O1
endif

CXX_FLAGS := $(C_FLAGS) -std=c++20 -Ilib -I3rdparty

SOURCES := $(filter-out %.bench.cpp, $(filter-out %.test.cpp, $(wildcard src/*.cpp)))
TARGETS := $(filter-out %/run-tests, $(basename $(SOURCES)))
ITEST_SOURCES := $(wildcard test/*.cpp)
ITEST_TARGETS := $(patsubst %.cpp, %, $(ITEST_SOURCES))
TEST_TARGET := ./src/run-tests
TEST_SOURCES := $(wildcard lib/dt/*.test.cpp) src/run-tests.cpp
TEST_OBJECTS := $(patsubst %.cpp, %.o, $(TEST_SOURCES))
BENCH_TARGET := ./src/run-bench
BENCH_SOURCES := $(wildcard lib/dt/*.bench.cpp) src/run-tests.cpp
BENCH_OBJECTS := $(patsubst %.cpp, %.o, $(BENCH_SOURCES))
DEPS := $(wildcard lib/dt/*.hpp)

.PHONY: all clean test bench

all: $(TARGETS)

clean:
	$(RM) $(TEST_TARGET) $(BENCH_TARGET) $(TARGETS) $(ITEST_TARGETS) $(TEST_OBJECTS) $(BENCH_OBJECTS) $(LD_DEPS)

bench: $(BENCH_TARGET)
	$(BENCH_TARGET)

test: $(TEST_TARGET)
	$(TEST_TARGET)

itest: $(ITEST_TARGETS)

$(BENCH_TARGET): $(BENCH_OBJECTS) $(LD_DEPS)
	g++ -o $@ $(CXX_FLAGS) $^

$(TEST_TARGET): $(TEST_OBJECTS) $(LD_DEPS)
	g++ -o $@ $(CXX_FLAGS) $^

%.o: %.c
	gcc -c -o $@ $(C_FLAGS) $<

%.o: %.cpp $(DEPS)
	g++ -c -o $@ $(CXX_FLAGS) $<

%: %.cpp $(DEPS) $(LD_DEPS)
	g++ -o $@ $(CXX_FLAGS) $< $(LD_FLAGS)
