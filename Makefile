
C_FLAGS := -W -Wall
LD_DEPS := 3rdparty/blake2/blake2b.o 3rdparty/lz4/lz4.o 3rdparty/lz4/lz4hc.o
LD_FLAGS := $(LD_DEPS)
GXX := g++
GCC := gcc

ifdef COV
	C_FLAGS := $(C_FLAGS) --coverage -g
else ifdef PROFILE
	C_FLAGS := $(C_FLAGS) -pg -g
else ifdef DEBUG
	C_FLAGS := $(C_FLAGS) -g
else
	C_FLAGS := $(C_FLAGS) -O3
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
TEST_PROF := $(patsubst %.o, %.gcda, $(TEST_OBJECTS)) $(patsubst %.o, %.gcno, $(TEST_OBJECTS)) \
	$(patsubst %.o, %.gcda, $(LD_DEPS)) $(patsubst %.o, %.gcno, $(LD_DEPS))
BENCH_TARGET := ./src/run-bench
BENCH_SOURCES := $(wildcard lib/dt/*.bench.cpp) src/run-tests.cpp
BENCH_OBJECTS := $(patsubst %.cpp, %.o, $(BENCH_SOURCES))
DEPS := $(wildcard lib/dt/*.hpp)

.PHONY: all clean test test-run coverage bench bench-run itest

all: $(TARGETS)

clean:
	$(RM) $(TEST_TARGET) $(BENCH_TARGET) $(TARGETS) $(ITEST_TARGETS) $(TEST_OBJECTS) $(BENCH_OBJECTS) $(LD_DEPS) $(TEST_PROF)

bench: $(BENCH_TARGET)

bench-run: bench
	$(BENCH_TARGET)

test: $(TEST_TARGET)

test-run: test
	$(TEST_TARGET)

itest: $(ITEST_TARGETS)

coverage:
	gcovr --html-details out/coverage.html

$(BENCH_TARGET): $(BENCH_OBJECTS) $(LD_DEPS)
	$(GXX) -o $@ $(CXX_FLAGS) $^

$(TEST_TARGET): $(TEST_OBJECTS) $(LD_DEPS)
	$(GXX) -o $@ $(CXX_FLAGS) $^

%.o: %.c
	$(GCC) -c -o $@ $(C_FLAGS) $<

%.o: %.cpp $(DEPS)
	$(GXX) -c -o $@ $(CXX_FLAGS) $<

%: %.cpp $(DEPS) $(LD_DEPS)
	$(GXX) -o $@ $(CXX_FLAGS) $< $(LD_FLAGS)
