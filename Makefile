GXX := g++
GCC := gcc
SHELL := /bin/bash
C_FLAGS := -W -Wall
LD_DEPS := $(LD_DEPS) 3rdparty/vrf03/convert.o 3rdparty/vrf03/verify.o 3rdparty/vrf03/ed25519_ref10.o lib/dt/lib.o
LD_FLAGS := $(LDFLAGS) -lzstd -lsodium -lfmt -lspdlog
RM := rm -rf

ifeq ($(OS),Windows_NT)
	LD_FLAGS := $(LD_FLAGS) -lboost_coroutine-mt  -lboost_json-mt  -lboost_url-mt -lboost_system-mt -lwsock32 -lws2_32
	C_FLAGS := $(C_FLAGS)
else
	LD_FLAGS := $(LD_FLAGS) -lboost_coroutine -lboost_json -lboost_url -lboost_system
	UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
		GXX := clang++
		GCC := clang
		C_FLAGS := $(C_FLAGS) -Wno-missing-braces

    endif
endif

ifdef COV
	C_FLAGS := $(C_FLAGS) --coverage -g
else ifdef PROFILE
	ifeq ($(UNAME_S),Darwin)
		C_FLAGS := $(C_FLAGS) -O3 -g
		LD_FLAGS := $(LD_FLAGS) -lprofiler
	else
		C_FLAGS := $(C_FLAGS) -pg -g
    endif
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
TARGETS_DSYM := $(patsubst %.cpp, %.dSYM, $(SOURCES))
ITEST_SOURCES := $(wildcard test/*.cpp)
ITEST_TARGETS := $(patsubst %.cpp, %, $(ITEST_SOURCES))
TEST_TARGET := src/run-tests
TEST_SOURCES := $(wildcard lib/dt/*.test.cpp) $(wildcard lib/dt/*/*.test.cpp) src/run-tests.cpp
TEST_OBJECTS := $(patsubst %.cpp, %.o, $(TEST_SOURCES))
TEST_PROF := $(patsubst %.o, %.gcda, $(TEST_OBJECTS)) $(patsubst %.o, %.gcno, $(TEST_OBJECTS)) \
	$(patsubst %.o, %.gcda, $(LD_DEPS)) $(patsubst %.o, %.gcno, $(LD_DEPS))
BENCH_TARGET := src/run-bench
BENCH_SOURCES := $(wildcard lib/dt/*.bench.cpp) $(wildcard lib/dt/*/*.bench.cpp) src/run-tests.cpp
BENCH_OBJECTS := $(patsubst %.cpp, %.o, $(BENCH_SOURCES))
DEPS := $(wildcard lib/dt/*.hpp) $(wildcard lib/dt/*/*.hpp) $(wildcard lib/dt/*/*/*.hpp)

.PHONY: all clean test test-run coverage bench bench-run itest

all: $(TARGETS)

clean:
	$(RM) $(TEST_TARGET) $(BENCH_TARGET) $(TARGETS) $(TARGETS_DSYM) $(ITEST_TARGETS) $(TEST_OBJECTS) $(BENCH_OBJECTS) $(LD_DEPS) $(TEST_PROF)

bench: $(BENCH_TARGET)

bench-run: bench
	$(BENCH_TARGET)

test: $(TEST_TARGET)

test-run: test
	$(TEST_TARGET)

itest: $(ITEST_TARGETS)

coverage:
	gcovr --gcov-ignore-parse-errors=negative_hits.warn --html-details tmp/coverage.html

$(BENCH_TARGET): $(BENCH_OBJECTS) $(LD_DEPS)
	$(GXX) -o $@ $(CXX_FLAGS) $(filter-out %.built, $(filter-out %.hpp, $^)) $(LD_FLAGS)

$(TEST_TARGET): $(TEST_OBJECTS) $(LD_DEPS)
	$(GXX) -o $@ $(CXX_FLAGS) $(filter-out %.built, $(filter-out %.hpp, $^)) $(LD_FLAGS)

%.o: %.c
	$(GCC) -c -o $@ $(C_FLAGS) -Wno-unused-function -Wno-array-parameter -Wno-unused-value $<

3rdparty/%.o: 3rdparty/%.cpp
	$(GXX) -c -o $@ $(CXX_FLAGS) $<

%.o: %.cpp $(DEPS)
	$(GXX) -c -o $@ $(CXX_FLAGS) $<

%: %.cpp $(DEPS) $(LD_DEPS)
	$(GXX) -o $@ $(CXX_FLAGS) $(filter-out %.hpp, $^) $(LD_FLAGS)
