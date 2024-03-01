cmake_minimum_required(VERSION 3.20)
project(DT)
if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not allowed")
endif()
if(NOT CMAKE_BUILD_TYPE)
   set(CMAKE_BUILD_TYPE Release
       CACHE STRING "Choose the type of build: Release Debug Coverage Profile Valgrind."
       FORCE)
endif()
set(COVERAGE_ARGS "" CACHE STRING "select specific unit tests to run for test coverage evaluations")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS NO)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
endif()
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
if (MSVC)
    add_compile_options(/bigobj)
endif()
if (CMAKE_SYSTEM_NAME MATCHES "^MINGW")
    list(APPEND CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES /mingw64/include)
endif()

add_subdirectory(3rdparty)
add_subdirectory(lib)
target_link_libraries(lib PUBLIC 3rdparty)

add_executable(dt src/dt.cpp)
target_link_libraries(dt PUBLIC lib 3rdparty)

file(GLOB ITEST_SRCS test/*.cpp)
foreach(ITEST_SRC IN LISTS ITEST_SRCS)
    cmake_path(GET ITEST_SRC STEM ITEST)
    add_executable(${ITEST} ${ITEST_SRC})
    target_link_libraries(${ITEST} PUBLIC lib 3rdparty)
endforeach()

if (EXISTS ${CMAKE_SOURCE_DIR}/src/dt-debug.cpp)
    add_executable(dt-debug src/dt-debug.cpp)
    target_link_libraries(dt-debug PUBLIC lib 3rdparty)
endif()

file(GLOB_RECURSE TEST_SRCS lib/dt/*.test.cpp)
add_executable(run-test src/run-test.cpp ${TEST_SRCS})
target_link_libraries(run-test PUBLIC lib 3rdparty)

file(GLOB_RECURSE BENCH_SRCS lib/dt/*.bench.cpp)
add_executable(run-bench src/run-test.cpp ${BENCH_SRCS})
target_link_libraries(run-bench PUBLIC lib 3rdparty)

message("copying configs")
file(COPY etc DESTINATION .)
if (EXISTS ${CMAKE_SOURCE_DIR}/publisher)
    file(COPY publisher DESTINATION .)
endif()
message("copying test data")
file(COPY data DESTINATION .)

if (CMAKE_BUILD_TYPE STREQUAL Valgrind)
    target_compile_options(lib PRIVATE -g -O1)
    target_compile_options(dt PRIVATE -g -O1)
elseif (CMAKE_BUILD_TYPE STREQUAL Profile)
    target_compile_options(lib PRIVATE -pg -g -O1)
    target_compile_options(dt PRIVATE -pg -g -O1)
    target_link_options(dt PRIVATE -pg -g)
elseif (CMAKE_BUILD_TYPE STREQUAL Coverage)
    target_compile_options(lib PRIVATE -g --coverage)
    target_compile_options(run-test PRIVATE -g --coverage)
    target_link_options(run-test PRIVATE -g --coverage)
    add_custom_command(TARGET run-test PRE_BUILD COMMAND
            find ${CMAKE_BINARY_DIR} -type f -name '*.gcda' -exec rm {} +)
    find_program(GCOVR_PATH gcovr)
    if (GCOVR_PATH)
        message("adding target coverage using ${GCOVR_PATH}")
        add_custom_target(coverage
            COMMENT "Running test coverage ..."
            COMMAND $<TARGET_FILE:run-test> ${COVERAGE_ARGS}
            COMMAND mkdir -p coverage
            COMMAND ${GCOVR_PATH} -j -r ${CMAKE_SOURCE_DIR} --gcov-ignore-parse-errors=negative_hits.warn --merge-mode-functions=separate --html-details coverage/coverage.html
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
    endif()
endif()