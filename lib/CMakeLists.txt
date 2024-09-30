set(Boost_NO_WARN_NEW_VERSIONS 1)
find_package(Boost 1.83 REQUIRED COMPONENTS json url coroutine)
find_package(PkgConfig REQUIRED)
pkg_check_modules(FMT REQUIRED fmt>=8.1.1)
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.18)
pkg_check_modules(SPDLOG REQUIRED spdlog>=1.9.2)
pkg_check_modules(ZSTD REQUIRED libzstd>=1.4.8)
find_library(SECP256K1_LIBRARY_PATH secp256k1)
file(GLOB_RECURSE LIB_SRCS dt/*.cpp)
list(FILTER LIB_SRCS EXCLUDE REGEX "\\.test\\.cpp$")
list(FILTER LIB_SRCS EXCLUDE REGEX "\\.bench\\.cpp$")
list(FILTER LIB_SRCS EXCLUDE REGEX "\\.fuzz\\.cpp$")
add_library(lib OBJECT ${LIB_SRCS})
target_include_directories(lib PUBLIC .)
target_link_libraries(lib PUBLIC Boost::json Boost::coroutine Boost::url
        ${Boost_LIBRARIES}
        ${FMT_LIBRARIES}
        ${SECP256K1_LIBRARY_PATH}
        ${SPDLOG_LIBRARIES}
        ${ZSTD_LIBRARIES}
)
if (MSVC)
    find_library(SECP256K1_PRE_LIBRARY_PATH secp256k1_precomputed)
    target_link_libraries(lib PUBLIC libsodium.lib)
    target_link_libraries(lib PUBLIC ${SECP256K1_PRE_LIBRARY_PATH})
else()
    target_link_libraries(lib PUBLIC ${SODIUM_LIBRARIES})
endif()
target_link_directories(lib PUBLIC
    ${Boost_LIBRARY_DIRS}
    ${FMT_LIBRARY_DIRS}
    ${SECP256K1_LIBRARY_DIRS}
    ${SODIUM_LIBRARY_DIRS}
    ${SPDLOG_LIBRARY_DIRS}
    ${ZSTD_LIBRARY_DIRS}
)
if (WIN32)
    target_compile_options(lib PUBLIC -DDT_USE_MIMALLOC=1 -DNOMINMAX=1)
    pkg_check_modules(MIMALLOC REQUIRED mimalloc>=2.0.5)
    target_link_libraries(lib PUBLIC ${MIMALLOC_LIBRARIES})
    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_link_libraries(lib PUBLIC atomic)
    endif()
    target_link_directories(lib PUBLIC ${MIMALLOC_LIBRARY_DIRS})
endif()
set_target_properties(lib PROPERTIES LINKER_LANGUAGE CXX)
if (MINGW)
    target_link_libraries(lib PUBLIC "ws2_32")
    target_link_libraries(lib PUBLIC "wsock32")
endif()