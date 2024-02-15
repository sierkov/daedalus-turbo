find_package(Boost 1.83 REQUIRED COMPONENTS json url coroutine)
find_package(PkgConfig REQUIRED)
pkg_check_modules(FMT REQUIRED fmt>=8.1.1)
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.18)
pkg_check_modules(SPDLOG REQUIRED spdlog>=1.9.2)
pkg_check_modules(ZSTD REQUIRED libzstd>=1.4.8)

file(GLOB_RECURSE LIB_SRCS dt/*.cpp)
list(FILTER LIB_SRCS EXCLUDE REGEX "\\.test\\.cpp$")
list(FILTER LIB_SRCS EXCLUDE REGEX "\\.bench\\.cpp$")
add_library(lib OBJECT ${LIB_SRCS})
target_include_directories(lib PUBLIC .)
target_link_libraries(lib PUBLIC
    Boost::json Boost::coroutine Boost::url
    ${Boost_LIBRARIES}
    ${FMT_LIBRARIES}
    ${SODIUM_LIBRARIES}
    ${SPDLOG_LIBRARIES}
    ${ZSTD_LIBRARIES}
)
target_link_directories(lib PUBLIC
    ${Boost_LIBRARY_DIRS}
    ${FMT_LIBRARY_DIRS}
    ${SODIUM_LIBRARY_DIRS}
    ${SPDLOG_LIBRARY_DIRS}
    ${ZSTD_LIBRARY_DIRS}
)
set_target_properties(lib PROPERTIES LINKER_LANGUAGE CXX)