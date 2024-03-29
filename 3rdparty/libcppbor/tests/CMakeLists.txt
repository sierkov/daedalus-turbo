add_executable(cppbor_test
    ${CMAKE_SOURCE_DIR}/src/cppbor.cpp
    ${CMAKE_SOURCE_DIR}/src/cppbor_parse.cpp
    cppbor_test.cpp
)

target_link_libraries(cppbor_test
    GTest::gtest_main
    GTest::gmock_main
    OpenSSL::SSL
)

include(GoogleTest)
gtest_discover_tests(cppbor_test)
