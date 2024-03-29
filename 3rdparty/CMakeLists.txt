add_library(libcppbor OBJECT libcppbor/src/cppbor.cpp)
target_include_directories(libcppbor PUBLIC libcppbor/include)
set_target_properties(libcppbor PROPERTIES LINKER_LANGUAGE CXX)

add_library(3rdparty OBJECT vrf03/convert.c vrf03/verify.c vrf03/ed25519_ref10.c)
target_include_directories(3rdparty PUBLIC .)
target_link_libraries(3rdparty PUBLIC libcppbor)
set_target_properties(3rdparty PROPERTIES LINKER_LANGUAGE C)