add_library(3rdparty OBJECT vrf03/convert.c vrf03/verify.c vrf03/keypair.c vrf03/prove.c vrf03/ed25519_ref10.c)
target_include_directories(3rdparty PUBLIC .)
set_target_properties(3rdparty PROPERTIES LINKER_LANGUAGE C)

add_library(3rdparty-cpp OBJECT hash-library/sha3.cpp hash-library/crc32.cpp)
target_include_directories(3rdparty-cpp PUBLIC .)
set_target_properties(3rdparty-cpp PROPERTIES LINKER_LANGUAGE CXX)
