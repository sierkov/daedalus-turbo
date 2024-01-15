add_library(3rdparty OBJECT vrf03/convert.c vrf03/verify.c vrf03/ed25519_ref10.c)
target_include_directories(3rdparty PUBLIC .)
set_target_properties(3rdparty PROPERTIES LINKER_LANGUAGE C)