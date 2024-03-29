cmake_minimum_required(VERSION 3.23)

# set the project name, language,  and version
project(cppbor 
    DESCRIPTION "LibCppBor: A Modern C++ CBOR Parser and Generator."
    VERSION 1.0.0
    LANGUAGES CXX
)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

################################################################################
# Additional packages
################################################################################

find_package(OpenSSL REQUIRED)

################################################################################
# Include directories
################################################################################

# Make cache variables for install destinations
include(GNUInstallDirs)

include_directories(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
# Note: We need to tell CMake that we want to use different include directories
#       depending on if we're building the library or using it from an installed
#       location.

################################################################################
# Target Build and Link
################################################################################

# Specify the Viper-Ed25519 source files (including submodules)
set(LIBCPPBOR_SOURCES
    ${CMAKE_SOURCE_DIR}/src/cppbor.cpp
    ${CMAKE_SOURCE_DIR}/src/cppbor_parse.cpp
)

# Add the library to build but do not specify STATIC vs. SHARED. A shared 
# library will be built if CMake is run with: -DBUILD_SHARED_LIBS=ON
add_library(${PROJECT_NAME} ${LIBCPPBOR_SOURCES})

# Specify libraries for linking
target_link_libraries(${PROJECT_NAME} PRIVATE
    OpenSSL::SSL
)

################################################################################
# Testing
################################################################################

# Enable testing globally. Individual tests may be found in the `tests`
# subdirectory of the repository.

# Explicitly opt in to modern CMake behaviors to avoid warnings with recent 
# versions of CMake. 
cmake_policy(SET CMP0135 NEW)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()
add_subdirectory(tests) 
