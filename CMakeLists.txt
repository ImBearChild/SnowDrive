cmake_minimum_required(VERSION 3.18)
project(snowdrive C CXX)

set(CMAKE_C_STANDARD 11)

enable_testing()

# Libraries
add_subdirectory(lib/common)
add_subdirectory(lib/snow9660)
add_subdirectory(lib/snowscsi)

# CLI tools
add_subdirectory(src)

# Tests (optional)
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()
