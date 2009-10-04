cmake_minimum_required(VERSION 2.6)
project(POLARSSL C)

enable_testing()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -W -Wdeclaration-after-statement")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")
set(CMAKE_C_FLAGS_COVERAGE "-g -O0 -fprofile-arcs -ftest-coverage -lgcov")

if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
set(CMAKE_SHARED_LINKER_FLAGS "-fprofile-arcs -ftest-coverage")
endif(CMAKE_BUILD_TYPE STREQUAL "Coverage")

include_directories(include/)

add_subdirectory(library)
add_subdirectory(tests)
add_subdirectory(programs)
