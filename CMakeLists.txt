cmake_minimum_required(VERSION 2.6)
project(POLARSSL C)

enable_testing()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wall -W -fprofile-arcs -ftest-coverage -lgcov")
set(CMAKE_SHARED_LINKER_FLAGS "-fprofile-arcs -ftest-coverage")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wall -W")
#set(CMAKE_SHARED_LINKER_FLAGS "")

include_directories(include/)

add_subdirectory(library)
add_subdirectory(programs)
add_subdirectory(tests)
