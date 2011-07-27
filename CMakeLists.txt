cmake_minimum_required(VERSION 2.6)
project(POLARSSL C)

enable_testing()

if(CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -W -Wdeclaration-after-statement")
  set(CMAKE_C_FLAGS_DEBUG "-g -O0")
  set(CMAKE_C_FLAGS_COVERAGE "-g -O0 -fprofile-arcs -ftest-coverage -lgcov")
endif(CMAKE_COMPILER_IS_GNUCC)
 
if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
  if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_SHARED_LINKER_FLAGS "-fprofile-arcs -ftest-coverage")
  endif(CMAKE_COMPILER_IS_GNUCC)
endif(CMAKE_BUILD_TYPE STREQUAL "Coverage")

option(USE_PKCS11_HELPER_LIBRARY "Build PolarSSL with the pkcs11-helper library." OFF)

if(LIB_INSTALL_DIR)
else()
set(LIB_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/lib)
endif()

include_directories(include/)

add_subdirectory(library)
add_subdirectory(include)

if(CMAKE_COMPILER_IS_GNUCC)
  add_subdirectory(tests)
endif(CMAKE_COMPILER_IS_GNUCC)

add_subdirectory(programs)

ADD_CUSTOM_TARGET(apidoc
                  COMMAND doxygen doxygen/polarssl.doxyfile
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
