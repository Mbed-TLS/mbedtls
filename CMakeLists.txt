cmake_minimum_required(VERSION 2.6)
project(POLARSSL C)

enable_testing()

string(REGEX MATCH "clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_C_COMPILER}")

if(CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -W -Wdeclaration-after-statement")
  set(CMAKE_C_FLAGS_RELEASE "-O2")
  set(CMAKE_C_FLAGS_DEBUG "-g3 -O0")
  set(CMAKE_C_FLAGS_COVERAGE "-g3 -O0 --coverage")
  set(CMAKE_C_FLAGS_ASAN "-fsanitize=address -fno-omit-frame-pointer -g3 -O1")
  set(CMAKE_C_FLAGS_CHECK "${CMAKE_C_FLAGS} -Werror -O1 -Wlogical-op -Wwrite-strings")
  set(CMAKE_C_FLAGS_CHECKFULL "${CMAKE_C_FLAGS_CHECK} -Wcast-qual")
endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_COMPILER_IS_CLANG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -W -Wdeclaration-after-statement")
  set(CMAKE_C_FLAGS_RELEASE "-O2")
  set(CMAKE_C_FLAGS_DEBUG "-g3 -O0")
  set(CMAKE_C_FLAGS_COVERAGE "-g3 -O0 --coverage")
  set(CMAKE_C_FLAGS_ASAN "-fsanitize=address -fno-omit-frame-pointer -g3 -O1")
  set(CMAKE_C_FLAGS_CHECK "${CMAKE_C_FLAGS} -Werror -O1 -Wpointer-arith -Wwrite-strings -Wdocumentation -Wunreachable-code")
endif(CMAKE_COMPILER_IS_CLANG)

set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
    CACHE STRING "Choose the type of build: None Debug Release Coverage ASan Check CheckFull"
    FORCE)

if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
  if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_SHARED_LINKER_FLAGS "--coverage")
  endif(CMAKE_COMPILER_IS_GNUCC)
  if(CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_SHARED_LINKER_FLAGS "--coverage")
  endif(CMAKE_COMPILER_IS_CLANG)
endif(CMAKE_BUILD_TYPE STREQUAL "Coverage")

option(USE_PKCS11_HELPER_LIBRARY "Build PolarSSL with the pkcs11-helper library." OFF)

option(ENABLE_ZLIB_SUPPORT "Build PolarSSL with zlib library." OFF)
option(ENABLE_PROGRAMS "Build PolarSSL programs." ON)

if(LIB_INSTALL_DIR)
else()
set(LIB_INSTALL_DIR lib)
endif()

include_directories(include/)

if(ENABLE_ZLIB_SUPPORT)
  find_package(ZLIB)

  if(ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIR})
  endif(ZLIB_FOUND)
endif(ENABLE_ZLIB_SUPPORT)

add_subdirectory(library)
add_subdirectory(include)

if(CMAKE_COMPILER_IS_GNUCC)
  add_subdirectory(tests)
endif(CMAKE_COMPILER_IS_GNUCC)
if(CMAKE_COMPILER_IS_CLANG)
  add_subdirectory(tests)
endif(CMAKE_COMPILER_IS_CLANG)

if(ENABLE_PROGRAMS)
  add_subdirectory(programs)
endif()

ADD_CUSTOM_TARGET(apidoc
                  COMMAND doxygen doxygen/polarssl.doxyfile
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

ADD_CUSTOM_TARGET(test-ref-config
    COMMAND tests/scripts/test-ref-configs.pl
    )

# add programs/test/selftest even though the selftest functions are
# called from the testsuites since it runs them in verbose mode,
# avoiding spurious "uncovered" printf lines
ADD_CUSTOM_TARGET(covtest
    COMMAND make test
    COMMAND programs/test/selftest
    COMMAND cd tests && ./compat.sh
    COMMAND cd tests && ./ssl-opt.sh
    )

ADD_CUSTOM_TARGET(lcov
    COMMAND rm -rf Coverage
    COMMAND lcov --capture --directory library/CMakeFiles/polarssl.dir -o polarssl.info
    COMMAND gendesc tests/Descriptions.txt -o descriptions
    COMMAND genhtml --title PolarSSL --description-file descriptions --keep-descriptions --legend --no-branch-coverage -o Coverage polarssl.info
    COMMAND rm -f polarssl.info descriptions
    )

ADD_CUSTOM_TARGET(memcheck
    COMMAND ctest -O memcheck.log -D ExperimentalMemCheck
    COMMAND tail -n1 memcheck.log | grep 'Memory checking results:' > /dev/null
    COMMAND rm -f memcheck.log
    )
