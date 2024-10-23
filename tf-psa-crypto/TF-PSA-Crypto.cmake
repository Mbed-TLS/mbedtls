include(GNUInstallDirs)

# Determine if TF-PSA-Crypto is being built as a subproject using add_subdirectory()
if(NOT DEFINED TF_PSA_CRYPTO_AS_SUBPROJECT)
  set(TF_PSA_CRYPTO_AS_SUBPROJECT ON)
  if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(TF_PSA_CRYPTO_AS_SUBPROJECT OFF)
  endif()
endif()

# Set the project, Mbed TLS and framework root directory.
set(TF_PSA_CRYPTO_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(MBEDTLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(MBEDTLS_FRAMEWORK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../framework)

option(ENABLE_PROGRAMS "Build TF-PSA-Crypto programs." ON)

option(TF_PSA_CRYPTO_FATAL_WARNINGS "Compiler warnings treated as errors" ON)
if(CMAKE_HOST_WIN32)
    # N.B. The comment on the next line is significant! If you change it,
    # edit the sed command in prepare_release.sh that modifies
    # CMakeLists.txt.
    option(GEN_FILES "Generate the auto-generated files as needed" OFF) # off in development
else()
    option(GEN_FILES "Generate the auto-generated files as needed" ON)
endif()

# Support for package config and install to be added later.
option(DISABLE_PACKAGE_CONFIG_AND_INSTALL "Disable package configuration, target export and installation" ON)

if (CMAKE_C_SIMULATE_ID)
    set(COMPILER_ID ${CMAKE_C_SIMULATE_ID})
else()
    set(COMPILER_ID ${CMAKE_C_COMPILER_ID})
endif(CMAKE_C_SIMULATE_ID)

string(REGEX MATCH "Clang" CMAKE_COMPILER_IS_CLANG "${COMPILER_ID}")
string(REGEX MATCH "GNU" CMAKE_COMPILER_IS_GNU "${COMPILER_ID}")
string(REGEX MATCH "IAR" CMAKE_COMPILER_IS_IAR "${COMPILER_ID}")
string(REGEX MATCH "MSVC" CMAKE_COMPILER_IS_MSVC "${COMPILER_ID}")

# the test suites currently have compile errors with MSVC
if(CMAKE_COMPILER_IS_MSVC)
    option(ENABLE_TESTING "Build TF-PSA-Crypto tests." OFF)
else()
    option(ENABLE_TESTING "Build TF-PSA-Crypto tests." ON)
endif()

option(USE_STATIC_TF_PSA_CRYPTO_LIBRARY "Build TF-PSA-Crypto static library." ON)
option(USE_SHARED_TF_PSA_CRYPTO_LIBRARY "Build TF-PSA-Crypto shared library." OFF)
option(LINK_WITH_PTHREAD "Explicitly link Mbed TLS library to pthread." OFF)
option(LINK_WITH_TRUSTED_STORAGE "Explicitly link Mbed TLS library to trusted_storage." OFF)

set(mbedcrypto_target "${TF_PSA_CRYPTO_TARGET_PREFIX}mbedcrypto")
if (USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
    set(mbedcrypto_static_target ${mbedcrypto_target})
endif()
if(USE_STATIC_TF_PSA_CRYPTO_LIBRARY AND USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    string(APPEND mbedcrypto_static_target "_static")
endif()

# Warning string - created as a list for compatibility with CMake 2.8
set(CTR_DRBG_128_BIT_KEY_WARN_L1 "****  WARNING!  MBEDTLS_CTR_DRBG_USE_128_BIT_KEY defined!\n")
set(CTR_DRBG_128_BIT_KEY_WARN_L2 "****  Using 128-bit keys for CTR_DRBG limits the security of generated\n")
set(CTR_DRBG_128_BIT_KEY_WARN_L3 "****  keys and operations that use random values generated to 128-bit security\n")

set(CTR_DRBG_128_BIT_KEY_WARNING "${WARNING_BORDER}"
                         "${CTR_DRBG_128_BIT_KEY_WARN_L1}"
                         "${CTR_DRBG_128_BIT_KEY_WARN_L2}"
                         "${CTR_DRBG_128_BIT_KEY_WARN_L3}"
                         "${WARNING_BORDER}")

# Python 3 is only needed here to check for configuration warnings.
if(NOT CMAKE_VERSION VERSION_LESS 3.15.0)
    set(Python3_FIND_STRATEGY LOCATION)
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        set(TF_PSA_CRYPTO_PYTHON_EXECUTABLE ${Python3_EXECUTABLE})
    endif()
else()
    find_package(PythonInterp 3)
    if(PYTHONINTERP_FOUND)
        set(TF_PSA_CRYPTO_PYTHON_EXECUTABLE ${PYTHON_EXECUTABLE})
    endif()
endif()
if(TF_PSA_CRYPTO_PYTHON_EXECUTABLE)

    # If 128-bit keys are configured for CTR_DRBG, display an appropriate warning
    execute_process(COMMAND ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE} ${MBEDTLS_DIR}/scripts/config.py -f ${MBEDTLS_DIR}/include/mbedtls/mbedtls_config.h get MBEDTLS_CTR_DRBG_USE_128_BIT_KEY
                        RESULT_VARIABLE result)
    if(${result} EQUAL 0)
        message(WARNING ${CTR_DRBG_128_BIT_KEY_WARNING})
    endif()

endif()

# We now potentially need to link all executables against PThreads, if available
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads)

# If this is the root project add longer list of available CMAKE_BUILD_TYPE values
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
        CACHE STRING "Choose the type of build: None Debug Release Coverage ASan ASanDbg MemSan MemSanDbg Check CheckFull TSan TSanDbg"
        FORCE)
endif()

# Make TF_PSA_CRYPTO_CONFIG_FILE and TF_PSA_CRYPTO_USER_CONFIG_FILE into PATHs
set(TF_PSA_CRYPTO_CONFIG_FILE "" CACHE FILEPATH "TF-PSA-Crypto config file (overrides default).")
set(TF_PSA_CRYPTO_USER_CONFIG_FILE "" CACHE FILEPATH "TF-PSA-Crypto user config file (appended to default).")

# Create a symbolic link from ${base_name} in the binary directory
# to the corresponding path in the source directory.
# Note: Copies the file(s) on Windows.
function(link_to_source base_name)
    set(link "${CMAKE_CURRENT_BINARY_DIR}/${base_name}")
    set(target "${CMAKE_CURRENT_SOURCE_DIR}/${base_name}")

    # Linking to non-existent file is not desirable. At best you will have a
    # dangling link, but when building in tree, this can create a symbolic link
    # to itself.
    if (EXISTS ${target} AND NOT EXISTS ${link})
        if (CMAKE_HOST_UNIX)
            execute_process(COMMAND ln -s ${target} ${link}
                RESULT_VARIABLE result
                ERROR_VARIABLE output)

            if (NOT ${result} EQUAL 0)
                message(FATAL_ERROR "Could not create symbolic link for: ${target} --> ${output}")
            endif()
        else()
            if (IS_DIRECTORY ${target})
                file(GLOB_RECURSE files FOLLOW_SYMLINKS LIST_DIRECTORIES false RELATIVE ${target} "${target}/*")
                foreach(file IN LISTS files)
                    configure_file("${target}/${file}" "${link}/${file}" COPYONLY)
                endforeach(file)
            else()
                configure_file(${target} ${link} COPYONLY)
            endif()
        endif()
    endif()
endfunction(link_to_source)

# Get the filename without the final extension (i.e. convert "a.b.c" to "a.b")
function(get_name_without_last_ext dest_var full_name)
    # Split into a list on '.' (but a cmake list is just a ';'-separated string)
    string(REPLACE "." ";" ext_parts "${full_name}")
    # Remove the last item if there are more than one
    list(LENGTH ext_parts ext_parts_len)
    if (${ext_parts_len} GREATER "1")
        math(EXPR ext_parts_last_item "${ext_parts_len} - 1")
        list(REMOVE_AT ext_parts ${ext_parts_last_item})
    endif()
    # Convert back to a string by replacing separators with '.'
    string(REPLACE ";" "." no_ext_name "${ext_parts}")
    # Copy into the desired variable
    set(${dest_var} ${no_ext_name} PARENT_SCOPE)
endfunction(get_name_without_last_ext)

include(CheckCCompilerFlag)

set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

function(set_base_compile_options target)
    if(CMAKE_COMPILER_IS_GNU)
        set_gnu_base_compile_options(${target})
    elseif(CMAKE_COMPILER_IS_CLANG)
        set_clang_base_compile_options(${target})
    elseif(CMAKE_COMPILER_IS_IAR)
        set_iar_base_compile_options(${target})
    elseif(CMAKE_COMPILER_IS_MSVC)
        set_msvc_base_compile_options(${target})
    endif()
endfunction(set_base_compile_options)

function(set_gnu_base_compile_options target)
    # some warnings we want are not available with old GCC versions
    # note: starting with CMake 2.8 we could use CMAKE_C_COMPILER_VERSION
    execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion
                    OUTPUT_VARIABLE GCC_VERSION)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wwrite-strings -Wmissing-prototypes)
    if (GCC_VERSION VERSION_GREATER 3.0 OR GCC_VERSION VERSION_EQUAL 3.0)
        target_compile_options(${target} PRIVATE -Wformat=2 -Wno-format-nonliteral)
    endif()
    if (GCC_VERSION VERSION_GREATER 4.3 OR GCC_VERSION VERSION_EQUAL 4.3)
        target_compile_options(${target} PRIVATE -Wvla)
    endif()
    if (GCC_VERSION VERSION_GREATER 4.5 OR GCC_VERSION VERSION_EQUAL 4.5)
        target_compile_options(${target} PRIVATE -Wlogical-op)
    endif()
    if (GCC_VERSION VERSION_GREATER 4.8 OR GCC_VERSION VERSION_EQUAL 4.8)
        target_compile_options(${target} PRIVATE -Wshadow)
    endif()
    if (GCC_VERSION VERSION_GREATER 5.0)
        CHECK_C_COMPILER_FLAG("-Wformat-signedness" C_COMPILER_SUPPORTS_WFORMAT_SIGNEDNESS)
        if(C_COMPILER_SUPPORTS_WFORMAT_SIGNEDNESS)
            target_compile_options(${target} PRIVATE -Wformat-signedness)
        endif()
    endif()
    if (GCC_VERSION VERSION_GREATER 7.0 OR GCC_VERSION VERSION_EQUAL 7.0)
      target_compile_options(${target} PRIVATE -Wformat-overflow=2 -Wformat-truncation)
    endif()
    target_compile_options(${target} PRIVATE $<$<CONFIG:Release>:-O2>)
    target_compile_options(${target} PRIVATE $<$<CONFIG:Debug>:-O0 -g3>)
    target_compile_options(${target} PRIVATE $<$<CONFIG:Coverage>:-O0 -g3 --coverage>)
    set_target_properties(${target} PROPERTIES LINK_FLAGS_COVERAGE "--coverage")
    # Old GCC versions hit a performance problem with test_suite_pkwrite
    # "Private keey write check EC" tests when building with Asan+UBSan
    # and -O3: those tests take more than 100x time than normal, with
    # test_suite_pkwrite taking >3h on the CI. Observed with GCC 5.4 on
    # Ubuntu 16.04 x86_64 and GCC 6.5 on Ubuntu 18.04 x86_64.
    # GCC 7.5 and above on Ubuntu 18.04 appear fine.
    # To avoid the performance problem, we use -O2 here. It doesn't slow
    # down much even with modern compiler versions.
    target_compile_options(${target} PRIVATE $<$<CONFIG:ASan>:-fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover=all -O2>)
    set_target_properties(${target} PROPERTIES LINK_FLAGS_ASAN "-fsanitize=address -fsanitize=undefined")
    target_compile_options(${target} PRIVATE $<$<CONFIG:ASanDbg>:-fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover=all -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls>)
    set_target_properties(${target} PROPERTIES LINK_FLAGS_ASANDBG "-fsanitize=address -fsanitize=undefined")
    target_compile_options(${target} PRIVATE $<$<CONFIG:TSan>:-fsanitize=thread -O3>)
    set_target_properties(${target} PROPERTIES LINK_FLAGS_TSAN "-fsanitize=thread")
    target_compile_options(${target} PRIVATE $<$<CONFIG:TSanDbg>:-fsanitize=thread -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls>)
    set_target_properties(${target} PROPERTIES LINK_FLAGS_TSANDBG "-fsanitize=thread")
    target_compile_options(${target} PRIVATE $<$<CONFIG:Check>:-Os>)
    target_compile_options(${target} PRIVATE $<$<CONFIG:CheckFull>:-Os -Wcast-qual>)

    if(TF_PSA_CRYPTO_FATAL_WARNINGS)
        target_compile_options(${target} PRIVATE -Werror)
    endif(TF_PSA_CRYPTO_FATAL_WARNINGS)
endfunction(set_gnu_base_compile_options)

function(set_clang_base_compile_options target)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wwrite-strings -Wmissing-prototypes -Wpointer-arith -Wimplicit-fallthrough -Wshadow -Wvla -Wformat=2 -Wno-format-nonliteral)
    target_compile_options(${target} PRIVATE $<$<CONFIG:Release>:-O2>)
    target_compile_options(${target} PRIVATE $<$<CONFIG:Debug>:-O0 -g3>)
    target_compile_options(${target} PRIVATE $<$<CONFIG:Coverage>:-O0 -g3 --coverage>)
    set_target_properties(${target} PROPERTIES LINK_FLAGS_COVERAGE "--coverage")
    target_compile_options(${target} PRIVATE $<$<CONFIG:ASan>:-fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover=all -O3>)
    set_target_properties(${target} PROPERTIES LINK_FLAGS_ASAN "-fsanitize=address -fsanitize=undefined")
    target_compile_options(${target} PRIVATE $<$<CONFIG:ASanDbg>:-fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover=all -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls>)
    set_target_properties(${target} PROPERTIES LINK_FLAGS_ASANDBG "-fsanitize=address -fsanitize=undefined")
    target_compile_options(${target} PRIVATE $<$<CONFIG:MemSan>:-fsanitize=memory>)
    set_target_properties(${target} PROPERTIES LINK_FLAGS_MEMSAN "-fsanitize=memory")
    target_compile_options(${target} PRIVATE $<$<CONFIG:MemSanDbg>:-fsanitize=memory -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2>)
    set_target_properties(${target} PROPERTIES LINK_FLAGS_MEMSANDBG "-fsanitize=memory")
    target_compile_options(${target} PRIVATE $<$<CONFIG:TSan>:-fsanitize=thread -O3>)
    set_target_properties(${target} PROPERTIES LINK_FLAGS_TSAN "-fsanitize=thread")
    target_compile_options(${target} PRIVATE $<$<CONFIG:TSanDbg>:-fsanitize=thread -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls>)
    set_target_properties(${target} PROPERTIES LINK_FLAGS_TSANDBG "-fsanitize=thread")
    target_compile_options(${target} PRIVATE $<$<CONFIG:Check>:-Os>)

    if(MBEDTLS_FATAL_WARNINGS)
        target_compile_options(${target} PRIVATE -Werror)
    endif(MBEDTLS_FATAL_WARNINGS)
endfunction(set_clang_base_compile_options)

function(set_iar_base_compile_options target)
    target_compile_options(${target} PRIVATE --warn_about_c_style_casts)
    target_compile_options(${target} PRIVATE $<$<CONFIG:Release>:-Ohz>)
    target_compile_options(${target} PRIVATE $<$<CONFIG:Debug>:--debug -On>)

    if(MBEDTLS_FATAL_WARNINGS)
        target_compile_options(${target} PRIVATE --warnings_are_errors)
    endif(MBEDTLS_FATAL_WARNINGS)
endfunction(set_iar_base_compile_options)

function(set_msvc_base_compile_options target)
    # Strictest warnings, UTF-8 source and execution charset
    target_compile_options(${target} PRIVATE /W3 /utf-8)

    if(MBEDTLS_FATAL_WARNINGS)
        target_compile_options(${target} PRIVATE /WX)
    endif(MBEDTLS_FATAL_WARNINGS)
endfunction(set_msvc_base_compile_options)

if(CMAKE_BUILD_TYPE STREQUAL "Check" AND TEST_CPP)
    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
    if(CMAKE_COMPILER_IS_CLANG OR CMAKE_COMPILER_IS_GNU)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic")
    endif()
endif()

if(LIB_INSTALL_DIR)
    set(CMAKE_INSTALL_LIBDIR "${LIB_INSTALL_DIR}")
endif()

if (NOT EXISTS "${MBEDTLS_FRAMEWORK_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "${MBEDTLS_FRAMEWORK_DIR}/CMakeLists.txt not found. Run `git submodule update --init` from the source tree to fetch the submodule contents.")
endif()

add_subdirectory(include)
add_subdirectory(core)
add_subdirectory(drivers)

#
# The C files in tests/src directory contain test code shared among test suites
# and programs. This shared test code is compiled and linked to test suites and
# programs objects as a set of compiled objects. The compiled objects are NOT
# built into a library that the test suite and program objects would link
# against as they link against the tfpsacrypto library. The reason is that such
# library is expected to have mutual dependencies with the aforementioned
# library and that there is as of today no portable way of handling such
# dependencies (only toolchain specific solutions).
#
# Thus the below definition of the `mbedtls_test` CMake library of objects
# target. This library of objects is used by tests and programs CMake files
# to define the test executables.
#
if(ENABLE_TESTING OR ENABLE_PROGRAMS)
    file(GLOB MBEDTLS_TEST_FILES
         ${MBEDTLS_DIR}/tests/src/*.c
         ${MBEDTLS_DIR}/tests/src/drivers/*.c)
    add_library(mbedtls_test OBJECT ${MBEDTLS_TEST_FILES})
    set_base_compile_options(mbedtls_test)
    if(GEN_FILES)
        add_custom_command(
            OUTPUT
                ${MBEDTLS_DIR}/tests/src/test_keys.h
            WORKING_DIRECTORY
                ${MBEDTLS_DIR}/tests
            COMMAND
                "${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}"
                "${MBEDTLS_FRAMEWORK_DIR}/scripts/generate_test_keys.py"
                "--output"
                "${MBEDTLS_DIR}/tests/src/test_keys.h"
            DEPENDS
                ${MBEDTLS_FRAMEWORK_DIR}/scripts/generate_test_keys.py
        )
        add_custom_target(test_keys_header DEPENDS ${MBEDTLS_DIR}/tests/src/test_keys.h)

        add_custom_command(
            OUTPUT
                ${MBEDTLS_DIR}/tests/src/test_certs.h
            WORKING_DIRECTORY
                ${MBEDTLS_DIR}/tests
            COMMAND
                "${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}"
                "${MBEDTLS_FRAMEWORK_DIR}/scripts/generate_test_cert_macros.py"
                "--output"
                "${MBEDTLS_DIR}/tests/src/test_certs.h"
            DEPENDS
                ${MBEDTLS_FRAMEWORK_DIR}/scripts/generate_test_cert_macros.py
        )
        add_custom_target(test_certs_header DEPENDS ${MBEDTLS_DIR}/tests/src/test_certs.h)
        add_dependencies(mbedtls_test test_keys_header test_certs_header)
    endif()
    target_include_directories(mbedtls_test
        PRIVATE ${MBEDTLS_DIR}/tests/include
        PRIVATE ${MBEDTLS_DIR}/include
        PRIVATE include
        PRIVATE drivers/builtin/include
        PRIVATE core
        PRIVATE drivers/builtin/src)
    # Request C11, needed for memory poisoning tests
    set_target_properties(mbedtls_test PROPERTIES C_STANDARD 11)

    # Pass-through TF_PSA_CRYPTO_CONFIG_FILE and TF_PSA_CRYPTO_USER_CONFIG_FILE
    if(TF_PSA_CRYPTO_CONFIG_FILE)
        target_compile_definitions(mbedtls_test
            PUBLIC TF_PSA_CRYPTO_CONFIG_FILE="${TF_PSA_CRYPTO_CONFIG_FILE}")
    endif()
    if(TF_PSA_CRYPTO_USER_CONFIG_FILE)
        target_compile_definitions(mbedtls_test
            PUBLIC TF_PSA_CRYPTO_USER_CONFIG_FILE="${TF_PSA_CRYPTO_USER_CONFIG_FILE}")
    endif()
endif()

if(ENABLE_PROGRAMS)
    add_subdirectory(programs)
endif()

if(ENABLE_TESTING)
    enable_testing()

    add_subdirectory(tests)

    # additional convenience targets for Unix only
    if(UNIX)
        ADD_CUSTOM_TARGET(memcheck
            COMMAND sed -i.bak s+/usr/bin/valgrind+`which valgrind`+ DartConfiguration.tcl
            COMMAND ctest -O memcheck.log -D ExperimentalMemCheck
            COMMAND tail -n1 memcheck.log | grep 'Memory checking results:' > /dev/null
            COMMAND rm -f memcheck.log
            COMMAND mv DartConfiguration.tcl.bak DartConfiguration.tcl
        )
    endif(UNIX)

    # Make scripts needed for testing available in an out-of-source build.
    if (NOT ${CMAKE_CURRENT_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
        link_to_source(scripts)
        # Copy (don't link) DartConfiguration.tcl, needed for memcheck, to
        # keep things simple with the sed commands in the memcheck target.
        configure_file(${CMAKE_CURRENT_SOURCE_DIR}/DartConfiguration.tcl
                    ${CMAKE_CURRENT_BINARY_DIR}/DartConfiguration.tcl COPYONLY)
    endif()
endif()
