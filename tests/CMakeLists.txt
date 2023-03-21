set(libs
    ${mbedtls_target}
)

# Set the project root directory if it's not already defined, as may happen if
# the tests folder is included directly by a parent project, without including
# the top level CMakeLists.txt.
if(NOT DEFINED MBEDTLS_DIR)
    set(MBEDTLS_DIR ${CMAKE_SOURCE_DIR})
endif()

if(USE_PKCS11_HELPER_LIBRARY)
    set(libs ${libs} pkcs11-helper)
endif(USE_PKCS11_HELPER_LIBRARY)

if(ENABLE_ZLIB_SUPPORT)
    set(libs ${libs} ${ZLIB_LIBRARIES})
endif(ENABLE_ZLIB_SUPPORT)

if(NOT MBEDTLS_PYTHON_EXECUTABLE)
    message(FATAL_ERROR "Cannot build test suites without Python 3")
endif()

# Enable definition of various functions used throughout the testsuite
# (gethostname, strdup, fileno...) even when compiling with -std=c99. Harmless
# on non-POSIX platforms.
add_definitions("-D_POSIX_C_SOURCE=200809L")

# If SKIP_TEST_SUITES is not defined with -D, get it from the environment.
if((NOT DEFINED SKIP_TEST_SUITES) AND (DEFINED ENV{SKIP_TEST_SUITES}))
    set(SKIP_TEST_SUITES $ENV{SKIP_TEST_SUITES})
endif()
# Test suites caught by SKIP_TEST_SUITES are built but not executed.
# "foo" as a skip pattern skips "test_suite_foo" and "test_suite_foo.bar"
# but not "test_suite_foobar".
string(REGEX REPLACE "[ ,;]" "|" SKIP_TEST_SUITES_REGEX "${SKIP_TEST_SUITES}")
string(REPLACE "." "\\." SKIP_TEST_SUITES_REGEX "${SKIP_TEST_SUITES_REGEX}")
set(SKIP_TEST_SUITES_REGEX "^(${SKIP_TEST_SUITES_REGEX})(\$|\\.)")

function(add_test_suite suite_name)
    if(ARGV1)
        set(data_name ${ARGV1})
    else()
        set(data_name ${suite_name})
    endif()

    add_custom_command(
        OUTPUT test_suite_${data_name}.c
        COMMAND ${MBEDTLS_PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_test_code.py -f ${CMAKE_CURRENT_SOURCE_DIR}/suites/test_suite_${suite_name}.function -d ${CMAKE_CURRENT_SOURCE_DIR}/suites/test_suite_${data_name}.data -t ${CMAKE_CURRENT_SOURCE_DIR}/suites/main_test.function -p ${CMAKE_CURRENT_SOURCE_DIR}/suites/host_test.function -s ${CMAKE_CURRENT_SOURCE_DIR}/suites --helpers-file ${CMAKE_CURRENT_SOURCE_DIR}/suites/helpers.function -o .
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_test_code.py ${mbedtls_target} ${CMAKE_CURRENT_SOURCE_DIR}/suites/helpers.function ${CMAKE_CURRENT_SOURCE_DIR}/suites/main_test.function ${CMAKE_CURRENT_SOURCE_DIR}/suites/host_test.function ${CMAKE_CURRENT_SOURCE_DIR}/suites/test_suite_${suite_name}.function ${CMAKE_CURRENT_SOURCE_DIR}/suites/test_suite_${data_name}.data
    )

    add_executable(test_suite_${data_name} test_suite_${data_name}.c
                   $<TARGET_OBJECTS:mbedtls_test>
                   $<TARGET_OBJECTS:mbedtls_test_helpers>)
    target_link_libraries(test_suite_${data_name} ${libs})
    # Include test-specific header files from ./include and private header
    # files (used by some invasive tests) from ../library. Public header
    # files are automatically included because the library targets declare
    # them as PUBLIC.
    target_include_directories(test_suite_${data_name}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../library)

    if(${data_name} MATCHES ${SKIP_TEST_SUITES_REGEX})
        message(STATUS "The test suite ${data_name} will not be executed.")
    else()
        add_test(${data_name}-suite test_suite_${data_name} --verbose)
    endif()
endfunction(add_test_suite)

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function")
endif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG)

if(CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wdocumentation -Wno-documentation-deprecated-sync -Wunreachable-code")
endif(CMAKE_COMPILER_IS_CLANG)

if(MSVC)
    # If a warning level has been defined, suppress all warnings for test code
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W0")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /WX-")
endif(MSVC)

file(GLOB test_suites RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" suites/*.data)
list(SORT test_suites)
foreach(test_suite ${test_suites})
    get_filename_component(data_name ${test_suite} NAME)
    string(REGEX REPLACE "\\.data\$" "" data_name "${data_name}")
    string(REPLACE "test_suite_" "" data_name "${data_name}")
    string(REGEX MATCH "[^.]*" function_name "${data_name}")
    add_test_suite(${function_name} ${data_name})
endforeach(test_suite)

# Make scripts and data files needed for testing available in an
# out-of-source build.
if (NOT ${CMAKE_CURRENT_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/seedfile")
        link_to_source(seedfile)
    endif()
    link_to_source(Descriptions.txt)
    link_to_source(compat.sh)
    link_to_source(context-info.sh)
    link_to_source(data_files)
    link_to_source(scripts)
    link_to_source(ssl-opt.sh)
    link_to_source(suites)
endif()
