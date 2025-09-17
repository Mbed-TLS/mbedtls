# components-build-system.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Build System Testing
################################################################

component_test_make_shared () {
    msg "build/test: make shared" # ~ 40s
    make SHARED=1 TEST_CPP=1 all check
    ldd programs/util/strerror | grep libmbedcrypto
    $FRAMEWORK/tests/programs/dlopen_demo.sh
}

component_test_cmake_shared () {
    msg "build/test: cmake shared" # ~ 2min
    cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .
    make
    ldd programs/util/strerror | grep libmbedcrypto
    make test
    $FRAMEWORK/tests/programs/dlopen_demo.sh
}

component_build_make_no_gen_files () {
    msg "prepare for building in a minimal environment"

    # Ensure that the generated files are present (should be a no-op
    # since the all.sh infrastructure already does it).
    make generated_files

    # Arrange for the non-generated sources to be more recent than any
    # generated file. This allows us to detect if the makefile tries
    # to rebuild the generated files from their dependencies when it
    # shouldn't.
    # Wait 1 second so this test is effective even if the filesystem
    # only has a granularity of 1 second for timestamps.
    sleep 1
    git ls-files -z | xargs -0 touch --

    # The setup code of all.sh sets up a "quiet" wrapper for `make`.
    # We want to bypass it and just use the normal make program,
    # so that this test mimics a normal user's platform.
    # And anyway we need to bypass it because it wouldn't work without bash
    # and other tools in the $PATH.
    # The wrapper is used because the setup code adds the
    # `.../framework/scripts/quiet` directlry to the beginning of the $PATH.
    # So here we remove that.
    shopt -s extglob
    # Strip off all entries in $PATH that ends with `/quiet`. (This misses
    # the very last element, but we know we'll never need to remove the last
    # element, since we just want to remove the wrapper directory that comes
    # before the normal programs.)
    PATH=${PATH//*([!:])\/quiet:/}

    # Locate the minimum programs needed for the build: ${CC} and ${AR}.
    AR="$(command -v ar)"
    # GCC needs "as" in $PATH by default. To use GCC, we need to tell it where
    # to find the assembler. Or we can use clang which just works.
    CC="$(command -v clang)"
    # For cleaning.
    RM="$(command -v rm)"

    # Test the build with make.
    # Preferably we should also test with CMake. Note that a CMake test
    # would be harder to set up, because CMake will find e.g. /usr/bin/python
    # even if it isn't on $PATH.
    msg "build: make lib with GEN_FILES off in minimal environment"
    env PATH=/no/such/directory "$(command -v make)" GEN_FILES= AR="$AR" CC="$CC" lib

    msg "build: make -C library clean with GEN_FILES off in minimal environment"
    env PATH=/no/such/directory "$(command -v make)" GEN_FILES= RM="$RM" -C library clean

    msg "build: make lib with GEN_FILES off with generated files missing"
    make neat
    # Check that a sample generated file is absent
    not test -f library/error.c
    PERL="$(command -v perl)"
    PYTHON="$(command -v python3)"
    # We take whatever Python environment we're in. For a future improvement,
    # make a venv with just scripts/basic.requirements.txt.
    env PATH=/no/such/directory "$(command -v make)" GEN_FILES= AR="$AR" CC="$CC" PERL="$PERL" PYTHON="$PYTHON" lib
}

support_test_cmake_out_of_source () {
    distrib_id=""
    distrib_ver=""
    distrib_ver_minor=""
    distrib_ver_major=""

    # Attempt to parse lsb-release to find out distribution and version. If not
    # found this should fail safe (test is supported).
    if [[ -f /etc/lsb-release ]]; then

        while read -r lsb_line; do
            case "$lsb_line" in
                "DISTRIB_ID"*) distrib_id=${lsb_line/#DISTRIB_ID=};;
                "DISTRIB_RELEASE"*) distrib_ver=${lsb_line/#DISTRIB_RELEASE=};;
            esac
        done < /etc/lsb-release

        distrib_ver_major="${distrib_ver%%.*}"
        distrib_ver="${distrib_ver#*.}"
        distrib_ver_minor="${distrib_ver%%.*}"
    fi

    # Running the out of source CMake test on Ubuntu 16.04 using more than one
    # processor (as the CI does) can create a race condition whereby the build
    # fails to see a generated file, despite that file actually having been
    # generated. This problem appears to go away with 18.04 or newer, so make
    # the out of source tests unsupported on Ubuntu 16.04.
    [ "$distrib_id" != "Ubuntu" ] || [ "$distrib_ver_major" -gt 16 ]
}

component_test_cmake_out_of_source () {
    # Remove existing generated files so that we use the ones cmake
    # generates
    make neat

    msg "build: cmake 'out-of-source' build"
    MBEDTLS_ROOT_DIR="$PWD"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"
    # Note: Explicitly generate files as these are turned off in releases
    cmake -D CMAKE_BUILD_TYPE:String=Check -D GEN_FILES=ON -D TEST_CPP=1 "$MBEDTLS_ROOT_DIR"
    make

    msg "test: cmake 'out-of-source' build"
    make test
    # Check that ssl-opt.sh can find the test programs.
    # Also ensure that there are no error messages such as
    # "No such file or directory", which would indicate that some required
    # file is missing (ssl-opt.sh tolerates the absence of some files so
    # may exit with status 0 but emit errors).
    ./tests/ssl-opt.sh -f 'Default' >ssl-opt.out 2>ssl-opt.err
    grep PASS ssl-opt.out
    cat ssl-opt.err >&2
    # If ssl-opt.err is non-empty, record an error and keep going.
    [ ! -s ssl-opt.err ]
    rm ssl-opt.out ssl-opt.err
    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"
}

component_test_cmake_as_subdirectory () {
    # Remove existing generated files so that we use the ones CMake
    # generates
    make neat

    msg "build: cmake 'as-subdirectory' build"
    cd programs/test/cmake_subproject
    # Note: Explicitly generate files as these are turned off in releases
    cmake -D GEN_FILES=ON .
    make
    ./cmake_subproject
}

support_test_cmake_as_subdirectory () {
    support_test_cmake_out_of_source
}

component_test_cmake_as_package () {
    # Remove existing generated files so that we use the ones CMake
    # generates
    make neat

    msg "build: cmake 'as-package' build"
    root_dir="$(pwd)"
    cd programs/test/cmake_package
    build_variant_dir="$(pwd)"
    cmake .
    make
    ./cmake_package
    if [[ "$OSTYPE" == linux* ]]; then
        PKG_CONFIG_PATH="${build_variant_dir}/mbedtls/pkgconfig" \
        ${root_dir}/framework/scripts/pkgconfig.sh \
        mbedtls mbedx509 mbedcrypto
        # These are the EXPECTED package names. Renaming these could break
        # consumers of pkg-config, consider carefully.
    fi
}

support_test_cmake_as_package () {
    support_test_cmake_out_of_source
}

component_test_cmake_as_package_install () {
    # Remove existing generated files so that we use the ones CMake
    # generates
    make neat

    msg "build: cmake 'as-installed-package' build"
    cd programs/test/cmake_package_install
    cmake .
    make
    ./cmake_package_install
}

support_test_cmake_as_package_install () {
    support_test_cmake_out_of_source
}

component_build_cmake_custom_config_file () {
    # Make a copy of config file to use for the in-tree test
    cp "$CONFIG_H" include/mbedtls_config_in_tree_copy.h

    MBEDTLS_ROOT_DIR="$PWD"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"

    # Build once to get the generated files (which need an intact config file)
    cmake "$MBEDTLS_ROOT_DIR"
    make

    msg "build: cmake with -DMBEDTLS_CONFIG_FILE"
    scripts/config.py -w full_config.h full
    echo '#error "cmake -DMBEDTLS_CONFIG_FILE is not working."' > "$MBEDTLS_ROOT_DIR/$CONFIG_H"
    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h "$MBEDTLS_ROOT_DIR"
    make

    msg "build: cmake with -DMBEDTLS_CONFIG_FILE + -DMBEDTLS_USER_CONFIG_FILE"
    # In the user config, disable one feature (for simplicity, pick a feature
    # that nothing else depends on).
    echo '#undef MBEDTLS_NIST_KW_C' >user_config.h

    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h -DMBEDTLS_USER_CONFIG_FILE=user_config.h "$MBEDTLS_ROOT_DIR"
    make
    not programs/test/query_compile_time_config MBEDTLS_NIST_KW_C

    rm -f user_config.h full_config.h

    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"

    # Now repeat the test for an in-tree build:

    # Restore config for the in-tree test
    mv include/mbedtls_config_in_tree_copy.h "$CONFIG_H"

    # Build once to get the generated files (which need an intact config)
    cmake .
    make

    msg "build: cmake (in-tree) with -DMBEDTLS_CONFIG_FILE"
    scripts/config.py -w full_config.h full
    echo '#error "cmake -DMBEDTLS_CONFIG_FILE is not working."' > "$MBEDTLS_ROOT_DIR/$CONFIG_H"
    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h .
    make

    msg "build: cmake (in-tree) with -DMBEDTLS_CONFIG_FILE + -DMBEDTLS_USER_CONFIG_FILE"
    # In the user config, disable one feature (for simplicity, pick a feature
    # that nothing else depends on).
    echo '#undef MBEDTLS_NIST_KW_C' >user_config.h

    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h -DMBEDTLS_USER_CONFIG_FILE=user_config.h .
    make
    not programs/test/query_compile_time_config MBEDTLS_NIST_KW_C

    rm -f user_config.h full_config.h
}

support_build_cmake_custom_config_file () {
    support_test_cmake_out_of_source
}

component_build_cmake_programs_no_testing () {
    # Verify that the type of builds performed by oss-fuzz don't get accidentally broken
    msg "build: cmake with -DENABLE_PROGRAMS=ON and -DENABLE_TESTING=OFF"
    cmake -DENABLE_PROGRAMS=ON -DENABLE_TESTING=OFF .
    make
}

support_build_cmake_programs_no_testing () {
    support_test_cmake_out_of_source
}
