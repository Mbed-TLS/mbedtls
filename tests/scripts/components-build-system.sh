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
    $MAKE_COMMAND SHARED=1 TEST_CPP=1 all check
    ldd programs/util/strerror | grep libmbedcrypto
    $FRAMEWORK/tests/programs/dlopen_demo.sh
}

component_test_cmake_shared () {
    msg "build/test: cmake shared" # ~ 2min
    cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .
    make
    ldd programs/util/strerror | grep libtfpsacrypto
    make test
    $FRAMEWORK/tests/programs/dlopen_demo.sh
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
    $MAKE_COMMAND neat

    msg "build: cmake 'out-of-source' build"
    MBEDTLS_ROOT_DIR="$PWD"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"
    # Note: Explicitly generate files as these are turned off in releases
    # Note: Use Clang compiler also for C++ (C uses it by default)
    CXX=clang++ cmake -D CMAKE_BUILD_TYPE:String=Check -D GEN_FILES=ON \
                      -D TEST_CPP=1 "$MBEDTLS_ROOT_DIR"
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
    $MAKE_COMMAND neat

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
    $MAKE_COMMAND neat

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
    $MAKE_COMMAND neat

    msg "build: cmake 'as-installed-package' build"
    cd programs/test/cmake_package_install
    cmake .
    make

    if ! cmp -s "mbedtls/lib/libtfpsacrypto.a" "mbedtls/lib/libmbedcrypto.a"; then
        echo "Error: Crypto static libraries are different or one of them is missing/unreadable." >&2
        exit 1
    fi
    if ! cmp -s "mbedtls/lib/libtfpsacrypto.so" "mbedtls/lib/libmbedcrypto.so"; then
        echo "Error: Crypto shared libraries are different or one of them is missing/unreadable." >&2
        exit 1
    fi

    ./cmake_package_install
}

support_test_cmake_as_package_install () {
    support_test_cmake_out_of_source
}

component_test_cmake_install_with_destdir () {
    # Remove existing generated files so that we use the ones CMake
    # generates
    $MAKE_COMMAND neat

    msg "install: cmake with DESTDIR staging"
    MBEDTLS_ROOT_DIR="$PWD"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"
    cmake -DGEN_FILES=ON -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF -DUSE_SHARED_MBEDTLS_LIBRARY=ON -DCMAKE_INSTALL_PREFIX:PATH=/usr "$MBEDTLS_ROOT_DIR"
    make

    DESTDIR="$OUT_OF_SOURCE_DIR/stage" make install

    install_lib_subdir="$(sed -n 's/^CMAKE_INSTALL_LIBDIR:PATH=//p' CMakeCache.txt)"
    [ -n "$install_lib_subdir" ] # Failed to read CMAKE_INSTALL_LIBDIR from CMakeCache.txt

    install_lib_path="$OUT_OF_SOURCE_DIR/stage/usr/${install_lib_subdir}"

    if [[ "$OSTYPE" == darwin* ]]; then
        # On macOS the custom install logic installs libmbedcrypto.dylib
        # directly without a versioned symlink chain.
        for lib in tfpsacrypto mbedcrypto mbedx509 mbedtls; do
            [ -f "$install_lib_path/lib${lib}.a" ]
            [ -e "$install_lib_path/lib${lib}.dylib" ]
        done
    else
        # library/CMakeLists.txt installs libmbedcrypto.so with a versioned
        # symlink chain on Linux.
        for lib in tfpsacrypto mbedcrypto mbedx509 mbedtls; do
            if [ "$QUIET" -eq 0 ]; then
                echo "Checking lib=$lib"
            fi
            [ -f "$install_lib_path/lib${lib}.a" ]
            [ -L "$install_lib_path/lib${lib}.so" ]
            [ -e "$install_lib_path/lib${lib}.so" ]

            # Match ABI-version names such as libxxx.so.17
            # and check that symlink.
            versioned=( "$install_lib_path/lib${lib}.so".+([0-9]) )
            if [ "$QUIET" -eq 0 ]; then
                declare -p versioned
            fi
            [ "${#versioned[@]}" -eq 1 ]
            [ -L "${versioned[0]}" ]
            [ -e "${versioned[0]}" ]
        done
    fi
}

support_test_cmake_install_with_destdir () {
    support_test_cmake_out_of_source
}

component_build_cmake_custom_config_file () {
    # Make a copy of config file to use for the in-tree test
    cp "$CONFIG_H" include/mbedtls_config_in_tree_copy.h
    cp "$CRYPTO_CONFIG_H" include/mbedtls_crypto_config_in_tree_copy.h

    MBEDTLS_ROOT_DIR="$PWD"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"

    # Build once to get the generated files (which need an intact config file)
    cmake "$MBEDTLS_ROOT_DIR"
    make

    msg "build: cmake with -DMBEDTLS_CONFIG_FILE"
    cd "$MBEDTLS_ROOT_DIR"
    scripts/config.py full
    cp include/mbedtls/mbedtls_config.h $OUT_OF_SOURCE_DIR/full_config.h
    cp tf-psa-crypto/include/psa/crypto_config.h $OUT_OF_SOURCE_DIR/full_crypto_config.h
    cd "$OUT_OF_SOURCE_DIR"
    echo '#error "cmake -DMBEDTLS_CONFIG_FILE is not working."' > "$MBEDTLS_ROOT_DIR/$CONFIG_H"
    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h -DTF_PSA_CRYPTO_CONFIG_FILE=full_crypto_config.h "$MBEDTLS_ROOT_DIR"
    make

    msg "build: cmake with -DMBEDTLS/TF_PSA_CRYPTO_CONFIG_FILE + -DMBEDTLS/TF_PSA_CRYPTO_USER_CONFIG_FILE"
    # In the user config, disable one feature (for simplicity, pick a feature
    # that nothing else depends on).
    echo '#undef MBEDTLS_SSL_ALL_ALERT_MESSAGES' >user_config.h
    echo '#undef MBEDTLS_NIST_KW_C' >crypto_user_config.h

    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h -DMBEDTLS_USER_CONFIG_FILE=user_config.h -DTF_PSA_CRYPTO_CONFIG_FILE=full_crypto_config.h -DTF_PSA_CRYPTO_USER_CONFIG_FILE=crypto_user_config.h "$MBEDTLS_ROOT_DIR"
    make
    not programs/test/query_compile_time_config MBEDTLS_SSL_ALL_ALERT_MESSAGES
    not programs/test/query_compile_time_config MBEDTLS_NIST_KW_C

    rm -f user_config.h full_config.h full_crypto_config.h

    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"

    # Now repeat the test for an in-tree build:

    # Restore config for the in-tree test
    mv include/mbedtls_config_in_tree_copy.h "$CONFIG_H"
    mv include/mbedtls_crypto_config_in_tree_copy.h "$CRYPTO_CONFIG_H"

    # Build once to get the generated files (which need an intact config)
    cmake .
    make

    msg "build: cmake (in-tree) with -DMBEDTLS_CONFIG_FILE"
    cp include/mbedtls/mbedtls_config.h full_config.h
    cp tf-psa-crypto/include/psa/crypto_config.h full_crypto_config.h

    echo '#error "cmake -DMBEDTLS_CONFIG_FILE is not working."' > "$MBEDTLS_ROOT_DIR/$CONFIG_H"
    cmake -DGEN_FILES=OFF -DTF_PSA_CRYPTO_CONFIG_FILE=full_crypto_config.h -DMBEDTLS_CONFIG_FILE=full_config.h .
    make

    msg "build: cmake (in-tree) with -DMBEDTLS/TF_PSA_CRYPTO_CONFIG_FILE + -DMBEDTLS/TF_PSA_CRYPTO_USER_CONFIG_FILE"
    # In the user config, disable one feature (for simplicity, pick a feature
    # that nothing else depends on).
    echo '#undef MBEDTLS_SSL_ALL_ALERT_MESSAGES' >user_config.h
    echo '#undef MBEDTLS_NIST_KW_C' >crypto_user_config.h

    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h -DMBEDTLS_USER_CONFIG_FILE=user_config.h -DTF_PSA_CRYPTO_CONFIG_FILE=full_crypto_config.h -DTF_PSA_CRYPTO_USER_CONFIG_FILE=crypto_user_config.h .
    make
    not programs/test/query_compile_time_config MBEDTLS_SSL_ALL_ALERT_MESSAGES
    not programs/test/query_compile_time_config MBEDTLS_NIST_KW_C

    rm -f user_config.h full_config.h
}

support_build_cmake_custom_config_file () {
    support_test_cmake_out_of_source
}

component_build_cmake_config_options () {
    MBEDTLS_ROOT_DIR="$PWD"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"

    msg "configure: cmake with MBEDTLS_CONFIG_NAME"
    cmake -DMBEDTLS_CONFIG_NAME=crypto "$MBEDTLS_ROOT_DIR"
    make query_compile_time_config
    not programs/test/query_compile_time_config MBEDTLS_SSL_TLS_C
    programs/test/query_compile_time_config PSA_WANT_ALG_CMAC

    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"

    msg "configure: cmake with a false-like option name"
    cmake -DMBEDTLS_CONFIG_SET=NO "$MBEDTLS_ROOT_DIR"
    grep '^#define NO$' generated/include/mbedtls/mbedtls_config.h
    cmake -DMBEDTLS_CONFIG_SET= .
    grep '^TF_PSA_CRYPTO_CONFIG_FILE:FILEPATH=$' CMakeCache.txt

    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"

    msg "configure: cmake with MBEDTLS_CONFIG_BASE_FILE only"
    cmake -DMBEDTLS_CONFIG_BASE_FILE=configs/config-ccm-psk-tls1_2.h \
          "$MBEDTLS_ROOT_DIR"
    cmp "$MBEDTLS_ROOT_DIR/configs/config-ccm-psk-tls1_2.h" \
        generated/include/mbedtls/mbedtls_config.h
    not test -e generated/include/psa/crypto_config.h

    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"
    launch_dir="$OUT_OF_SOURCE_DIR.launch"
    mkdir "$launch_dir"
    cd "$launch_dir"

    msg "configure: resolve a relative base config from the source tree"
    cmake -H"$MBEDTLS_ROOT_DIR" -B"$OUT_OF_SOURCE_DIR" \
        -DMBEDTLS_CONFIG_BASE_FILE=configs/config-ccm-psk-tls1_2.h \
        -DMBEDTLS_CONFIG_SET=MBEDTLS_DEBUG_C
    grep '^#define MBEDTLS_DEBUG_C' \
        "$OUT_OF_SOURCE_DIR/generated/include/mbedtls/mbedtls_config.h"

    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR" "$launch_dir"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"

    msg "configure: reject MBEDTLS_CONFIG_FILE with transformations"
    not cmake -DMBEDTLS_CONFIG_FILE=configs/config-ccm-psk-tls1_2.h \
              -DMBEDTLS_CONFIG_SET=MBEDTLS_DEBUG_C "$MBEDTLS_ROOT_DIR"

    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"

    msg "configure: reject TF_PSA_CRYPTO_CONFIG_FILE with Mbed TLS transformations"
    not cmake \
        -DTF_PSA_CRYPTO_CONFIG_FILE="$MBEDTLS_ROOT_DIR/tf-psa-crypto/include/psa/crypto_config.h" \
        -DMBEDTLS_CONFIG_SET=MBEDTLS_DEBUG_C "$MBEDTLS_ROOT_DIR"

    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"

    msg "build: combine Mbed TLS and TF-PSA-Crypto transformations"
    cmake \
        -DMBEDTLS_CONFIG_BASE_FILE=configs/config-ccm-psk-tls1_2.h \
        '-DMBEDTLS_CONFIG_SET=MBEDTLS_DEBUG_C;PSA_WANT_ALG_RIPEMD160' \
        -DTF_PSA_CRYPTO_CONFIG_BASE_FILE="$MBEDTLS_ROOT_DIR/tf-psa-crypto/configs/crypto-config-symmetric-only.h" \
        -DTF_PSA_CRYPTO_CONFIG_UNSET=PSA_WANT_ALG_RIPEMD160 \
        "$MBEDTLS_ROOT_DIR"
    make query_compile_time_config
    programs/test/query_compile_time_config MBEDTLS_DEBUG_C
    grep '^#define PSA_WANT_ALG_RIPEMD160' \
        generated/include/psa/crypto_config.h
    not programs/test/query_compile_time_config PSA_WANT_ALG_RIPEMD160
    not programs/test/query_compile_time_config \
        PSA_WANT_KEY_TYPE_DH_KEY_PAIR_BASIC

    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"

    msg "configure: reject a missing base configuration"
    not cmake -DMBEDTLS_CONFIG_BASE_FILE=configs/does-not-exist.h \
              "$MBEDTLS_ROOT_DIR"

    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"

    msg "build: cmake with a base config, MBEDTLS_CONFIG_SET and MBEDTLS_CONFIG_UNSET"
    cp "$MBEDTLS_ROOT_DIR/configs/config-ccm-psk-tls1_2.h" base_config.before
    cmake -DMBEDTLS_CONFIG_BASE_FILE=configs/config-ccm-psk-tls1_2.h \
          '-DMBEDTLS_CONFIG_UNSET=MBEDTLS_SSL_SRV_C;PSA_WANT_ALG_CMAC;PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128' \
          '-DMBEDTLS_CONFIG_SET=MBEDTLS_SSL_RENEGOTIATION;MBEDTLS_DEBUG_C;MBEDTLS_ERROR_C;MBEDTLS_SSL_IN_CONTENT_LEN=12000' \
          "$MBEDTLS_ROOT_DIR"
    make query_compile_time_config

    programs/test/query_compile_time_config MBEDTLS_SSL_PROTO_TLS1_2
    programs/test/query_compile_time_config MBEDTLS_SSL_RENEGOTIATION
    programs/test/query_compile_time_config MBEDTLS_DEBUG_C
    programs/test/query_compile_time_config MBEDTLS_ERROR_C
    not programs/test/query_compile_time_config MBEDTLS_SSL_SRV_C
    not programs/test/query_compile_time_config PSA_WANT_ALG_CMAC
    [ "$(programs/test/query_compile_time_config MBEDTLS_SSL_IN_CONTENT_LEN)" = \
      "12000" ]
    cmp base_config.before \
        "$MBEDTLS_ROOT_DIR/configs/config-ccm-psk-tls1_2.h"

    msg "install: generated configurations are relocatable"
    install_dir="$OUT_OF_SOURCE_DIR.install"
    cmake -DCMAKE_INSTALL_PREFIX="$install_dir" .
    cmake --build . --target install
    cmp generated/include/mbedtls/mbedtls_config.h \
        "$install_dir/include/mbedtls/mbedtls_config.h"
    cmp tf-psa-crypto/include/psa/crypto_config.h \
        "$install_dir/include/psa/crypto_config.h"

    # The installed targets must not refer to the build tree.
    cd "$MBEDTLS_ROOT_DIR"
    mv "$OUT_OF_SOURCE_DIR" "$OUT_OF_SOURCE_DIR.moved"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"
    mkdir consumer
    cat >consumer/CMakeLists.txt <<EOF
cmake_minimum_required(VERSION 3.10)
project(consumer C)
find_package(MbedTLS REQUIRED CONFIG)
add_executable(consumer
    "$MBEDTLS_ROOT_DIR/programs/test/cmake_package_install/cmake_package_config.c")
target_link_libraries(consumer PRIVATE
    MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::tfpsacrypto)
EOF
    mkdir consumer-build
    cd consumer-build
    cmake -DCMAKE_PREFIX_PATH="$install_dir" ../consumer
    cmake --build .
    cd ..

    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR" "$OUT_OF_SOURCE_DIR.moved" "$install_dir"

    msg "configure: reject transformations in an in-tree build"
    not cmake -DMBEDTLS_CONFIG_SET=NO .
    rm -rf CMakeCache.txt CMakeFiles
}

support_build_cmake_config_options () {
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
