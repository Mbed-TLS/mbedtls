# components-configuration-platform.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Configuration Testing - Platform
################################################################

component_tf_psa_crypto_build_no_std_function () {
    # catch compile bugs in _uninit functions
    msg "build: full config with NO_STD_FUNCTION, make, gcc" # ~ 30s
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py full
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py set MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py unset MBEDTLS_ENTROPY_NV_SEED
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py unset MBEDTLS_PLATFORM_NV_SEED_ALT

    cmake -D CMAKE_C_COMPILER=gcc -D CMAKE_BUILD_TYPE:String=Check -D GEN_FILES=ON "$TF_PSA_CRYPTO_ROOT_DIR"
    make
}

component_tf_psa_crypto_build_no_sockets () {
    # Note, C99 compliance can also be tested with the sockets support disabled,
    # as that requires a POSIX platform (which isn't the same as C99).
    msg "build: full config except net_sockets.c, make, gcc -std=c99 -pedantic" # ~ 30s
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py full
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py unset MBEDTLS_NET_C # getaddrinfo() undeclared, etc.
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py set MBEDTLS_NO_PLATFORM_ENTROPY # uses syscall() on GNU/Linux
    cmake -D CMAKE_C_COMPILER=gcc -D CMAKE_C_FLAGS="-Werror -Wall -Wextra -O1 -std=c99 -pedantic" -D CMAKE_BUILD_TYPE:String=Check -D GEN_FILES=ON "$TF_PSA_CRYPTO_ROOT_DIR"
    make
}

component_tf_psa_crypto_test_no_date_time () {
    msg "build: default config without MBEDTLS_HAVE_TIME_DATE"
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py unset MBEDTLS_HAVE_TIME_DATE
    cmake -D CMAKE_BUILD_TYPE:String=Check $TF_PSA_CRYPTO_ROOT_DIR
    make

    msg "test: !MBEDTLS_HAVE_TIME_DATE - main suites"
    make test
}

component_tf_psa_crypto_test_platform_calloc_macro () {
    msg "build: MBEDTLS_PLATFORM_{CALLOC/FREE}_MACRO enabled (ASan build)"
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py set MBEDTLS_PLATFORM_MEMORY
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py set MBEDTLS_PLATFORM_CALLOC_MACRO calloc
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py set MBEDTLS_PLATFORM_FREE_MACRO free
    cmake -D CMAKE_C_COMPILER=$ASAN_CC -D CMAKE_BUILD_TYPE:String=Asan -D GEN_FILES=ON "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: MBEDTLS_PLATFORM_{CALLOC/FREE}_MACRO enabled (ASan build)"
    make test
}

component_tf_psa_crypto_test_have_int32 () {
    msg "build: gcc, force 32-bit bignum limbs"
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py unset MBEDTLS_HAVE_ASM
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py unset MBEDTLS_AESNI_C
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py unset MBEDTLS_AESCE_C
    cmake -D CMAKE_C_COMPILER=gcc -D CMAKE_C_FLAGS='-O2 -Werror -Wall -Wextra -DMBEDTLS_HAVE_INT32' -D CMAKE_BUILD_TYPE:String=Check -D GEN_FILES=ON "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: gcc, force 32-bit bignum limbs"
    make test
}

component_tf_psa_crypto_test_have_int64 () {
    msg "build: gcc, force 64-bit bignum limbs"
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py unset MBEDTLS_HAVE_ASM
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py unset MBEDTLS_AESNI_C
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py unset MBEDTLS_AESCE_C
    cmake -D CMAKE_C_COMPILER=gcc -D CMAKE_C_FLAGS="-O2 -Werror -Wall -Wextra -DMBEDTLS_HAVE_INT64" -D CMAKE_C_COMPILER=gcc -D CMAKE_BUILD_TYPE:String=Check -D GEN_FILES=ON "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: gcc, force 64-bit bignum limbs"
    make test
}

component_tf_psa_crypto_test_have_int32_cmake_new_bignum () {
    msg "build: gcc, force 32-bit bignum limbs, new bignum interface, test hooks (ASan build)"
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py unset MBEDTLS_HAVE_ASM
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py unset MBEDTLS_AESNI_C
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py unset MBEDTLS_AESCE_C
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py set MBEDTLS_TEST_HOOKS
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py set MBEDTLS_ECP_WITH_MPI_UINT
    # Find a way to add LDFLAGS
    cmake -D CMAKE_C_COMPILER=gcc -D CMAKE_C_FLAGS="$ASAN_CFLAGS -Werror -Wall -Wextra -DMBEDTLS_HAVE_INT32" -D CMAKE_EXE_LINKER_FLAGS="$ASAN_CFLAGS" -D CMAKE_BUILD_TYPE:String=Check -D GEN_FILES=ON "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: gcc, force 32-bit bignum limbs, new bignum interface, test hooks (ASan build)"
    make test
}

component_tf_psa_crypto_test_no_udbl_division () {
    msg "build: MBEDTLS_NO_UDBL_DIVISION native" # ~ 10s
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py full
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py set MBEDTLS_NO_UDBL_DIVISION
    cmake -D CMAKE_C_FLAGS='-Werror -O1' -D CMAKE_BUILD_TYPE:String=Check -D GEN_FILES=ON "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: MBEDTLS_NO_UDBL_DIVISION native" # ~ 10s
    make test
}

component_tf_psa_crypto_test_no_64bit_multiplication () {
    msg "build: MBEDTLS_NO_64BIT_MULTIPLICATION native" # ~ 10s
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py full
    $TF_PSA_CRYPTO_ROOT_DIR/scripts/config.py set MBEDTLS_NO_64BIT_MULTIPLICATION
    cmake -D CMAKE_C_FLAGS='-Werror -O1' -D CMAKE_BUILD_TYPE:String=Check -D GEN_FILES=ON "$TF_PSA_CRYPTO_ROOT_DIR"
    make

    msg "test: MBEDTLS_NO_64BIT_MULTIPLICATION native" # ~ 10s
    make test
}
