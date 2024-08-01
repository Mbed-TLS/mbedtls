# components.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains the test components that are executed by all.sh

# The functions below are named as follows:
#  * component_XXX: independent components. They can be run in any order.
#      * component_check_XXX: quick tests that aren't worth parallelizing.
#      * component_build_XXX: build things but don't run them.
#      * component_test_XXX: build and test.
#      * component_release_XXX: tests that the CI should skip during PR testing.
#  * support_XXX: if support_XXX exists and returns false then
#    component_XXX is not run by default.

# Each component must start by invoking `msg` with a short informative message.
#
# Warning: due to the way bash detects errors, the failure of a command
# inside 'if' or '!' is not detected. Use the 'not' function instead of '!'.
#
# Each component is executed in a separate shell process. The component
# fails if any command in it returns a non-zero status.
#
# The framework in all.sh performs some cleanup tasks after each component.
# This means that components can assume that the working directory is in a
# cleaned-up state, and don't need to perform the cleanup themselves.
# * Run `make clean`.
# * Restore `include/mbedtls/mbedtls_config.h` from a backup made before running
#   the component.
# * Check out `Makefile`, `library/Makefile`, `programs/Makefile`,
#   `tests/Makefile` and `programs/fuzz/Makefile` from git.
#   This cleans up after an in-tree use of CMake.
#
# The tests are roughly in order from fastest to slowest. This doesn't
# have to be exact, but in general you should add slower tests towards
# the end and fast checks near the beginning.


################################################################
#### Build and test many configurations and targets
################################################################

################################################################
#### Basic checks
################################################################

#
# Test Suites to be executed
#
# The test ordering tries to optimize for the following criteria:
# 1. Catch possible problems early, by running first tests that run quickly
#    and/or are more likely to fail than others (eg I use Clang most of the
#    time, so start with a GCC build).
# 2. Minimize total running time, by avoiding useless rebuilds
#
# Indicative running times are given for reference.

################################################################
#### Build and test many configurations and targets
################################################################

component_test_psa_crypto_config_accel_hash_keep_builtins () {
    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated+builtin hash"
    # This component ensures that all the test cases for
    # md_psa_dynamic_dispatch with legacy+driver in test_suite_md are run.

    loc_accel_list="ALG_MD5 ALG_RIPEMD160 ALG_SHA_1 \
                    ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"

    # Start from default config (no USE_PSA)
    helper_libtestdriver1_adjust_config "default"

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated+builtin hash"
    make test
}

# This should be renamed to test and updated once the accelerator ECDH code is in place and ready to test.
component_build_psa_accel_alg_ecdh () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_ECDH without MBEDTLS_ECDH_C"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py unset MBEDTLS_ECDH_C
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_ECDH -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator HMAC code is in place and ready to test.
component_build_psa_accel_alg_hmac () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_HMAC"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_HMAC -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator HKDF code is in place and ready to test.
component_build_psa_accel_alg_hkdf () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_HKDF without MBEDTLS_HKDF_C"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_HKDF_C
    # Make sure to unset TLS1_3 since it requires HKDF_C and will not build properly without it.
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_HKDF -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator MD5 code is in place and ready to test.
component_build_psa_accel_alg_md5 () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_MD5 - other hashes"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RIPEMD160
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_1
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_224
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_256
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_384
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_512
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS
    scripts/config.py unset MBEDTLS_LMS_C
    scripts/config.py unset MBEDTLS_LMS_PRIVATE
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_MD5 -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator RIPEMD160 code is in place and ready to test.
component_build_psa_accel_alg_ripemd160 () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_RIPEMD160 - other hashes"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_MD5
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_1
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_224
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_256
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_384
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_512
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS
    scripts/config.py unset MBEDTLS_LMS_C
    scripts/config.py unset MBEDTLS_LMS_PRIVATE
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_RIPEMD160 -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator SHA1 code is in place and ready to test.
component_build_psa_accel_alg_sha1 () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_SHA_1 - other hashes"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_MD5
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RIPEMD160
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_224
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_256
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_384
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_512
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS
    scripts/config.py unset MBEDTLS_LMS_C
    scripts/config.py unset MBEDTLS_LMS_PRIVATE
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_SHA_1 -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator SHA224 code is in place and ready to test.
component_build_psa_accel_alg_sha224 () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_SHA_224 - other hashes"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_MD5
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RIPEMD160
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_1
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_384
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_512
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_SHA_224 -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator SHA256 code is in place and ready to test.
component_build_psa_accel_alg_sha256 () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_SHA_256 - other hashes"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_MD5
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RIPEMD160
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_1
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_224
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_384
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_512
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_SHA_256 -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator SHA384 code is in place and ready to test.
component_build_psa_accel_alg_sha384 () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_SHA_384 - other hashes"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_MD5
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RIPEMD160
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_1
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_224
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_256
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS
    scripts/config.py unset MBEDTLS_LMS_C
    scripts/config.py unset MBEDTLS_LMS_PRIVATE
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_SHA_384 -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator SHA512 code is in place and ready to test.
component_build_psa_accel_alg_sha512 () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_SHA_512 - other hashes"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_MD5
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RIPEMD160
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_1
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_224
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_256
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_SHA_384
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS
    scripts/config.py unset MBEDTLS_LMS_C
    scripts/config.py unset MBEDTLS_LMS_PRIVATE
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_SHA_512 -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator RSA code is in place and ready to test.
component_build_psa_accel_alg_rsa_pkcs1v15_crypt () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_RSA_PKCS1V15_CRYPT + PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py -f "$CRYPTO_CONFIG_H" set PSA_WANT_ALG_RSA_PKCS1V15_CRYPT 1
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RSA_PKCS1V15_SIGN
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RSA_OAEP
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RSA_PSS
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_CRYPT -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator RSA code is in place and ready to test.
component_build_psa_accel_alg_rsa_pkcs1v15_sign () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_RSA_PKCS1V15_SIGN + PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py -f "$CRYPTO_CONFIG_H" set PSA_WANT_ALG_RSA_PKCS1V15_SIGN 1
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RSA_PKCS1V15_CRYPT
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RSA_OAEP
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RSA_PSS
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator RSA code is in place and ready to test.
component_build_psa_accel_alg_rsa_oaep () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_RSA_OAEP + PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py -f "$CRYPTO_CONFIG_H" set PSA_WANT_ALG_RSA_OAEP 1
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RSA_PKCS1V15_CRYPT
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RSA_PKCS1V15_SIGN
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RSA_PSS
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_RSA_OAEP -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator RSA code is in place and ready to test.
component_build_psa_accel_alg_rsa_pss () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_ALG_RSA_PSS + PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py -f "$CRYPTO_CONFIG_H" set PSA_WANT_ALG_RSA_PSS 1
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RSA_PKCS1V15_CRYPT
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RSA_PKCS1V15_SIGN
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_RSA_OAEP
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_ALG_RSA_PSS -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator RSA code is in place and ready to test.
component_build_psa_accel_key_type_rsa_key_pair () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_xxx + PSA_WANT_ALG_RSA_PSS"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py -f "$CRYPTO_CONFIG_H" set PSA_WANT_ALG_RSA_PSS 1
    scripts/config.py -f "$CRYPTO_CONFIG_H" set PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC 1
    scripts/config.py -f "$CRYPTO_CONFIG_H" set PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT 1
    scripts/config.py -f "$CRYPTO_CONFIG_H" set PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT 1
    scripts/config.py -f "$CRYPTO_CONFIG_H" set PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE 1
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# This should be renamed to test and updated once the accelerator RSA code is in place and ready to test.
component_build_psa_accel_key_type_rsa_public_key () {
    msg "build: full - MBEDTLS_USE_PSA_CRYPTO + PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY + PSA_WANT_ALG_RSA_PSS"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py -f "$CRYPTO_CONFIG_H" set PSA_WANT_ALG_RSA_PSS 1
    scripts/config.py -f "$CRYPTO_CONFIG_H" set PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY 1
    # Need to define the correct symbol and include the test driver header path in order to build with the test driver
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY -I../tests/include" LDFLAGS="$ASAN_CFLAGS"
}

# For timebeing, no VIA Padlock platform available.
component_build_aes_via_padlock () {

    msg "AES:VIA PadLock, build with default configuration."
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py set MBEDTLS_PADLOCK_C
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    make CC=gcc CFLAGS="$ASAN_CFLAGS -m32" LDFLAGS="-m32 $ASAN_CFLAGS"
    grep -q mbedtls_padlock_has_support ./programs/test/selftest

}

support_build_aes_via_padlock_only () {
    ( [ "$MBEDTLS_TEST_PLATFORM" == "Linux-x86_64" ] || \
        [ "$MBEDTLS_TEST_PLATFORM" == "Linux-amd64" ] ) && \
    [ "`dpkg --print-foreign-architectures`" == "i386" ]
}

