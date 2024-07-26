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

# Helper function for controlling (start & stop) the psasim server.
helper_psasim_server() {
    OPERATION=$1
    if [ "$OPERATION" == "start" ]; then
    (
        cd tests
        msg "start server in tests"
        psa-client-server/psasim/test/start_server.sh
        msg "start server in tf-psa-crypto/tests"
        cd ../tf-psa-crypto/tests
        ../../tests/psa-client-server/psasim/test/start_server.sh
    )
    else
    (
        msg "terminate servers and cleanup"
        tests/psa-client-server/psasim//test/kill_servers.sh

        # Remove temporary files and logs
        cd tests
        rm -f psa_notify_*
        rm -f psa_service_*
        rm -f psa_server.log

        cd ../tf-psa-crypto/tests
        rm -f psa_notify_*
        rm -f psa_service_*
        rm -f psa_server.log
    )
    fi
}

component_test_no_rsa_key_pair_generation() {
    msg "build: default config minus PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE"
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    scripts/config.py unset MBEDTLS_GENPRIME
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE
    make

    msg "test: default config minus PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE"
    make test
}

component_test_full_no_cipher () {
    msg "build: full no CIPHER"

    scripts/config.py full
    scripts/config.py unset MBEDTLS_CIPHER_C

    # The built-in implementation of the following algs/key-types depends
    # on CIPHER_C so we disable them.
    # This does not hold for KEY_TYPE_CHACHA20 and ALG_CHACHA20_POLY1305
    # so we keep them enabled.
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM_STAR_NO_TAG
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CMAC
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CBC_NO_PADDING
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CBC_PKCS7
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CFB
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CTR
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_ECB_NO_PADDING
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_OFB
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_STREAM_CIPHER
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_KEY_TYPE_DES

    # The following modules directly depends on CIPHER_C
    scripts/config.py unset MBEDTLS_CMAC_C
    scripts/config.py unset MBEDTLS_NIST_KW_C

    make

    # Ensure that CIPHER_C was not re-enabled
    not grep mbedtls_cipher_init ${BUILTIN_SRC_PATH}/cipher.o

    msg "test: full no CIPHER"
    make test
}

component_test_psasim () {
    msg "build server library and application"
    scripts/config.py crypto
    helper_psasim_config server
    helper_psasim_build server

    helper_psasim_cleanup_before_client

    msg "build library for client"
    helper_psasim_config client
    helper_psasim_build client

    msg "build basic psasim client"
    make -C tests/psa-client-server/psasim CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS" test/psa_client_base
    msg "test basic psasim client"
    tests/psa-client-server/psasim/test/run_test.sh psa_client_base

    msg "build full psasim client"
    make -C tests/psa-client-server/psasim CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS" test/psa_client_full
    msg "test full psasim client"
    tests/psa-client-server/psasim/test/run_test.sh psa_client_full

    make -C tests/psa-client-server/psasim clean
}

component_test_suite_with_psasim () {
    msg "build server library and application"
    helper_psasim_config server
    # Modify server's library configuration here (if needed)
    helper_psasim_build server

    helper_psasim_cleanup_before_client

    msg "build client library"
    helper_psasim_config client
    # PAKE functions are still unsupported from PSASIM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_JPAKE
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
    helper_psasim_build client

    msg "build test suites"
    make PSASIM=1 CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS" tests

    helper_psasim_server kill
    helper_psasim_server start

    # psasim takes an extremely long execution time on some test suites so we
    # exclude them from the list.
    SKIP_TEST_SUITES="constant_time_hmac,lmots,lms"
    export SKIP_TEST_SUITES

    msg "run test suites"
    make PSASIM=1 test

    helper_psasim_server kill
}
