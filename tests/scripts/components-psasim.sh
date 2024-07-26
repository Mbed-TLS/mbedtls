# components-psasim.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains the test components that are executed by all.sh

################################################################
#### Remote Procedure Call PSA Testing
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
