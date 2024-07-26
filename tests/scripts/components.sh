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

################################################################
#### Build and test many configurations and targets
################################################################

component_test_default_out_of_box () {
    msg "build: make, default config (out-of-box)" # ~1min
    make
    # Disable fancy stuff
    unset MBEDTLS_TEST_OUTCOME_FILE

    msg "test: main suites make, default config (out-of-box)" # ~10s
    make test

    msg "selftest: make, default config (out-of-box)" # ~10s
    programs/test/selftest

    msg "program demos: make, default config (out-of-box)" # ~10s
    tests/scripts/run_demos.py
}

component_test_default_cmake_gcc_asan () {
    msg "build: cmake, gcc, ASan" # ~ 1 min 50s
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "program demos (ASan build)" # ~10s
    tests/scripts/run_demos.py

    msg "test: selftest (ASan build)" # ~ 10s
    programs/test/selftest

    msg "test: metatests (GCC, ASan build)"
    tests/scripts/run-metatests.sh any asan poison

    msg "test: ssl-opt.sh (ASan build)" # ~ 1 min
    tests/ssl-opt.sh

    msg "test: compat.sh (ASan build)" # ~ 6 min
    tests/compat.sh

    msg "test: context-info.sh (ASan build)" # ~ 15 sec
    tests/context-info.sh
}

component_test_default_cmake_gcc_asan_new_bignum () {
    msg "build: cmake, gcc, ASan" # ~ 1 min 50s
    scripts/config.py set MBEDTLS_ECP_WITH_MPI_UINT
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: selftest (ASan build)" # ~ 10s
    programs/test/selftest

    msg "test: ssl-opt.sh (ASan build)" # ~ 1 min
    tests/ssl-opt.sh

    msg "test: compat.sh (ASan build)" # ~ 6 min
    tests/compat.sh

    msg "test: context-info.sh (ASan build)" # ~ 15 sec
    tests/context-info.sh
}

component_test_full_cmake_gcc_asan () {
    msg "build: full config, cmake, gcc, ASan"
    scripts/config.py full
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (inc. selftests) (full config, ASan build)"
    make test

    msg "test: selftest (full config, ASan build)" # ~ 10s
    programs/test/selftest

    msg "test: ssl-opt.sh (full config, ASan build)"
    tests/ssl-opt.sh

    # Note: the next two invocations cover all compat.sh test cases.
    # We should use the same here and in basic-build-test.sh.
    msg "test: compat.sh: default version (full config, ASan build)"
    tests/compat.sh -e 'ARIA\|CHACHA'

    msg "test: compat.sh: next: ARIA, Chacha (full config, ASan build)"
    env OPENSSL="$OPENSSL_NEXT" tests/compat.sh -e '^$' -f 'ARIA\|CHACHA'

    msg "test: context-info.sh (full config, ASan build)" # ~ 15 sec
    tests/context-info.sh
}


component_test_full_cmake_gcc_asan_new_bignum () {
    msg "build: full config, cmake, gcc, ASan"
    scripts/config.py full
    scripts/config.py set MBEDTLS_ECP_WITH_MPI_UINT
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (inc. selftests) (full config, new bignum, ASan)"
    make test

    msg "test: selftest (full config, new bignum, ASan)" # ~ 10s
    programs/test/selftest

    msg "test: ssl-opt.sh (full config, new bignum, ASan)"
    tests/ssl-opt.sh

    # Note: the next two invocations cover all compat.sh test cases.
    # We should use the same here and in basic-build-test.sh.
    msg "test: compat.sh: default version (full config, new bignum, ASan)"
    tests/compat.sh -e 'ARIA\|CHACHA'

    msg "test: compat.sh: next: ARIA, Chacha (full config, new bignum, ASan)"
    env OPENSSL="$OPENSSL_NEXT" tests/compat.sh -e '^$' -f 'ARIA\|CHACHA'

    msg "test: context-info.sh (full config, new bignum, ASan)" # ~ 15 sec
    tests/context-info.sh
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

component_test_ref_configs () {
    msg "test/build: ref-configs (ASan build)" # ~ 6 min 20s
    # test-ref-configs works by overwriting mbedtls_config.h; this makes cmake
    # want to re-generate generated files that depend on it, quite correctly.
    # However this doesn't work as the generation script expects a specific
    # format for mbedtls_config.h, which the other files don't follow. Also,
    # cmake can't know this, but re-generation is actually not necessary as
    # the generated files only depend on the list of available options, not
    # whether they're on or off. So, disable cmake's (over-sensitive here)
    # dependency resolution for generated files and just rely on them being
    # present (thanks to pre_generate_files) by turning GEN_FILES off.
    CC=$ASAN_CC cmake -D GEN_FILES=Off -D CMAKE_BUILD_TYPE:String=Asan .
    tests/scripts/test-ref-configs.pl config-tfm.h
}

component_test_no_renegotiation () {
    msg "build: Default + !MBEDTLS_SSL_RENEGOTIATION (ASan build)" # ~ 6 min
    scripts/config.py unset MBEDTLS_SSL_RENEGOTIATION
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: !MBEDTLS_SSL_RENEGOTIATION - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: !MBEDTLS_SSL_RENEGOTIATION - ssl-opt.sh (ASan build)" # ~ 6 min
    tests/ssl-opt.sh
}

component_test_no_pem_no_fs () {
    msg "build: Default + !MBEDTLS_PEM_PARSE_C + !MBEDTLS_FS_IO (ASan build)"
    scripts/config.py unset MBEDTLS_PEM_PARSE_C
    scripts/config.py unset MBEDTLS_FS_IO
    scripts/config.py unset MBEDTLS_PSA_ITS_FILE_C # requires a filesystem
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_STORAGE_C # requires PSA ITS
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: !MBEDTLS_PEM_PARSE_C !MBEDTLS_FS_IO - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: !MBEDTLS_PEM_PARSE_C !MBEDTLS_FS_IO - ssl-opt.sh (ASan build)" # ~ 6 min
    tests/ssl-opt.sh
}

component_test_rsa_no_crt () {
    msg "build: Default + RSA_NO_CRT (ASan build)" # ~ 6 min
    scripts/config.py set MBEDTLS_RSA_NO_CRT
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: RSA_NO_CRT - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: RSA_NO_CRT - RSA-related part of ssl-opt.sh (ASan build)" # ~ 5s
    tests/ssl-opt.sh -f RSA

    msg "test: RSA_NO_CRT - RSA-related part of compat.sh (ASan build)" # ~ 3 min
    tests/compat.sh -t RSA

    msg "test: RSA_NO_CRT - RSA-related part of context-info.sh (ASan build)" # ~ 15 sec
    tests/context-info.sh
}

component_test_no_ctr_drbg_classic () {
    msg "build: Full minus CTR_DRBG, classic crypto in TLS"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_CTR_DRBG_C
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: Full minus CTR_DRBG, classic crypto - main suites"
    make test

    # In this configuration, the TLS test programs use HMAC_DRBG.
    # The SSL tests are slow, so run a small subset, just enough to get
    # confidence that the SSL code copes with HMAC_DRBG.
    msg "test: Full minus CTR_DRBG, classic crypto - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f 'Default\|SSL async private.*delay=\|tickets enabled on server'

    msg "test: Full minus CTR_DRBG, classic crypto - compat.sh (subset)"
    tests/compat.sh -m tls12 -t 'ECDSA PSK' -V NO -p OpenSSL
}

component_test_no_ctr_drbg_use_psa () {
    msg "build: Full minus CTR_DRBG, PSA crypto in TLS"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_CTR_DRBG_C
    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: Full minus CTR_DRBG, USE_PSA_CRYPTO - main suites"
    make test

    # In this configuration, the TLS test programs use HMAC_DRBG.
    # The SSL tests are slow, so run a small subset, just enough to get
    # confidence that the SSL code copes with HMAC_DRBG.
    msg "test: Full minus CTR_DRBG, USE_PSA_CRYPTO - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f 'Default\|SSL async private.*delay=\|tickets enabled on server'

    msg "test: Full minus CTR_DRBG, USE_PSA_CRYPTO - compat.sh (subset)"
    tests/compat.sh -m tls12 -t 'ECDSA PSK' -V NO -p OpenSSL
}

component_test_no_hmac_drbg_classic () {
    msg "build: Full minus HMAC_DRBG, classic crypto in TLS"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_ECDSA_DETERMINISTIC # requires HMAC_DRBG
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: Full minus HMAC_DRBG, classic crypto - main suites"
    make test

    # Normally our ECDSA implementation uses deterministic ECDSA. But since
    # HMAC_DRBG is disabled in this configuration, randomized ECDSA is used
    # instead.
    # Test SSL with non-deterministic ECDSA. Only test features that
    # might be affected by how ECDSA signature is performed.
    msg "test: Full minus HMAC_DRBG, classic crypto - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f 'Default\|SSL async private: sign'

    # To save time, only test one protocol version, since this part of
    # the protocol is identical in (D)TLS up to 1.2.
    msg "test: Full minus HMAC_DRBG, classic crypto - compat.sh (ECDSA)"
    tests/compat.sh -m tls12 -t 'ECDSA'
}

component_test_no_hmac_drbg_use_psa () {
    msg "build: Full minus HMAC_DRBG, PSA crypto in TLS"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_ECDSA_DETERMINISTIC # requires HMAC_DRBG
    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: Full minus HMAC_DRBG, USE_PSA_CRYPTO - main suites"
    make test

    # Normally our ECDSA implementation uses deterministic ECDSA. But since
    # HMAC_DRBG is disabled in this configuration, randomized ECDSA is used
    # instead.
    # Test SSL with non-deterministic ECDSA. Only test features that
    # might be affected by how ECDSA signature is performed.
    msg "test: Full minus HMAC_DRBG, USE_PSA_CRYPTO - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f 'Default\|SSL async private: sign'

    # To save time, only test one protocol version, since this part of
    # the protocol is identical in (D)TLS up to 1.2.
    msg "test: Full minus HMAC_DRBG, USE_PSA_CRYPTO - compat.sh (ECDSA)"
    tests/compat.sh -m tls12 -t 'ECDSA'
}

component_test_psa_external_rng_no_drbg_classic () {
    msg "build: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG, classic crypto in TLS"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py set MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
    scripts/config.py unset MBEDTLS_ENTROPY_C
    scripts/config.py unset MBEDTLS_ENTROPY_NV_SEED
    scripts/config.py unset MBEDTLS_PLATFORM_NV_SEED_ALT
    scripts/config.py unset MBEDTLS_CTR_DRBG_C
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_ECDSA_DETERMINISTIC # requires HMAC_DRBG
    # When MBEDTLS_USE_PSA_CRYPTO is disabled and there is no DRBG,
    # the SSL test programs don't have an RNG and can't work. Explicitly
    # make them use the PSA RNG with -DMBEDTLS_TEST_USE_PSA_CRYPTO_RNG.
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DMBEDTLS_TEST_USE_PSA_CRYPTO_RNG" LDFLAGS="$ASAN_CFLAGS"

    msg "test: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG, classic crypto - main suites"
    make test

    msg "test: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG, classic crypto - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f 'Default'
}

component_test_psa_external_rng_no_drbg_use_psa () {
    msg "build: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG, PSA crypto in TLS"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
    scripts/config.py unset MBEDTLS_ENTROPY_C
    scripts/config.py unset MBEDTLS_ENTROPY_NV_SEED
    scripts/config.py unset MBEDTLS_PLATFORM_NV_SEED_ALT
    scripts/config.py unset MBEDTLS_CTR_DRBG_C
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_ECDSA_DETERMINISTIC # requires HMAC_DRBG
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG, PSA crypto - main suites"
    make test

    msg "test: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG, PSA crypto - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f 'Default\|opaque'
}

component_test_sw_inet_pton () {
    msg "build: default plus MBEDTLS_TEST_SW_INET_PTON"

    # MBEDTLS_TEST_HOOKS required for x509_crt_parse_cn_inet_pton
    scripts/config.py set MBEDTLS_TEST_HOOKS
    make CFLAGS="-DMBEDTLS_TEST_SW_INET_PTON"

    msg "test: default plus MBEDTLS_TEST_SW_INET_PTON"
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

component_test_tls1_2_default_stream_cipher_only () {
    msg "build: default with only stream cipher use psa"

    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    # Disable AEAD (controlled by the presence of one of GCM_C, CCM_C, CHACHAPOLY_C)
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM_STAR_NO_TAG
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_GCM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CHACHA20_POLY1305
    # Note: The three unsets below are to be removed for Mbed TLS 4.0
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py unset MBEDTLS_CCM_C
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    #Disable TLS 1.3 (as no AEAD)
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    # Disable CBC. Note: When implemented, PSA_WANT_ALG_CBC_MAC will also need to be unset here to fully disable CBC
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CBC_NO_PADDING
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CBC_PKCS7
    # Disable CBC-legacy (controlled by MBEDTLS_CIPHER_MODE_CBC plus at least one block cipher (AES, ARIA, Camellia, DES))
    # Note: The unset below is to be removed for 4.0
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CBC
    # Disable CBC-EtM (controlled by the same as CBC-legacy plus MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    scripts/config.py unset MBEDTLS_SSL_ENCRYPT_THEN_MAC
    # Enable stream (currently that's just the NULL pseudo-cipher (controlled by MBEDTLS_CIPHER_NULL_CIPHER))
    scripts/config.py set MBEDTLS_CIPHER_NULL_CIPHER
    # Modules that depend on AEAD
    scripts/config.py unset MBEDTLS_SSL_CONTEXT_SERIALIZATION
    scripts/config.py unset MBEDTLS_SSL_TICKET_C

    make

    msg "test: default with only stream cipher use psa"
    make test

    # Not running ssl-opt.sh because most tests require a non-NULL ciphersuite.
}

component_test_tls1_2_default_cbc_legacy_cipher_only () {
    msg "build: default with only CBC-legacy cipher use psa"

    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    # Disable AEAD (controlled by the presence of one of GCM_C, CCM_C, CHACHAPOLY_C)
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM_STAR_NO_TAG
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_GCM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CHACHA20_POLY1305
    # Note: The three unsets below are to be removed for Mbed TLS 4.0
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py unset MBEDTLS_CCM_C
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    #Disable TLS 1.3 (as no AEAD)
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    # Enable CBC-legacy (controlled by MBEDTLS_CIPHER_MODE_CBC plus at least one block cipher (AES, ARIA, Camellia, DES))
    scripts/config.py -f $CRYPTO_CONFIG_H set PSA_WANT_ALG_CBC_NO_PADDING
    # Disable CBC-EtM (controlled by the same as CBC-legacy plus MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    scripts/config.py unset MBEDTLS_SSL_ENCRYPT_THEN_MAC
    # Disable stream (currently that's just the NULL pseudo-cipher (controlled by MBEDTLS_CIPHER_NULL_CIPHER))
    scripts/config.py unset MBEDTLS_CIPHER_NULL_CIPHER
    # Modules that depend on AEAD
    scripts/config.py unset MBEDTLS_SSL_CONTEXT_SERIALIZATION
    scripts/config.py unset MBEDTLS_SSL_TICKET_C

    make

    msg "test: default with only CBC-legacy cipher use psa"
    make test

    msg "test: default with only CBC-legacy cipher use psa - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f "TLS 1.2"
}

component_test_tls1_2_default_cbc_legacy_cbc_etm_cipher_only () {
    msg "build: default with only CBC-legacy and CBC-EtM ciphers use psa"

    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    # Disable AEAD (controlled by the presence of one of GCM_C, CCM_C, CHACHAPOLY_C)
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM_STAR_NO_TAG
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_GCM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CHACHA20_POLY1305
    # Note: The three unsets below are to be removed for Mbed TLS 4.0
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py unset MBEDTLS_CCM_C
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    #Disable TLS 1.3 (as no AEAD)
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    # Enable CBC-legacy (controlled by MBEDTLS_CIPHER_MODE_CBC plus at least one block cipher (AES, ARIA, Camellia, DES))
    scripts/config.py -f $CRYPTO_CONFIG_H set PSA_WANT_ALG_CBC_NO_PADDING
    # Enable CBC-EtM (controlled by the same as CBC-legacy plus MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    scripts/config.py set MBEDTLS_SSL_ENCRYPT_THEN_MAC
    # Disable stream (currently that's just the NULL pseudo-cipher (controlled by MBEDTLS_CIPHER_NULL_CIPHER))
    scripts/config.py unset MBEDTLS_CIPHER_NULL_CIPHER
    # Modules that depend on AEAD
    scripts/config.py unset MBEDTLS_SSL_CONTEXT_SERIALIZATION
    scripts/config.py unset MBEDTLS_SSL_TICKET_C

    make

    msg "test: default with only CBC-legacy and CBC-EtM ciphers use psa"
    make test

    msg "test: default with only CBC-legacy and CBC-EtM ciphers use psa - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f "TLS 1.2"
}

# We're not aware of any other (open source) implementation of EC J-PAKE in TLS
# that we could use for interop testing. However, we now have sort of two
# implementations ourselves: one using PSA, the other not. At least test that
# these two interoperate with each other.
component_test_tls1_2_ecjpake_compatibility() {
    msg "build: TLS1.2 server+client w/ EC-JPAKE w/o USE_PSA"
    scripts/config.py set MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
    # Explicitly make lib first to avoid a race condition:
    # https://github.com/Mbed-TLS/mbedtls/issues/8229
    make lib
    make -C programs ssl/ssl_server2 ssl/ssl_client2
    cp programs/ssl/ssl_server2 s2_no_use_psa
    cp programs/ssl/ssl_client2 c2_no_use_psa

    msg "build: TLS1.2 server+client w/ EC-JPAKE w/ USE_PSA"
    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    make clean
    make lib
    make -C programs ssl/ssl_server2 ssl/ssl_client2
    make -C programs test/udp_proxy test/query_compile_time_config

    msg "test: server w/o USE_PSA - client w/ USE_PSA, text password"
    P_SRV=../s2_no_use_psa tests/ssl-opt.sh -f "ECJPAKE: working, TLS"
    msg "test: server w/o USE_PSA - client w/ USE_PSA, opaque password"
    P_SRV=../s2_no_use_psa tests/ssl-opt.sh -f "ECJPAKE: opaque password client only, working, TLS"
    msg "test: client w/o USE_PSA - server w/ USE_PSA, text password"
    P_CLI=../c2_no_use_psa tests/ssl-opt.sh -f "ECJPAKE: working, TLS"
    msg "test: client w/o USE_PSA - server w/ USE_PSA, opaque password"
    P_CLI=../c2_no_use_psa tests/ssl-opt.sh -f "ECJPAKE: opaque password server only, working, TLS"

    rm s2_no_use_psa c2_no_use_psa
}

component_test_everest () {
    msg "build: Everest ECDH context (ASan build)" # ~ 6 min
    scripts/config.py set MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: Everest ECDH context - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: metatests (clang, ASan)"
    tests/scripts/run-metatests.sh any asan poison

    msg "test: Everest ECDH context - ECDH-related part of ssl-opt.sh (ASan build)" # ~ 5s
    tests/ssl-opt.sh -f ECDH

    msg "test: Everest ECDH context - compat.sh with some ECDH ciphersuites (ASan build)" # ~ 3 min
    # Exclude some symmetric ciphers that are redundant here to gain time.
    tests/compat.sh -f ECDH -V NO -e 'ARIA\|CAMELLIA\|CHACHA'
}

component_test_everest_curve25519_only () {
    msg "build: Everest ECDH context, only Curve25519" # ~ 6 min
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    scripts/config.py set MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_DETERMINISTIC_ECDSA
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_ECDSA
    scripts/config.py -f $CRYPTO_CONFIG_H set PSA_WANT_ALG_ECDH
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_ECJPAKE_C
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_JPAKE

    # Disable all curves
    scripts/config.py unset-all "MBEDTLS_ECP_DP_[0-9A-Z_a-z]*_ENABLED"
    scripts/config.py -f $CRYPTO_CONFIG_H unset-all "PSA_WANT_ECC_[0-9A-Z_a-z]*$"
    scripts/config.py -f $CRYPTO_CONFIG_H set PSA_WANT_ECC_MONTGOMERY_255

    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: Everest ECDH context, only Curve25519" # ~ 50s
    make test
}

component_test_small_ssl_out_content_len () {
    msg "build: small SSL_OUT_CONTENT_LEN (ASan build)"
    scripts/config.py set MBEDTLS_SSL_IN_CONTENT_LEN 16384
    scripts/config.py set MBEDTLS_SSL_OUT_CONTENT_LEN 4096
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: small SSL_OUT_CONTENT_LEN - ssl-opt.sh MFL and large packet tests"
    tests/ssl-opt.sh -f "Max fragment\|Large packet"
}

component_test_small_ssl_in_content_len () {
    msg "build: small SSL_IN_CONTENT_LEN (ASan build)"
    scripts/config.py set MBEDTLS_SSL_IN_CONTENT_LEN 4096
    scripts/config.py set MBEDTLS_SSL_OUT_CONTENT_LEN 16384
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: small SSL_IN_CONTENT_LEN - ssl-opt.sh MFL tests"
    tests/ssl-opt.sh -f "Max fragment"
}

component_test_small_ssl_dtls_max_buffering () {
    msg "build: small MBEDTLS_SSL_DTLS_MAX_BUFFERING #0"
    scripts/config.py set MBEDTLS_SSL_DTLS_MAX_BUFFERING 1000
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: small MBEDTLS_SSL_DTLS_MAX_BUFFERING #0 - ssl-opt.sh specific reordering test"
    tests/ssl-opt.sh -f "DTLS reordering: Buffer out-of-order hs msg before reassembling next, free buffered msg"
}

component_test_small_mbedtls_ssl_dtls_max_buffering () {
    msg "build: small MBEDTLS_SSL_DTLS_MAX_BUFFERING #1"
    scripts/config.py set MBEDTLS_SSL_DTLS_MAX_BUFFERING 190
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: small MBEDTLS_SSL_DTLS_MAX_BUFFERING #1 - ssl-opt.sh specific reordering test"
    tests/ssl-opt.sh -f "DTLS reordering: Buffer encrypted Finished message, drop for fragmented NewSessionTicket"
}

component_test_full_cmake_clang () {
    msg "build: cmake, full config, clang" # ~ 50s
    scripts/config.py full
    CC=clang CXX=clang cmake -D CMAKE_BUILD_TYPE:String=Release -D ENABLE_TESTING=On -D TEST_CPP=1 .
    make

    msg "test: main suites (full config, clang)" # ~ 5s
    make test

    msg "test: cpp_dummy_build (full config, clang)" # ~ 1s
    programs/test/cpp_dummy_build

    msg "test: metatests (clang)"
    tests/scripts/run-metatests.sh any pthread

    msg "program demos (full config, clang)" # ~10s
    tests/scripts/run_demos.py

    msg "test: psa_constant_names (full config, clang)" # ~ 1s
    tests/scripts/test_psa_constant_names.py

    msg "test: ssl-opt.sh default, ECJPAKE, SSL async (full config)" # ~ 1s
    tests/ssl-opt.sh -f 'Default\|ECJPAKE\|SSL async private'
}

skip_suites_without_constant_flow () {
    # Skip the test suites that don't have any constant-flow annotations.
    # This will need to be adjusted if we ever start declaring things as
    # secret from macros or functions inside tests/include or tests/src.
    SKIP_TEST_SUITES=$(
        git -C tests/suites grep -L TEST_CF_ 'test_suite_*.function' |
            sed 's/test_suite_//; s/\.function$//' |
            tr '\n' ,),$(
        git -C tf-psa-crypto/tests/suites grep -L TEST_CF_ 'test_suite_*.function' |
            sed 's/test_suite_//; s/\.function$//' |
            tr '\n' ,)
    export SKIP_TEST_SUITES
}

skip_all_except_given_suite () {
    # Skip all but the given test suite
    SKIP_TEST_SUITES=$(
        ls -1 tests/suites/test_suite_*.function |
        grep -v $1.function |
         sed 's/tests.suites.test_suite_//; s/\.function$//' |
        tr '\n' ,),$(
        ls -1 tf-psa-crypto/tests/suites/test_suite_*.function |
        grep -v $1.function |
         sed 's/tf-psa-crypto.tests.suites.test_suite_//; s/\.function$//' |
        tr '\n' ,)
    export SKIP_TEST_SUITES
}

component_test_memsan_constant_flow () {
    # This tests both (1) accesses to undefined memory, and (2) branches or
    # memory access depending on secret values. To distinguish between those:
    # - unset MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN - does the failure persist?
    # - or alternatively, change the build type to MemSanDbg, which enables
    # origin tracking and nicer stack traces (which are useful for debugging
    # anyway), and check if the origin was TEST_CF_SECRET() or something else.
    msg "build: cmake MSan (clang), full config minus MBEDTLS_USE_PSA_CRYPTO with constant flow testing"
    scripts/config.py full
    scripts/config.py set MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_AESNI_C # memsan doesn't grok asm
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=MemSan .
    make

    msg "test: main suites (full minus MBEDTLS_USE_PSA_CRYPTO, Msan + constant flow)"
    make test
}

component_test_memsan_constant_flow_psa () {
    # This tests both (1) accesses to undefined memory, and (2) branches or
    # memory access depending on secret values. To distinguish between those:
    # - unset MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN - does the failure persist?
    # - or alternatively, change the build type to MemSanDbg, which enables
    # origin tracking and nicer stack traces (which are useful for debugging
    # anyway), and check if the origin was TEST_CF_SECRET() or something else.
    msg "build: cmake MSan (clang), full config with constant flow testing"
    scripts/config.py full
    scripts/config.py set MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN
    scripts/config.py unset MBEDTLS_AESNI_C # memsan doesn't grok asm
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=MemSan .
    make

    msg "test: main suites (Msan + constant flow)"
    make test
}

component_release_test_valgrind_constant_flow () {
    # This tests both (1) everything that valgrind's memcheck usually checks
    # (heap buffer overflows, use of uninitialized memory, use-after-free,
    # etc.) and (2) branches or memory access depending on secret values,
    # which will be reported as uninitialized memory. To distinguish between
    # secret and actually uninitialized:
    # - unset MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND - does the failure persist?
    # - or alternatively, build with debug info and manually run the offending
    # test suite with valgrind --track-origins=yes, then check if the origin
    # was TEST_CF_SECRET() or something else.
    msg "build: cmake release GCC, full config minus MBEDTLS_USE_PSA_CRYPTO with constant flow testing"
    scripts/config.py full
    scripts/config.py set MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    skip_suites_without_constant_flow
    cmake -D CMAKE_BUILD_TYPE:String=Release .
    make

    # this only shows a summary of the results (how many of each type)
    # details are left in Testing/<date>/DynamicAnalysis.xml
    msg "test: some suites (full minus MBEDTLS_USE_PSA_CRYPTO, valgrind + constant flow)"
    make memcheck

    # Test asm path in constant time module - by default, it will test the plain C
    # path under Valgrind or Memsan. Running only the constant_time tests is fast (<1s)
    msg "test: valgrind asm constant_time"
    scripts/config.py --force set MBEDTLS_TEST_CONSTANT_FLOW_ASM
    skip_all_except_given_suite test_suite_constant_time
    cmake -D CMAKE_BUILD_TYPE:String=Release .
    make clean
    make
    make memcheck
}

component_release_test_valgrind_constant_flow_psa () {
    # This tests both (1) everything that valgrind's memcheck usually checks
    # (heap buffer overflows, use of uninitialized memory, use-after-free,
    # etc.) and (2) branches or memory access depending on secret values,
    # which will be reported as uninitialized memory. To distinguish between
    # secret and actually uninitialized:
    # - unset MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND - does the failure persist?
    # - or alternatively, build with debug info and manually run the offending
    # test suite with valgrind --track-origins=yes, then check if the origin
    # was TEST_CF_SECRET() or something else.
    msg "build: cmake release GCC, full config with constant flow testing"
    scripts/config.py full
    scripts/config.py set MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND
    skip_suites_without_constant_flow
    cmake -D CMAKE_BUILD_TYPE:String=Release .
    make

    # this only shows a summary of the results (how many of each type)
    # details are left in Testing/<date>/DynamicAnalysis.xml
    msg "test: some suites (valgrind + constant flow)"
    make memcheck
}

component_test_tsan () {
    msg "build: TSan (clang)"
    scripts/config.py full
    scripts/config.py set MBEDTLS_THREADING_C
    scripts/config.py set MBEDTLS_THREADING_PTHREAD
    # Self-tests do not currently use multiple threads.
    scripts/config.py unset MBEDTLS_SELF_TEST

    # The deprecated MBEDTLS_PSA_CRYPTO_SE_C interface is not thread safe.
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_SE_C

    CC=clang cmake -D CMAKE_BUILD_TYPE:String=TSan .
    make

    msg "test: main suites (TSan)"
    make test
}

component_test_default_no_deprecated () {
    # Test that removing the deprecated features from the default
    # configuration leaves something consistent.
    msg "build: make, default + MBEDTLS_DEPRECATED_REMOVED" # ~ 30s
    scripts/config.py set MBEDTLS_DEPRECATED_REMOVED
    make CFLAGS='-O -Werror -Wall -Wextra'

    msg "test: make, default + MBEDTLS_DEPRECATED_REMOVED" # ~ 5s
    make test
}

component_test_full_no_deprecated () {
    msg "build: make, full_no_deprecated config" # ~ 30s
    scripts/config.py full_no_deprecated
    make CFLAGS='-O -Werror -Wall -Wextra'

    msg "test: make, full_no_deprecated config" # ~ 5s
    make test

    msg "test: ensure that X509 has no direct dependency on BIGNUM_C"
    not grep mbedtls_mpi library/libmbedx509.a
}

component_test_full_no_deprecated_deprecated_warning () {
    # Test that there is nothing deprecated in "full_no_deprecated".
    # A deprecated feature would trigger a warning (made fatal) from
    # MBEDTLS_DEPRECATED_WARNING.
    msg "build: make, full_no_deprecated config, MBEDTLS_DEPRECATED_WARNING" # ~ 30s
    scripts/config.py full_no_deprecated
    scripts/config.py unset MBEDTLS_DEPRECATED_REMOVED
    scripts/config.py set MBEDTLS_DEPRECATED_WARNING
    make CFLAGS='-O -Werror -Wall -Wextra'

    msg "test: make, full_no_deprecated config, MBEDTLS_DEPRECATED_WARNING" # ~ 5s
    make test
}

component_test_full_deprecated_warning () {
    # Test that when MBEDTLS_DEPRECATED_WARNING is enabled, the build passes
    # with only certain whitelisted types of warnings.
    msg "build: make, full config + MBEDTLS_DEPRECATED_WARNING, expect warnings" # ~ 30s
    scripts/config.py full
    scripts/config.py set MBEDTLS_DEPRECATED_WARNING
    # Expect warnings from '#warning' directives in check_config.h.
    # Note that gcc is required to allow the use of -Wno-error=cpp, which allows us to
    # display #warning messages without them being treated as errors.
    make CC=gcc CFLAGS='-O -Werror -Wall -Wextra -Wno-error=cpp' lib programs

    msg "build: make tests, full config + MBEDTLS_DEPRECATED_WARNING, expect warnings" # ~ 30s
    # Set MBEDTLS_TEST_DEPRECATED to enable tests for deprecated features.
    # By default those are disabled when MBEDTLS_DEPRECATED_WARNING is set.
    # Expect warnings from '#warning' directives in check_config.h and
    # from the use of deprecated functions in test suites.
    make CC=gcc CFLAGS='-O -Werror -Wall -Wextra -Wno-error=deprecated-declarations -Wno-error=cpp -DMBEDTLS_TEST_DEPRECATED' tests

    msg "test: full config + MBEDTLS_TEST_DEPRECATED" # ~ 30s
    make test

    msg "program demos: full config + MBEDTLS_TEST_DEPRECATED" # ~10s
    tests/scripts/run_demos.py
}

component_build_baremetal () {
  msg "build: make, baremetal config"
  scripts/config.py baremetal
  make CFLAGS="-O1 -Werror -I$PWD/tests/include/baremetal-override/"
}
support_build_baremetal () {
    # Older Glibc versions include time.h from other headers such as stdlib.h,
    # which makes the no-time.h-in-baremetal check fail. Ubuntu 16.04 has this
    # problem, Ubuntu 18.04 is ok.
    ! grep -q -F time.h /usr/include/x86_64-linux-gnu/sys/types.h
}

component_test_no_psa_crypto_full_cmake_asan() {
    # full minus MBEDTLS_PSA_CRYPTO_C: run the same set of tests as basic-build-test.sh
    msg "build: cmake, full config minus PSA crypto, ASan"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_CLIENT
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py unset MBEDTLS_PSA_ITS_FILE_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_SE_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_STORAGE_C
    scripts/config.py unset MBEDTLS_LMS_C
    scripts/config.py unset MBEDTLS_LMS_PRIVATE
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (full minus PSA crypto)"
    make test

    # Note: ssl-opt.sh has some test cases that depend on
    # MBEDTLS_ECP_RESTARTABLE && !MBEDTLS_USE_PSA_CRYPTO
    # This is the only component where those tests are not skipped.
    msg "test: ssl-opt.sh (full minus PSA crypto)"
    tests/ssl-opt.sh

    # Note: the next two invocations cover all compat.sh test cases.
    # We should use the same here and in basic-build-test.sh.
    msg "test: compat.sh: default version (full minus PSA crypto)"
    tests/compat.sh -e 'ARIA\|CHACHA'

    msg "test: compat.sh: next: ARIA, Chacha (full minus PSA crypto)"
    env OPENSSL="$OPENSSL_NEXT" tests/compat.sh -e '^$' -f 'ARIA\|CHACHA'
}

# Common helper for component_full_without_ecdhe_ecdsa() and
# component_full_without_ecdhe_ecdsa_and_tls13() which:
# - starts from the "full" configuration minus the list of symbols passed in
#   as 1st parameter
# - build
# - test only TLS (i.e. test_suite_tls and ssl-opt)
build_full_minus_something_and_test_tls () {
    symbols_to_disable="$1"

    msg "build: full minus something, test TLS"

    scripts/config.py full
    for sym in $symbols_to_disable; do
        echo "Disabling $sym"
        scripts/config.py unset $sym
    done

    make

    msg "test: full minus something, test TLS"
    ( cd tests; ./test_suite_ssl )

    msg "ssl-opt: full minus something, test TLS"
    tests/ssl-opt.sh
}

component_full_without_ecdhe_ecdsa () {
    build_full_minus_something_and_test_tls "MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED"
}

component_full_without_ecdhe_ecdsa_and_tls13 () {
    build_full_minus_something_and_test_tls "MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
                                             MBEDTLS_SSL_PROTO_TLS1_3"
}

component_build_tfm() {
    # Check that the TF-M configuration can build cleanly with various
    # warning flags enabled. We don't build or run tests, since the
    # TF-M configuration needs a TF-M platform. A tweaked version of
    # the configuration that works on mainstream platforms is in
    # configs/config-tfm.h, tested via test-ref-configs.pl.
    cp configs/config-tfm.h "$CONFIG_H"

    msg "build: TF-M config, clang, armv7-m thumb2"
    make lib CC="clang" CFLAGS="--target=arm-linux-gnueabihf -march=armv7-m -mthumb -Os -std=c99 -Werror -Wall -Wextra -Wwrite-strings -Wpointer-arith -Wimplicit-fallthrough -Wshadow -Wvla -Wformat=2 -Wno-format-nonliteral -Wshadow -Wasm-operand-widths -Wunused -I../tests/include/spe"

    msg "build: TF-M config, gcc native build"
    make clean
    make lib CC="gcc" CFLAGS="-Os -std=c99 -Werror -Wall -Wextra -Wwrite-strings -Wpointer-arith -Wshadow -Wvla -Wformat=2 -Wno-format-nonliteral -Wshadow -Wformat-signedness -Wlogical-op -I../tests/include/spe"
}

component_test_no_platform () {
    # Full configuration build, without platform support, file IO and net sockets.
    # This should catch missing mbedtls_printf definitions, and by disabling file
    # IO, it should catch missing '#include <stdio.h>'
    msg "build: full config except platform/fsio/net, make, gcc, C99" # ~ 30s
    scripts/config.py full_no_platform
    scripts/config.py unset MBEDTLS_PLATFORM_C
    scripts/config.py unset MBEDTLS_NET_C
    scripts/config.py unset MBEDTLS_FS_IO
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_SE_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_STORAGE_C
    scripts/config.py unset MBEDTLS_PSA_ITS_FILE_C
    scripts/config.py unset MBEDTLS_ENTROPY_NV_SEED
    # Note, _DEFAULT_SOURCE needs to be defined for platforms using glibc version >2.19,
    # to re-enable platform integration features otherwise disabled in C99 builds
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -std=c99 -pedantic -Os -D_DEFAULT_SOURCE' lib programs
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -Os' test
}

component_build_no_std_function () {
    # catch compile bugs in _uninit functions
    msg "build: full config with NO_STD_FUNCTION, make, gcc" # ~ 30s
    scripts/config.py full
    scripts/config.py set MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
    scripts/config.py unset MBEDTLS_ENTROPY_NV_SEED
    scripts/config.py unset MBEDTLS_PLATFORM_NV_SEED_ALT
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Check .
    make
}

component_build_no_ssl_srv () {
    msg "build: full config except SSL server, make, gcc" # ~ 30s
    scripts/config.py full
    scripts/config.py unset MBEDTLS_SSL_SRV_C
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -O1'
}

component_build_no_ssl_cli () {
    msg "build: full config except SSL client, make, gcc" # ~ 30s
    scripts/config.py full
    scripts/config.py unset MBEDTLS_SSL_CLI_C
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -O1'
}

component_build_no_sockets () {
    # Note, C99 compliance can also be tested with the sockets support disabled,
    # as that requires a POSIX platform (which isn't the same as C99).
    msg "build: full config except net_sockets.c, make, gcc -std=c99 -pedantic" # ~ 30s
    scripts/config.py full
    scripts/config.py unset MBEDTLS_NET_C # getaddrinfo() undeclared, etc.
    scripts/config.py set MBEDTLS_NO_PLATFORM_ENTROPY # uses syscall() on GNU/Linux
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -O1 -std=c99 -pedantic' lib
}

component_test_memory_buffer_allocator_backtrace () {
    msg "build: default config with memory buffer allocator and backtrace enabled"
    scripts/config.py set MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_PLATFORM_MEMORY
    scripts/config.py set MBEDTLS_MEMORY_BACKTRACE
    scripts/config.py set MBEDTLS_MEMORY_DEBUG
    cmake -DCMAKE_BUILD_TYPE:String=Release .
    make

    msg "test: MBEDTLS_MEMORY_BUFFER_ALLOC_C and MBEDTLS_MEMORY_BACKTRACE"
    make test
}

component_test_memory_buffer_allocator () {
    msg "build: default config with memory buffer allocator"
    scripts/config.py set MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_PLATFORM_MEMORY
    cmake -DCMAKE_BUILD_TYPE:String=Release .
    make

    msg "test: MBEDTLS_MEMORY_BUFFER_ALLOC_C"
    make test

    msg "test: ssl-opt.sh, MBEDTLS_MEMORY_BUFFER_ALLOC_C"
    # MBEDTLS_MEMORY_BUFFER_ALLOC is slow. Skip tests that tend to time out.
    tests/ssl-opt.sh -e '^DTLS proxy'
}

component_test_no_max_fragment_length () {
    # Run max fragment length tests with MFL disabled
    msg "build: default config except MFL extension (ASan build)" # ~ 30s
    scripts/config.py unset MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: ssl-opt.sh, MFL-related tests"
    tests/ssl-opt.sh -f "Max fragment length"
}

component_test_asan_remove_peer_certificate () {
    msg "build: default config with MBEDTLS_SSL_KEEP_PEER_CERTIFICATE disabled (ASan build)"
    scripts/config.py unset MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE"
    make test

    msg "test: ssl-opt.sh, !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE"
    tests/ssl-opt.sh

    msg "test: compat.sh, !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE"
    tests/compat.sh

    msg "test: context-info.sh, !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE"
    tests/context-info.sh
}

component_test_no_max_fragment_length_small_ssl_out_content_len () {
    msg "build: no MFL extension, small SSL_OUT_CONTENT_LEN (ASan build)"
    scripts/config.py unset MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
    scripts/config.py set MBEDTLS_SSL_IN_CONTENT_LEN 16384
    scripts/config.py set MBEDTLS_SSL_OUT_CONTENT_LEN 4096
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: MFL tests (disabled MFL extension case) & large packet tests"
    tests/ssl-opt.sh -f "Max fragment length\|Large buffer"

    msg "test: context-info.sh (disabled MFL extension case)"
    tests/context-info.sh
}

component_test_variable_ssl_in_out_buffer_len () {
    msg "build: MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH enabled (ASan build)"
    scripts/config.py set MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH enabled"
    make test

    msg "test: ssl-opt.sh, MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH enabled"
    tests/ssl-opt.sh

    msg "test: compat.sh, MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH enabled"
    tests/compat.sh
}

component_test_dtls_cid_legacy () {
    msg "build: MBEDTLS_SSL_DTLS_CONNECTION_ID (legacy) enabled (ASan build)"
    scripts/config.py set MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT 1

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: MBEDTLS_SSL_DTLS_CONNECTION_ID (legacy)"
    make test

    msg "test: ssl-opt.sh, MBEDTLS_SSL_DTLS_CONNECTION_ID (legacy) enabled"
    tests/ssl-opt.sh

    msg "test: compat.sh, MBEDTLS_SSL_DTLS_CONNECTION_ID (legacy) enabled"
    tests/compat.sh
}

component_test_ssl_alloc_buffer_and_mfl () {
    msg "build: default config with memory buffer allocator and MFL extension"
    scripts/config.py set MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_PLATFORM_MEMORY
    scripts/config.py set MBEDTLS_MEMORY_DEBUG
    scripts/config.py set MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
    scripts/config.py set MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH
    cmake -DCMAKE_BUILD_TYPE:String=Release .
    make

    msg "test: MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH, MBEDTLS_MEMORY_BUFFER_ALLOC_C, MBEDTLS_MEMORY_DEBUG and MBEDTLS_SSL_MAX_FRAGMENT_LENGTH"
    make test

    msg "test: MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH, MBEDTLS_MEMORY_BUFFER_ALLOC_C, MBEDTLS_MEMORY_DEBUG and MBEDTLS_SSL_MAX_FRAGMENT_LENGTH"
    tests/ssl-opt.sh -f "Handshake memory usage"
}

component_test_when_no_ciphersuites_have_mac () {
    msg "build: when no ciphersuites have MAC"
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_NO_PADDING
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_PKCS7
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CMAC
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128

    scripts/config.py unset MBEDTLS_CIPHER_NULL_CIPHER
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CBC
    scripts/config.py unset MBEDTLS_CMAC_C

    make

    msg "test: !MBEDTLS_SSL_SOME_SUITES_USE_MAC"
    make test

    msg "test ssl-opt.sh: !MBEDTLS_SSL_SOME_SUITES_USE_MAC"
    tests/ssl-opt.sh -f 'Default\|EtM' -e 'without EtM'
}

component_test_no_date_time () {
    msg "build: default config without MBEDTLS_HAVE_TIME_DATE"
    scripts/config.py unset MBEDTLS_HAVE_TIME_DATE
    cmake -D CMAKE_BUILD_TYPE:String=Check .
    make

    msg "test: !MBEDTLS_HAVE_TIME_DATE - main suites"
    make test
}

component_test_platform_calloc_macro () {
    msg "build: MBEDTLS_PLATFORM_{CALLOC/FREE}_MACRO enabled (ASan build)"
    scripts/config.py set MBEDTLS_PLATFORM_MEMORY
    scripts/config.py set MBEDTLS_PLATFORM_CALLOC_MACRO calloc
    scripts/config.py set MBEDTLS_PLATFORM_FREE_MACRO   free
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: MBEDTLS_PLATFORM_{CALLOC/FREE}_MACRO enabled (ASan build)"
    make test
}

component_test_malloc_0_null () {
    msg "build: malloc(0) returns NULL (ASan+UBSan build)"
    scripts/config.py full
    make CC=$ASAN_CC CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"$PWD/tests/configs/user-config-malloc-0-null.h\"' $ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: malloc(0) returns NULL (ASan+UBSan build)"
    make test

    msg "selftest: malloc(0) returns NULL (ASan+UBSan build)"
    # Just the calloc selftest. "make test" ran the others as part of the
    # test suites.
    programs/test/selftest calloc

    msg "test ssl-opt.sh: malloc(0) returns NULL (ASan+UBSan build)"
    # Run a subset of the tests. The choice is a balance between coverage
    # and time (including time indirectly wasted due to flaky tests).
    # The current choice is to skip tests whose description includes
    # "proxy", which is an approximation of skipping tests that use the
    # UDP proxy, which tend to be slower and flakier.
    tests/ssl-opt.sh -e 'proxy'
}

component_build_mbedtls_config_file () {
    msg "build: make with MBEDTLS_CONFIG_FILE" # ~40s
    scripts/config.py -w full_config.h full
    echo '#error "MBEDTLS_CONFIG_FILE is not working"' >"$CONFIG_H"
    make CFLAGS="-I '$PWD' -DMBEDTLS_CONFIG_FILE='\"full_config.h\"'"
    # Make sure this feature is enabled. We'll disable it in the next phase.
    programs/test/query_compile_time_config MBEDTLS_NIST_KW_C
    make clean

    msg "build: make with MBEDTLS_CONFIG_FILE + MBEDTLS_USER_CONFIG_FILE"
    # In the user config, disable one feature (for simplicity, pick a feature
    # that nothing else depends on).
    echo '#undef MBEDTLS_NIST_KW_C' >user_config.h
    make CFLAGS="-I '$PWD' -DMBEDTLS_CONFIG_FILE='\"full_config.h\"' -DMBEDTLS_USER_CONFIG_FILE='\"user_config.h\"'"
    not programs/test/query_compile_time_config MBEDTLS_NIST_KW_C

    rm -f user_config.h full_config.h
}





component_test_m32_no_asm () {
    # Build without assembly, so as to use portable C code (in a 32-bit
    # build) and not the i386-specific inline assembly.
    #
    # Note that we require gcc, because clang Asan builds fail to link for
    # this target (cannot find libclang_rt.lsan-i386.a - this is a known clang issue).
    msg "build: i386, make, gcc, no asm (ASan build)" # ~ 30s
    scripts/config.py full
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C # AESNI for 32-bit is tested in test_aesni_m32
    make CC=gcc CFLAGS="$ASAN_CFLAGS -m32" LDFLAGS="-m32 $ASAN_CFLAGS"

    msg "test: i386, make, gcc, no asm (ASan build)"
    make test
}
support_test_m32_no_asm () {
    case $(uname -m) in
        amd64|x86_64) true;;
        *) false;;
    esac
}

component_test_m32_o2 () {
    # Build with optimization, to use the i386 specific inline assembly
    # and go faster for tests.
    msg "build: i386, make, gcc -O2 (ASan build)" # ~ 30s
    scripts/config.py full
    scripts/config.py unset MBEDTLS_AESNI_C # AESNI for 32-bit is tested in test_aesni_m32
    make CC=gcc CFLAGS="$ASAN_CFLAGS -m32" LDFLAGS="-m32 $ASAN_CFLAGS"

    msg "test: i386, make, gcc -O2 (ASan build)"
    make test

    msg "test ssl-opt.sh, i386, make, gcc-O2"
    tests/ssl-opt.sh
}
support_test_m32_o2 () {
    support_test_m32_no_asm "$@"
}

component_test_m32_everest () {
    msg "build: i386, Everest ECDH context (ASan build)" # ~ 6 min
    scripts/config.py set MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED
    scripts/config.py unset MBEDTLS_AESNI_C # AESNI for 32-bit is tested in test_aesni_m32
    make CC=gcc CFLAGS="$ASAN_CFLAGS -m32" LDFLAGS="-m32 $ASAN_CFLAGS"

    msg "test: i386, Everest ECDH context - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: i386, Everest ECDH context - ECDH-related part of ssl-opt.sh (ASan build)" # ~ 5s
    tests/ssl-opt.sh -f ECDH

    msg "test: i386, Everest ECDH context - compat.sh with some ECDH ciphersuites (ASan build)" # ~ 3 min
    # Exclude some symmetric ciphers that are redundant here to gain time.
    tests/compat.sh -f ECDH -V NO -e 'ARIA\|CAMELLIA\|CHACHA'
}
support_test_m32_everest () {
    support_test_m32_no_asm "$@"
}

component_test_mx32 () {
    msg "build: 64-bit ILP32, make, gcc" # ~ 30s
    scripts/config.py full
    make CC=gcc CFLAGS='-O2 -Werror -Wall -Wextra -mx32' LDFLAGS='-mx32'

    msg "test: 64-bit ILP32, make, gcc"
    make test
}
support_test_mx32 () {
    case $(uname -m) in
        amd64|x86_64) true;;
        *) false;;
    esac
}

component_test_have_int32 () {
    msg "build: gcc, force 32-bit bignum limbs"
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C
    make CC=gcc CFLAGS='-O2 -Werror -Wall -Wextra -DMBEDTLS_HAVE_INT32'

    msg "test: gcc, force 32-bit bignum limbs"
    make test
}

component_test_have_int64 () {
    msg "build: gcc, force 64-bit bignum limbs"
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C
    make CC=gcc CFLAGS='-O2 -Werror -Wall -Wextra -DMBEDTLS_HAVE_INT64'

    msg "test: gcc, force 64-bit bignum limbs"
    make test
}

component_test_have_int32_cmake_new_bignum () {
    msg "build: gcc, force 32-bit bignum limbs, new bignum interface, test hooks (ASan build)"
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C
    scripts/config.py set MBEDTLS_TEST_HOOKS
    scripts/config.py set MBEDTLS_ECP_WITH_MPI_UINT
    make CC=gcc CFLAGS="$ASAN_CFLAGS -Werror -Wall -Wextra -DMBEDTLS_HAVE_INT32" LDFLAGS="$ASAN_CFLAGS"

    msg "test: gcc, force 32-bit bignum limbs, new bignum interface, test hooks (ASan build)"
    make test
}

component_test_no_udbl_division () {
    msg "build: MBEDTLS_NO_UDBL_DIVISION native" # ~ 10s
    scripts/config.py full
    scripts/config.py set MBEDTLS_NO_UDBL_DIVISION
    make CFLAGS='-Werror -O1'

    msg "test: MBEDTLS_NO_UDBL_DIVISION native" # ~ 10s
    make test
}

component_test_no_64bit_multiplication () {
    msg "build: MBEDTLS_NO_64BIT_MULTIPLICATION native" # ~ 10s
    scripts/config.py full
    scripts/config.py set MBEDTLS_NO_64BIT_MULTIPLICATION
    make CFLAGS='-Werror -O1'

    msg "test: MBEDTLS_NO_64BIT_MULTIPLICATION native" # ~ 10s
    make test
}

component_test_no_strings () {
    msg "build: no strings" # ~10s
    scripts/config.py full
    # Disable options that activate a large amount of string constants.
    scripts/config.py unset MBEDTLS_DEBUG_C
    scripts/config.py unset MBEDTLS_ERROR_C
    scripts/config.py set MBEDTLS_ERROR_STRERROR_DUMMY
    scripts/config.py unset MBEDTLS_VERSION_FEATURES
    make CFLAGS='-Werror -Os'

    msg "test: no strings" # ~ 10s
    make test
}

component_test_no_x509_info () {
    msg "build: full + MBEDTLS_X509_REMOVE_INFO" # ~ 10s
    scripts/config.pl full
    scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # too slow for tests
    scripts/config.pl set MBEDTLS_X509_REMOVE_INFO
    make CFLAGS='-Werror -O2'

    msg "test: full + MBEDTLS_X509_REMOVE_INFO" # ~ 10s
    make test

    msg "test: ssl-opt.sh, full + MBEDTLS_X509_REMOVE_INFO" # ~ 1 min
    tests/ssl-opt.sh
}

component_test_tls12_only () {
    msg "build: default config without MBEDTLS_SSL_PROTO_TLS1_3, cmake, gcc, ASan"
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (inc. selftests) (ASan build)"
    make test

    msg "test: ssl-opt.sh (ASan build)"
    tests/ssl-opt.sh

    msg "test: compat.sh (ASan build)"
    tests/compat.sh
}

component_test_tls13_only () {
    msg "build: default config without MBEDTLS_SSL_PROTO_TLS1_2"
    scripts/config.py set MBEDTLS_SSL_EARLY_DATA
    scripts/config.py set MBEDTLS_SSL_RECORD_SIZE_LIMIT
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test: TLS 1.3 only, all key exchange modes enabled"
    make test

    msg "ssl-opt.sh: TLS 1.3 only, all key exchange modes enabled"
    tests/ssl-opt.sh
}

component_test_tls13_only_psk () {
    msg "build: TLS 1.3 only from default, only PSK key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_ECDH_C
    scripts/config.py unset MBEDTLS_DHM_C
    scripts/config.py unset MBEDTLS_X509_CRT_PARSE_C
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT
    scripts/config.py unset MBEDTLS_SSL_SERVER_NAME_INDICATION
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_PKCS1_V21
    scripts/config.py unset MBEDTLS_PKCS7_C
    scripts/config.py set   MBEDTLS_SSL_EARLY_DATA
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, only PSK key exchange mode enabled"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, only PSK key exchange mode enabled"
    tests/ssl-opt.sh
}

component_test_tls13_only_ephemeral () {
    msg "build: TLS 1.3 only from default, only ephemeral key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_SSL_EARLY_DATA
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, only ephemeral key exchange mode"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, only ephemeral key exchange mode"
    tests/ssl-opt.sh
}

component_test_tls13_only_ephemeral_ffdh () {
    msg "build: TLS 1.3 only from default, only ephemeral ffdh key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_SSL_EARLY_DATA
    scripts/config.py unset MBEDTLS_ECDH_C

    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, only ephemeral ffdh key exchange mode"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, only ephemeral ffdh key exchange mode"
    tests/ssl-opt.sh
}

component_test_tls13_only_psk_ephemeral () {
    msg "build: TLS 1.3 only from default, only PSK ephemeral key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_X509_CRT_PARSE_C
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT
    scripts/config.py unset MBEDTLS_SSL_SERVER_NAME_INDICATION
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_PKCS1_V21
    scripts/config.py unset MBEDTLS_PKCS7_C
    scripts/config.py set   MBEDTLS_SSL_EARLY_DATA
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, only PSK ephemeral key exchange mode"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, only PSK ephemeral key exchange mode"
    tests/ssl-opt.sh
}

component_test_tls13_only_psk_ephemeral_ffdh () {
    msg "build: TLS 1.3 only from default, only PSK ephemeral ffdh key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_X509_CRT_PARSE_C
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT
    scripts/config.py unset MBEDTLS_SSL_SERVER_NAME_INDICATION
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_PKCS1_V21
    scripts/config.py unset MBEDTLS_PKCS7_C
    scripts/config.py set   MBEDTLS_SSL_EARLY_DATA
    scripts/config.py unset MBEDTLS_ECDH_C
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, only PSK ephemeral ffdh key exchange mode"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, only PSK ephemeral ffdh key exchange mode"
    tests/ssl-opt.sh
}

component_test_tls13_only_psk_all () {
    msg "build: TLS 1.3 only from default, without ephemeral key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_X509_CRT_PARSE_C
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT
    scripts/config.py unset MBEDTLS_SSL_SERVER_NAME_INDICATION
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_PKCS1_V21
    scripts/config.py unset MBEDTLS_PKCS7_C
    scripts/config.py set   MBEDTLS_SSL_EARLY_DATA
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, PSK and PSK ephemeral key exchange modes"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, PSK and PSK ephemeral key exchange modes"
    tests/ssl-opt.sh
}

component_test_tls13_only_ephemeral_all () {
    msg "build: TLS 1.3 only from default, without PSK key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
    scripts/config.py set   MBEDTLS_SSL_EARLY_DATA
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, ephemeral and PSK ephemeral key exchange modes"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, ephemeral and PSK ephemeral key exchange modes"
    tests/ssl-opt.sh
}

component_test_tls13_no_padding () {
    msg "build: default config plus early data minus padding"
    scripts/config.py set MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY 1
    scripts/config.py set MBEDTLS_SSL_EARLY_DATA
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make
    msg "test: default config plus early data minus padding"
    make test
    msg "ssl-opt.sh (TLS 1.3 no padding)"
    tests/ssl-opt.sh
}

component_test_tls13_no_compatibility_mode () {
    msg "build: default config plus early data minus middlebox compatibility mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
    scripts/config.py set   MBEDTLS_SSL_EARLY_DATA
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make
    msg "test: default config plus early data minus middlebox compatibility mode"
    make test
    msg "ssl-opt.sh (TLS 1.3 no compatibility mode)"
    tests/ssl-opt.sh
}

component_test_full_minus_session_tickets() {
    msg "build: full config without session tickets"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_SSL_SESSION_TICKETS
    scripts/config.py unset MBEDTLS_SSL_EARLY_DATA
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make
    msg "test: full config without session tickets"
    make test
    msg "ssl-opt.sh (full config without session tickets)"
    tests/ssl-opt.sh
}

component_test_memsan () {
    msg "build: MSan (clang)" # ~ 1 min 20s
    scripts/config.py unset MBEDTLS_AESNI_C # memsan doesn't grok asm
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=MemSan .
    make

    msg "test: main suites (MSan)" # ~ 10s
    make test

    msg "test: metatests (MSan)"
    tests/scripts/run-metatests.sh any msan

    msg "program demos (MSan)" # ~20s
    tests/scripts/run_demos.py

    msg "test: ssl-opt.sh (MSan)" # ~ 1 min
    tests/ssl-opt.sh

    # Optional part(s)

    if [ "$MEMORY" -gt 0 ]; then
        msg "test: compat.sh (MSan)" # ~ 6 min 20s
        tests/compat.sh
    fi
}

component_release_test_valgrind () {
    msg "build: Release (clang)"
    # default config, in particular without MBEDTLS_USE_PSA_CRYPTO
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=Release .
    make

    msg "test: main suites, Valgrind (default config)"
    make memcheck

    # Optional parts (slow; currently broken on OS X because programs don't
    # seem to receive signals under valgrind on OS X).
    # These optional parts don't run on the CI.
    if [ "$MEMORY" -gt 0 ]; then
        msg "test: ssl-opt.sh --memcheck (default config)"
        tests/ssl-opt.sh --memcheck
    fi

    if [ "$MEMORY" -gt 1 ]; then
        msg "test: compat.sh --memcheck (default config)"
        tests/compat.sh --memcheck
    fi

    if [ "$MEMORY" -gt 0 ]; then
        msg "test: context-info.sh --memcheck (default config)"
        tests/context-info.sh --memcheck
    fi
}

component_release_test_valgrind_psa () {
    msg "build: Release, full (clang)"
    # full config, in particular with MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py full
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=Release .
    make

    msg "test: main suites, Valgrind (full config)"
    make memcheck
}

component_build_zeroize_checks () {
    msg "build: check for obviously wrong calls to mbedtls_platform_zeroize()"

    scripts/config.py full

    # Only compile - we're looking for sizeof-pointer-memaccess warnings
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/user-config-zeroize-memset.h\"' -DMBEDTLS_TEST_DEFINES_ZEROIZE -Werror -Wsizeof-pointer-memaccess"
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
