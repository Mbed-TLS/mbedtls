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

# Get a list of library-wise undefined symbols and ensure that they only
# belong to psa_xxx() functions and not to mbedtls_yyy() ones.
# This function is a common helper used by both:
# - component_test_default_psa_crypto_client_without_crypto_provider
# - component_build_full_psa_crypto_client_without_crypto_provider.
common_check_mbedtls_missing_symbols () {
    nm library/libmbedcrypto.a | grep ' [TRrDC] ' | grep -Eo '(mbedtls_|psa_).*' | sort -u > sym_def.txt
    nm library/libmbedcrypto.a | grep ' U ' | grep -Eo '(mbedtls_|psa_).*' | sort -u > sym_undef.txt
    comm sym_def.txt sym_undef.txt -13 > linking_errors.txt
    not grep mbedtls_ linking_errors.txt

    rm sym_def.txt sym_undef.txt linking_errors.txt
}

component_test_default_psa_crypto_client_without_crypto_provider () {
    msg "build: default config - PSA_CRYPTO_C + PSA_CRYPTO_CLIENT"

    scripts/config.py unset MBEDTLS_PSA_CRYPTO_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_STORAGE_C
    scripts/config.py unset MBEDTLS_PSA_ITS_FILE_C
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CLIENT
    scripts/config.py unset MBEDTLS_LMS_C

    make

    msg "check missing symbols: default config - PSA_CRYPTO_C + PSA_CRYPTO_CLIENT"
    common_check_mbedtls_missing_symbols

    msg "test: default config - PSA_CRYPTO_C + PSA_CRYPTO_CLIENT"
    make test
}

component_build_full_psa_crypto_client_without_crypto_provider () {
    msg "build: full config - PSA_CRYPTO_C"

    # Use full config which includes USE_PSA and CRYPTO_CLIENT.
    scripts/config.py full

    scripts/config.py unset MBEDTLS_PSA_CRYPTO_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_STORAGE_C
    # Dynamic secure element support is a deprecated feature and it is not
    # available when CRYPTO_C and PSA_CRYPTO_STORAGE_C are disabled.
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_SE_C

    # Since there is no crypto provider in this build it is not possible to
    # build all the test executables and progrems due to missing PSA functions
    # at link time. Therefore we will just build libraries and we'll check
    # that symbols of interest are there.
    make lib

    msg "check missing symbols: full config - PSA_CRYPTO_C"

    common_check_mbedtls_missing_symbols

    # Ensure that desired functions are included into the build (extend the
    # following list as required).
    grep mbedtls_pk_get_psa_attributes library/libmbedcrypto.a
    grep mbedtls_pk_import_into_psa library/libmbedcrypto.a
    grep mbedtls_pk_copy_from_psa library/libmbedcrypto.a
}

component_test_psa_crypto_rsa_no_genprime () {
    msg "build: default config minus MBEDTLS_GENPRIME"
    scripts/config.py unset MBEDTLS_GENPRIME
    make

    msg "test: default config minus MBEDTLS_GENPRIME"
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
    tests/scripts/test-ref-configs.pl
}

component_test_full_no_cipher_no_psa_crypto () {
    msg "build: full no CIPHER no PSA_CRYPTO_C"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_CIPHER_C
    # Don't pull in cipher via PSA mechanisms
    # (currently ignored anyway because we completely disable PSA)
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_CONFIG
    # Disable features that depend on CIPHER_C
    scripts/config.py unset MBEDTLS_CMAC_C
    scripts/config.py unset MBEDTLS_NIST_KW_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_CLIENT
    scripts/config.py unset MBEDTLS_SSL_TLS_C
    scripts/config.py unset MBEDTLS_SSL_TICKET_C
    # Disable features that depend on PSA_CRYPTO_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_SE_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_STORAGE_C
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_LMS_C
    scripts/config.py unset MBEDTLS_LMS_PRIVATE

    msg "test: full no CIPHER no PSA_CRYPTO_C"
    make test
}

# This is a common configurator and test function that is used in:
# - component_test_full_no_cipher_with_psa_crypto
# - component_test_full_no_cipher_with_psa_crypto_config
# It accepts 2 input parameters:
# - $1: boolean value which basically reflects status of MBEDTLS_PSA_CRYPTO_CONFIG
# - $2: a text string which describes the test component
common_test_full_no_cipher_with_psa_crypto () {
    USE_CRYPTO_CONFIG="$1"
    COMPONENT_DESCRIPTION="$2"

    msg "build: $COMPONENT_DESCRIPTION"

    scripts/config.py full
    scripts/config.py unset MBEDTLS_CIPHER_C

    if [ "$USE_CRYPTO_CONFIG" -eq 1 ]; then
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
    else
        # Don't pull in cipher via PSA mechanisms
        scripts/config.py unset MBEDTLS_PSA_CRYPTO_CONFIG
        # Disable cipher modes/keys that make PSA depend on CIPHER_C.
        # Keep CHACHA20 and CHACHAPOLY enabled since they do not depend on CIPHER_C.
        scripts/config.py unset-all MBEDTLS_CIPHER_MODE
    fi
    # The following modules directly depends on CIPHER_C
    scripts/config.py unset MBEDTLS_CMAC_C
    scripts/config.py unset MBEDTLS_NIST_KW_C

    make

    # Ensure that CIPHER_C was not re-enabled
    not grep mbedtls_cipher_init library/cipher.o

    msg "test: $COMPONENT_DESCRIPTION"
    make test
}

component_test_full_no_cipher_with_psa_crypto () {
    common_test_full_no_cipher_with_psa_crypto 0 "full no CIPHER no CRYPTO_CONFIG"
}

component_test_full_no_cipher_with_psa_crypto_config () {
    common_test_full_no_cipher_with_psa_crypto 1 "full no CIPHER"
}

component_test_full_no_bignum () {
    msg "build: full minus bignum"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_BIGNUM_C
    # Direct dependencies of bignum
    scripts/config.py unset MBEDTLS_ECP_C
    scripts/config.py unset MBEDTLS_RSA_C
    scripts/config.py unset MBEDTLS_DHM_C
    # Direct dependencies of ECP
    scripts/config.py unset MBEDTLS_ECDH_C
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_ECJPAKE_C
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE
    # Disable what auto-enables ECP_LIGHT
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_EXTENDED
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_COMPRESSED
    # Indirect dependencies of ECP
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
    # Direct dependencies of DHM
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
    # Direct dependencies of RSA
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT
    # PK and its dependencies
    scripts/config.py unset MBEDTLS_PK_C
    scripts/config.py unset MBEDTLS_PK_PARSE_C
    scripts/config.py unset MBEDTLS_PK_WRITE_C
    scripts/config.py unset MBEDTLS_X509_USE_C
    scripts/config.py unset MBEDTLS_X509_CRT_PARSE_C
    scripts/config.py unset MBEDTLS_X509_CRL_PARSE_C
    scripts/config.py unset MBEDTLS_X509_CSR_PARSE_C
    scripts/config.py unset MBEDTLS_X509_CREATE_C
    scripts/config.py unset MBEDTLS_X509_CRT_WRITE_C
    scripts/config.py unset MBEDTLS_X509_CSR_WRITE_C
    scripts/config.py unset MBEDTLS_PKCS7_C
    scripts/config.py unset MBEDTLS_SSL_SERVER_NAME_INDICATION
    scripts/config.py unset MBEDTLS_SSL_ASYNC_PRIVATE
    scripts/config.py unset MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK

    make

    msg "test: full minus bignum"
    make test
}



component_test_tls1_2_default_stream_cipher_only_use_psa () {
    msg "build: default with only stream cipher use psa"

    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    # Disable AEAD (controlled by the presence of one of GCM_C, CCM_C, CHACHAPOLY_C)
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py unset MBEDTLS_CCM_C
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    #Disable TLS 1.3 (as no AEAD)
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    # Disable CBC-legacy (controlled by MBEDTLS_CIPHER_MODE_CBC plus at least one block cipher (AES, ARIA, Camellia, DES))
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



component_test_tls1_2_deafult_cbc_legacy_cipher_only_use_psa () {
    msg "build: default with only CBC-legacy cipher use psa"

    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    # Disable AEAD (controlled by the presence of one of GCM_C, CCM_C, CHACHAPOLY_C)
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py unset MBEDTLS_CCM_C
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    #Disable TLS 1.3 (as no AEAD)
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    # Enable CBC-legacy (controlled by MBEDTLS_CIPHER_MODE_CBC plus at least one block cipher (AES, ARIA, Camellia, DES))
    scripts/config.py set MBEDTLS_CIPHER_MODE_CBC
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

component_test_tls1_2_default_cbc_legacy_cbc_etm_cipher_only_use_psa () {
    msg "build: default with only CBC-legacy and CBC-EtM ciphers use psa"

    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    # Disable AEAD (controlled by the presence of one of GCM_C, CCM_C, CHACHAPOLY_C)
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py unset MBEDTLS_CCM_C
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    #Disable TLS 1.3 (as no AEAD)
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    # Enable CBC-legacy (controlled by MBEDTLS_CIPHER_MODE_CBC plus at least one block cipher (AES, ARIA, Camellia, DES))
    scripts/config.py set MBEDTLS_CIPHER_MODE_CBC
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
            tr '\n' ,)
    export SKIP_TEST_SUITES
}

skip_all_except_given_suite () {
    # Skip all but the given test suite
    SKIP_TEST_SUITES=$(
        ls -1 tests/suites/test_suite_*.function |
        grep -v $1.function |
         sed 's/tests.suites.test_suite_//; s/\.function$//' |
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

component_build_dhm_alt () {
    msg "build: MBEDTLS_DHM_ALT" # ~30s
    scripts/config.py full
    scripts/config.py set MBEDTLS_DHM_ALT
    # debug.c currently references mbedtls_dhm_context fields directly.
    scripts/config.py unset MBEDTLS_DEBUG_C
    # We can only compile, not link, since we don't have any implementations
    # suitable for testing with the dummy alt headers.
    make CFLAGS='-Werror -Wall -Wextra -I../tests/include/alt-dummy' lib
}

component_test_no_psa_crypto_full_cmake_asan () {
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

component_build_tfm () {
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

support_test_aesni () {
    # Check that gcc targets x86_64 (we can build AESNI), and check for
    # AESNI support on the host (we can run AESNI).
    #
    # The name of this function is possibly slightly misleading, but needs to align
    # with the name of the corresponding test, component_test_aesni.
    #
    # In principle 32-bit x86 can support AESNI, but our implementation does not
    # support 32-bit x86, so we check for x86-64.
    # We can only grep /proc/cpuinfo on Linux, so this also checks for Linux
    (gcc -v 2>&1 | grep Target | grep -q x86_64) &&
        [[ "$HOSTTYPE" == "x86_64" && "$OSTYPE" == "linux-gnu" ]] &&
        (lscpu | grep -qw aes)
}

component_test_aesni () { # ~ 60s
    # This tests the two AESNI implementations (intrinsics and assembly), and also the plain C
    # fallback. It also tests the logic that is used to select which implementation(s) to build.
    #
    # This test does not require the host to have support for AESNI (if it doesn't, the run-time
    # AESNI detection will fallback to the plain C implementation, so the tests will instead
    # exercise the plain C impl).

    msg "build: default config with different AES implementations"
    scripts/config.py set MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    scripts/config.py set MBEDTLS_HAVE_ASM

    # test the intrinsics implementation
    msg "AES tests, test intrinsics"
    make clean
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -mpclmul -msse2 -maes'
    # check that we built intrinsics - this should be used by default when supported by the compiler
    ./programs/test/selftest aes | grep "AESNI code" | grep -q "intrinsics"

    # test the asm implementation
    msg "AES tests, test assembly"
    make clean
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -mno-pclmul -mno-sse2 -mno-aes'
    # check that we built assembly - this should be built if the compiler does not support intrinsics
    ./programs/test/selftest aes | grep "AESNI code" | grep -q "assembly"

    # test the plain C implementation
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    msg "AES tests, plain C"
    make clean
    make CC=gcc CFLAGS='-O2 -Werror'
    # check that there is no AESNI code present
    ./programs/test/selftest aes | not grep -q "AESNI code"
    not grep -q "AES note: using AESNI" ./programs/test/selftest
    grep -q "AES note: built-in implementation." ./programs/test/selftest

    # test the intrinsics implementation
    scripts/config.py set MBEDTLS_AESNI_C
    scripts/config.py set MBEDTLS_AES_USE_HARDWARE_ONLY
    msg "AES tests, test AESNI only"
    make clean
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -mpclmul -msse2 -maes'
    ./programs/test/selftest aes | grep -q "AES note: using AESNI"
    ./programs/test/selftest aes | not grep -q "AES note: built-in implementation."
    grep -q "AES note: using AESNI" ./programs/test/selftest
    not grep -q "AES note: built-in implementation." ./programs/test/selftest
}

support_test_aesni_m32 () {
    support_test_m32_no_asm && (lscpu | grep -qw aes)
}

component_test_aesni_m32 () { # ~ 60s
    # This tests are duplicated from component_test_aesni for i386 target
    #
    # AESNI intrinsic code supports i386 and assembly code does not support it.

    msg "build: default config with different AES implementations"
    scripts/config.py set MBEDTLS_AESNI_C
    scripts/config.py set MBEDTLS_PADLOCK_C
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    scripts/config.py set MBEDTLS_HAVE_ASM

    # test the intrinsics implementation with gcc
    msg "AES tests, test intrinsics (gcc)"
    make clean
    make CC=gcc CFLAGS='-m32 -Werror -Wall -Wextra' LDFLAGS='-m32'
    # check that we built intrinsics - this should be used by default when supported by the compiler
    ./programs/test/selftest aes | grep "AESNI code" | grep -q "intrinsics"
    grep -q "AES note: using AESNI" ./programs/test/selftest
    grep -q "AES note: built-in implementation." ./programs/test/selftest
    grep -q "AES note: using VIA Padlock" ./programs/test/selftest
    grep -q mbedtls_aesni_has_support ./programs/test/selftest

    scripts/config.py set MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_PADLOCK_C
    scripts/config.py set MBEDTLS_AES_USE_HARDWARE_ONLY
    msg "AES tests, test AESNI only"
    make clean
    make CC=gcc CFLAGS='-m32 -Werror -Wall -Wextra -mpclmul -msse2 -maes' LDFLAGS='-m32'
    ./programs/test/selftest aes | grep -q "AES note: using AESNI"
    ./programs/test/selftest aes | not grep -q "AES note: built-in implementation."
    grep -q "AES note: using AESNI" ./programs/test/selftest
    not grep -q "AES note: built-in implementation." ./programs/test/selftest
    not grep -q "AES note: using VIA Padlock" ./programs/test/selftest
    not grep -q mbedtls_aesni_has_support ./programs/test/selftest
}

support_test_aesni_m32_clang () {
    # clang >= 4 is required to build with target attributes
    support_test_aesni_m32 && [[ $(clang_version) -ge 4 ]]
}

component_test_aesni_m32_clang () {

    scripts/config.py set MBEDTLS_AESNI_C
    scripts/config.py set MBEDTLS_PADLOCK_C
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    scripts/config.py set MBEDTLS_HAVE_ASM

    # test the intrinsics implementation with clang
    msg "AES tests, test intrinsics (clang)"
    make clean
    make CC=clang CFLAGS='-m32 -Werror -Wall -Wextra' LDFLAGS='-m32'
    # check that we built intrinsics - this should be used by default when supported by the compiler
    ./programs/test/selftest aes | grep "AESNI code" | grep -q "intrinsics"
    grep -q "AES note: using AESNI" ./programs/test/selftest
    grep -q "AES note: built-in implementation." ./programs/test/selftest
    grep -q "AES note: using VIA Padlock" ./programs/test/selftest
    grep -q mbedtls_aesni_has_support ./programs/test/selftest
}

support_build_aes_armce () {
    # clang >= 11 is required to build with AES extensions
    [[ $(clang_version) -ge 11 ]]
}

component_build_aes_armce () {
    # Test variations of AES with Armv8 crypto extensions
    scripts/config.py set MBEDTLS_AESCE_C
    scripts/config.py set MBEDTLS_AES_USE_HARDWARE_ONLY

    msg "MBEDTLS_AES_USE_HARDWARE_ONLY, clang, aarch64"
    make -B library/aesce.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a+crypto"

    msg "MBEDTLS_AES_USE_HARDWARE_ONLY, clang, arm"
    make -B library/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm"

    msg "MBEDTLS_AES_USE_HARDWARE_ONLY, clang, thumb"
    make -B library/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb"

    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY

    msg "no MBEDTLS_AES_USE_HARDWARE_ONLY, clang, aarch64"
    make -B library/aesce.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a+crypto"

    msg "no MBEDTLS_AES_USE_HARDWARE_ONLY, clang, arm"
    make -B library/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm"

    msg "no MBEDTLS_AES_USE_HARDWARE_ONLY, clang, thumb"
    make -B library/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb"

    # test for presence of AES instructions
    scripts/config.py set MBEDTLS_AES_USE_HARDWARE_ONLY
    msg "clang, test A32 crypto instructions built"
    make -B library/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm -S"
    grep -E 'aes[0-9a-z]+.[0-9]\s*[qv]' library/aesce.o
    msg "clang, test T32 crypto instructions built"
    make -B library/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb -S"
    grep -E 'aes[0-9a-z]+.[0-9]\s*[qv]' library/aesce.o
    msg "clang, test aarch64 crypto instructions built"
    make -B library/aesce.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a -S"
    grep -E 'aes[a-z]+\s*[qv]' library/aesce.o

    # test for absence of AES instructions
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    scripts/config.py unset MBEDTLS_AESCE_C
    msg "clang, test A32 crypto instructions not built"
    make -B library/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm -S"
    not grep -E 'aes[0-9a-z]+.[0-9]\s*[qv]' library/aesce.o
    msg "clang, test T32 crypto instructions not built"
    make -B library/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb -S"
    not grep -E 'aes[0-9a-z]+.[0-9]\s*[qv]' library/aesce.o
    msg "clang, test aarch64 crypto instructions not built"
    make -B library/aesce.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a -S"
    not grep -E 'aes[a-z]+\s*[qv]' library/aesce.o
}

support_build_sha_armce () {
    # clang >= 4 is required to build with SHA extensions
    [[ $(clang_version) -ge 4 ]]
}

component_build_sha_armce () {
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT


    # Test variations of SHA256 Armv8 crypto extensions
    scripts/config.py set MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY
        msg "MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY clang, aarch64"
        make -B library/sha256.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a"
        msg "MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY clang, arm"
        make -B library/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm"
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY


    # test the deprecated form of the config option
    scripts/config.py set MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY
        msg "MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY clang, thumb"
        make -B library/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb"
    scripts/config.py unset MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY

    scripts/config.py set MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
        msg "MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT clang, aarch64"
        make -B library/sha256.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a"
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT


    # test the deprecated form of the config option
    scripts/config.py set MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT
        msg "MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT clang, arm"
        make -B library/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm -std=c99"
        msg "MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT clang, thumb"
        make -B library/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb"
    scripts/config.py unset MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT


    # examine the disassembly for presence of SHA instructions
    for opt in MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT; do
        scripts/config.py set ${opt}
            msg "${opt} clang, test A32 crypto instructions built"
            make -B library/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm -S"
            grep -E 'sha256[a-z0-9]+.32\s+[qv]' library/sha256.o

            msg "${opt} clang, test T32 crypto instructions built"
            make -B library/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb -S"
            grep -E 'sha256[a-z0-9]+.32\s+[qv]' library/sha256.o

            msg "${opt} clang, test aarch64 crypto instructions built"
            make -B library/sha256.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a -S"
            grep -E 'sha256[a-z0-9]+\s+[qv]' library/sha256.o
        scripts/config.py unset ${opt}
    done


    # examine the disassembly for absence of SHA instructions
    msg "clang, test A32 crypto instructions not built"
    make -B library/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm -S"
    not grep -E 'sha256[a-z0-9]+.32\s+[qv]' library/sha256.o

    msg "clang, test T32 crypto instructions not built"
    make -B library/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb -S"
    not grep -E 'sha256[a-z0-9]+.32\s+[qv]' library/sha256.o

    msg "clang, test aarch64 crypto instructions not built"
    make -B library/sha256.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a -S"
    not grep -E 'sha256[a-z0-9]+\s+[qv]' library/sha256.o
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
    scripts/config.py unset MBEDTLS_PADLOCK_C
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

component_build_arm_none_eabi_gcc () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc -O1, baremetal+debug" # ~ 10s
    scripts/config.py baremetal
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" LD="${ARM_NONE_EABI_GCC_PREFIX}ld" CFLAGS='-std=c99 -Werror -Wall -Wextra -O1' lib

    msg "size: ${ARM_NONE_EABI_GCC_PREFIX}gcc -O1, baremetal+debug"
    ${ARM_NONE_EABI_GCC_PREFIX}size -t library/*.o
}

component_build_arm_linux_gnueabi_gcc_arm5vte () {
    msg "build: ${ARM_LINUX_GNUEABI_GCC_PREFIX}gcc -march=arm5vte, baremetal+debug" # ~ 10s
    scripts/config.py baremetal
    # Build for a target platform that's close to what Debian uses
    # for its "armel" distribution (https://wiki.debian.org/ArmEabiPort).
    # See https://github.com/Mbed-TLS/mbedtls/pull/2169 and comments.
    # Build everything including programs, see for example
    # https://github.com/Mbed-TLS/mbedtls/pull/3449#issuecomment-675313720
    make CC="${ARM_LINUX_GNUEABI_GCC_PREFIX}gcc" AR="${ARM_LINUX_GNUEABI_GCC_PREFIX}ar" CFLAGS='-Werror -Wall -Wextra -march=armv5te -O1' LDFLAGS='-march=armv5te'

    msg "size: ${ARM_LINUX_GNUEABI_GCC_PREFIX}gcc -march=armv5te -O1, baremetal+debug"
    ${ARM_LINUX_GNUEABI_GCC_PREFIX}size -t library/*.o
}
support_build_arm_linux_gnueabi_gcc_arm5vte () {
    type ${ARM_LINUX_GNUEABI_GCC_PREFIX}gcc >/dev/null 2>&1
}

component_build_arm_none_eabi_gcc_arm5vte () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc -march=arm5vte, baremetal+debug" # ~ 10s
    scripts/config.py baremetal
    # This is an imperfect substitute for
    # component_build_arm_linux_gnueabi_gcc_arm5vte
    # in case the gcc-arm-linux-gnueabi toolchain is not available
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" CFLAGS='-std=c99 -Werror -Wall -Wextra -march=armv5te -O1' LDFLAGS='-march=armv5te' SHELL='sh -x' lib

    msg "size: ${ARM_NONE_EABI_GCC_PREFIX}gcc -march=armv5te -O1, baremetal+debug"
    ${ARM_NONE_EABI_GCC_PREFIX}size -t library/*.o
}

component_build_arm_none_eabi_gcc_m0plus () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc -mthumb -mcpu=cortex-m0plus, baremetal_size" # ~ 10s
    scripts/config.py baremetal_size
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" LD="${ARM_NONE_EABI_GCC_PREFIX}ld" CFLAGS='-std=c99 -Werror -Wall -Wextra -mthumb -mcpu=cortex-m0plus -Os' lib

    msg "size: ${ARM_NONE_EABI_GCC_PREFIX}gcc -mthumb -mcpu=cortex-m0plus -Os, baremetal_size"
    ${ARM_NONE_EABI_GCC_PREFIX}size -t library/*.o
    for lib in library/*.a; do
        echo "$lib:"
        ${ARM_NONE_EABI_GCC_PREFIX}size -t $lib | grep TOTALS
    done
}

component_build_arm_none_eabi_gcc_no_udbl_division () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc -DMBEDTLS_NO_UDBL_DIVISION, make" # ~ 10s
    scripts/config.py baremetal
    scripts/config.py set MBEDTLS_NO_UDBL_DIVISION
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" LD="${ARM_NONE_EABI_GCC_PREFIX}ld" CFLAGS='-std=c99 -Werror -Wall -Wextra' lib
    echo "Checking that software 64-bit division is not required"
    not grep __aeabi_uldiv library/*.o
}

component_build_arm_none_eabi_gcc_no_64bit_multiplication () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc MBEDTLS_NO_64BIT_MULTIPLICATION, make" # ~ 10s
    scripts/config.py baremetal
    scripts/config.py set MBEDTLS_NO_64BIT_MULTIPLICATION
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" LD="${ARM_NONE_EABI_GCC_PREFIX}ld" CFLAGS='-std=c99 -Werror -O1 -march=armv6-m -mthumb' lib
    echo "Checking that software 64-bit multiplication is not required"
    not grep __aeabi_lmul library/*.o
}

component_build_arm_clang_thumb () {
    # ~ 30s

    scripts/config.py baremetal

    msg "build: clang thumb 2, make"
    make clean
    make CC="clang" CFLAGS='-std=c99 -Werror -Os --target=arm-linux-gnueabihf -march=armv7-m -mthumb' lib

    # Some Thumb 1 asm is sensitive to optimisation level, so test both -O0 and -Os
    msg "build: clang thumb 1 -O0, make"
    make clean
    make CC="clang" CFLAGS='-std=c99 -Werror -O0 --target=arm-linux-gnueabihf -mcpu=arm1136j-s -mthumb' lib

    msg "build: clang thumb 1 -Os, make"
    make clean
    make CC="clang" CFLAGS='-std=c99 -Werror -Os --target=arm-linux-gnueabihf -mcpu=arm1136j-s -mthumb' lib
}

component_build_armcc () {
    msg "build: ARM Compiler 5"
    scripts/config.py baremetal
    # armc[56] don't support SHA-512 intrinsics
    scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT

    # older versions of armcc/armclang don't support AESCE_C on 32-bit Arm
    scripts/config.py unset MBEDTLS_AESCE_C

    # Stop armclang warning about feature detection for A64_CRYPTO.
    # With this enabled, the library does build correctly under armclang,
    # but in baremetal builds (as tested here), feature detection is
    # unavailable, and the user is notified via a #warning. So enabling
    # this feature would prevent us from building with -Werror on
    # armclang. Tracked in #7198.
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT

    scripts/config.py set MBEDTLS_HAVE_ASM

    make CC="$ARMC5_CC" AR="$ARMC5_AR" WARNING_CFLAGS='--strict --c99' lib

    msg "size: ARM Compiler 5"
    "$ARMC5_FROMELF" -z library/*.o

    # Compile mostly with -O1 since some Arm inline assembly is disabled for -O0.

    # ARM Compiler 6 - Target ARMv7-A
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv7-a"

    # ARM Compiler 6 - Target ARMv7-M
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv7-m"

    # ARM Compiler 6 - Target ARMv7-M+DSP
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv7-m+dsp"

    # ARM Compiler 6 - Target ARMv8-A - AArch32
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv8.2-a"

    # ARM Compiler 6 - Target ARMv8-M
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv8-m.main"

    # ARM Compiler 6 - Target Cortex-M0 - no optimisation
    armc6_build_test "-O0 --target=arm-arm-none-eabi -mcpu=cortex-m0"

    # ARM Compiler 6 - Target Cortex-M0
    armc6_build_test "-Os --target=arm-arm-none-eabi -mcpu=cortex-m0"

    # ARM Compiler 6 - Target ARMv8.2-A - AArch64
    #
    # Re-enable MBEDTLS_AESCE_C as this should be supported by the version of armclang
    # that we have in our CI
    scripts/config.py set MBEDTLS_AESCE_C
    armc6_build_test "-O1 --target=aarch64-arm-none-eabi -march=armv8.2-a+crypto"
}

support_build_armcc () {
    armc5_cc="$ARMC5_BIN_DIR/armcc"
    armc6_cc="$ARMC6_BIN_DIR/armclang"
    (check_tools "$armc5_cc" "$armc6_cc" > /dev/null 2>&1)
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


