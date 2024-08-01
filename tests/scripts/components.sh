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

