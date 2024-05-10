# components-configuration-crypto.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains the test components that are executed by all.sh

################################################################
#### Configuration Testing - Crypto
################################################################

component_test_psa_crypto_key_id_encodes_owner () {
    msg "build: full config + PSA_CRYPTO_KEY_ID_ENCODES_OWNER, cmake, gcc, ASan"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full config - USE_PSA_CRYPTO + PSA_CRYPTO_KEY_ID_ENCODES_OWNER, cmake, gcc, ASan"
    make test
}

component_test_psa_assume_exclusive_buffers () {
    msg "build: full config + MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS, cmake, gcc, ASan"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full config + MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS, cmake, gcc, ASan"
    make test
}

# check_renamed_symbols HEADER LIB
# Check that if HEADER contains '#define MACRO ...' then MACRO is not a symbol
# name is LIB.
check_renamed_symbols () {
    ! nm "$2" | sed 's/.* //' |
      grep -x -F "$(sed -n 's/^ *# *define  *\([A-Z_a-z][0-9A-Z_a-z]*\)..*/\1/p' "$1")"
}

component_build_psa_crypto_spm () {
    msg "build: full config + PSA_CRYPTO_KEY_ID_ENCODES_OWNER + PSA_CRYPTO_SPM, make, gcc"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
    scripts/config.py set MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
    scripts/config.py set MBEDTLS_PSA_CRYPTO_SPM
    # We can only compile, not link, since our test and sample programs
    # aren't equipped for the modified names used when MBEDTLS_PSA_CRYPTO_SPM
    # is active.
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -I../tests/include/spe' lib

    # Check that if a symbol is renamed by crypto_spe.h, the non-renamed
    # version is not present.
    echo "Checking for renamed symbols in the library"
    check_renamed_symbols tests/include/spe/crypto_spe.h library/libmbedcrypto.a
}

# Get a list of library-wise undefined symbols and ensure that they only
# belong to psa_xxx() functions and not to mbedtls_yyy() ones.
# This function is a common helper used by both:
# - component_test_default_psa_crypto_client_without_crypto_provider
# - component_build_full_psa_crypto_client_without_crypto_provider.
common_check_mbedtls_missing_symbols() {
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

component_test_psa_crypto_rsa_no_genprime() {
    msg "build: default config minus MBEDTLS_GENPRIME"
    scripts/config.py unset MBEDTLS_GENPRIME
    make

    msg "test: default config minus MBEDTLS_GENPRIME"
    make test
}

component_test_psa_external_rng_use_psa_crypto () {
    msg "build: full + PSA_CRYPTO_EXTERNAL_RNG + USE_PSA_CRYPTO minus CTR_DRBG"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_CTR_DRBG_C
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full + PSA_CRYPTO_EXTERNAL_RNG + USE_PSA_CRYPTO minus CTR_DRBG"
    make test

    msg "test: full + PSA_CRYPTO_EXTERNAL_RNG + USE_PSA_CRYPTO minus CTR_DRBG"
    tests/ssl-opt.sh -f 'Default\|opaque'
}

component_test_psa_inject_entropy () {
    msg "build: full + MBEDTLS_PSA_INJECT_ENTROPY"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_INJECT_ENTROPY
    scripts/config.py set MBEDTLS_ENTROPY_NV_SEED
    scripts/config.py set MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
    scripts/config.py unset MBEDTLS_PLATFORM_NV_SEED_ALT
    scripts/config.py unset MBEDTLS_PLATFORM_STD_NV_SEED_READ
    scripts/config.py unset MBEDTLS_PLATFORM_STD_NV_SEED_WRITE
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS '-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/user-config-for-test.h\"'" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full + MBEDTLS_PSA_INJECT_ENTROPY"
    make test
}

component_full_no_pkparse_pkwrite() {
    msg "build: full without pkparse and pkwrite"

    scripts/config.py crypto_full
    scripts/config.py unset MBEDTLS_PK_PARSE_C
    scripts/config.py unset MBEDTLS_PK_WRITE_C

    make CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    # Ensure that PK_[PARSE|WRITE]_C were not re-enabled accidentally (additive config).
    not grep mbedtls_pk_parse_key library/pkparse.o
    not grep mbedtls_pk_write_key_der library/pkwrite.o

    msg "test: full without pkparse and pkwrite"
    make test
}

component_test_crypto_full_md_light_only () {
    msg "build: crypto_full with only the light subset of MD"
    scripts/config.py crypto_full
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_CONFIG
    # Disable MD
    scripts/config.py unset MBEDTLS_MD_C
    # Disable direct dependencies of MD_C
    scripts/config.py unset MBEDTLS_HKDF_C
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_PKCS7_C
    # Disable indirect dependencies of MD_C
    scripts/config.py unset MBEDTLS_ECDSA_DETERMINISTIC # needs HMAC_DRBG
    # Disable things that would auto-enable MD_C
    scripts/config.py unset MBEDTLS_PKCS5_C

    # Note: MD-light is auto-enabled in build_info.h by modules that need it,
    # which we haven't disabled, so no need to explicitly enable it.
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    # Make sure we don't have the HMAC functions, but the hashing functions
    not grep mbedtls_md_hmac library/md.o
    grep mbedtls_md library/md.o

    msg "test: crypto_full with only the light subset of MD"
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

component_test_full_no_cipher_with_psa_crypto() {
    common_test_full_no_cipher_with_psa_crypto 0 "full no CIPHER no CRYPTO_CONFIG"
}

component_test_full_no_cipher_with_psa_crypto_config() {
    common_test_full_no_cipher_with_psa_crypto 1 "full no CIPHER"
}

component_test_full_no_ccm() {
    msg "build: full no PSA_WANT_ALG_CCM"

    # Full config enables:
    # - USE_PSA_CRYPTO so that TLS code dispatches cipher/AEAD to PSA
    # - CRYPTO_CONFIG so that PSA_WANT config symbols are evaluated
    scripts/config.py full

    # Disable PSA_WANT_ALG_CCM so that CCM is not supported in PSA. CCM_C is still
    # enabled, but not used from TLS since USE_PSA is set.
    # This is helpful to ensure that TLS tests below have proper dependencies.
    #
    # Note: also PSA_WANT_ALG_CCM_STAR_NO_TAG is enabled, but it does not cause
    # PSA_WANT_ALG_CCM to be re-enabled.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CCM

    make

    msg "test: full no PSA_WANT_ALG_CCM"
    make test
}

component_test_full_no_ccm_star_no_tag() {
    msg "build: full no PSA_WANT_ALG_CCM_STAR_NO_TAG"

    # Full config enables CRYPTO_CONFIG so that PSA_WANT config symbols are evaluated
    scripts/config.py full

    # Disable CCM_STAR_NO_TAG, which is the target of this test, as well as all
    # other components that enable MBEDTLS_PSA_BUILTIN_CIPHER internal symbol.
    # This basically disables all unauthenticated ciphers on the PSA side, while
    # keeping AEADs enabled.
    #
    # Note: PSA_WANT_ALG_CCM is enabled, but it does not cause
    # PSA_WANT_ALG_CCM_STAR_NO_TAG to be re-enabled.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CCM_STAR_NO_TAG
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_STREAM_CIPHER
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CTR
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CFB
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_OFB
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_ECB_NO_PADDING
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_NO_PADDING
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_PKCS7

    make

    # Ensure MBEDTLS_PSA_BUILTIN_CIPHER was not enabled
    not grep mbedtls_psa_cipher library/psa_crypto_cipher.o

    msg "test: full no PSA_WANT_ALG_CCM_STAR_NO_TAG"
    make test
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

component_test_psa_collect_statuses () {
  msg "build+test: psa_collect_statuses" # ~30s
  scripts/config.py full
  tests/scripts/psa_collect_statuses.py
  # Check that psa_crypto_init() succeeded at least once
  grep -q '^0:psa_crypto_init:' tests/statuses.log
  rm -f tests/statuses.log
}

# Check that the specified libraries exist and are empty.
are_empty_libraries () {
  nm "$@" >/dev/null 2>/dev/null
  ! nm "$@" 2>/dev/null | grep -v ':$' | grep .
}

component_build_crypto_default () {
  msg "build: make, crypto only"
  scripts/config.py crypto
  make CFLAGS='-O1 -Werror'
  are_empty_libraries library/libmbedx509.* library/libmbedtls.*
}

component_build_crypto_full () {
  msg "build: make, crypto only, full config"
  scripts/config.py crypto_full
  make CFLAGS='-O1 -Werror'
  are_empty_libraries library/libmbedx509.* library/libmbedtls.*
}

component_test_crypto_for_psa_service () {
  msg "build: make, config for PSA crypto service"
  scripts/config.py crypto
  scripts/config.py set MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
  # Disable things that are not needed for just cryptography, to
  # reach a configuration that would be typical for a PSA cryptography
  # service providing all implemented PSA algorithms.
  # System stuff
  scripts/config.py unset MBEDTLS_ERROR_C
  scripts/config.py unset MBEDTLS_TIMING_C
  scripts/config.py unset MBEDTLS_VERSION_FEATURES
  # Crypto stuff with no PSA interface
  scripts/config.py unset MBEDTLS_BASE64_C
  # Keep MBEDTLS_CIPHER_C because psa_crypto_cipher, CCM and GCM need it.
  scripts/config.py unset MBEDTLS_HKDF_C # PSA's HKDF is independent
  # Keep MBEDTLS_MD_C because deterministic ECDSA needs it for HMAC_DRBG.
  scripts/config.py unset MBEDTLS_NIST_KW_C
  scripts/config.py unset MBEDTLS_PEM_PARSE_C
  scripts/config.py unset MBEDTLS_PEM_WRITE_C
  scripts/config.py unset MBEDTLS_PKCS12_C
  scripts/config.py unset MBEDTLS_PKCS5_C
  # MBEDTLS_PK_PARSE_C and MBEDTLS_PK_WRITE_C are actually currently needed
  # in PSA code to work with RSA keys. We don't require users to set those:
  # they will be reenabled in build_info.h.
  scripts/config.py unset MBEDTLS_PK_C
  scripts/config.py unset MBEDTLS_PK_PARSE_C
  scripts/config.py unset MBEDTLS_PK_WRITE_C
  make CFLAGS='-O1 -Werror' all test
  are_empty_libraries library/libmbedx509.* library/libmbedtls.*
}

component_build_crypto_baremetal () {
  msg "build: make, crypto only, baremetal config"
  scripts/config.py crypto_baremetal
  make CFLAGS="-O1 -Werror -I$PWD/tests/include/baremetal-override/"
  are_empty_libraries library/libmbedx509.* library/libmbedtls.*
}
support_build_crypto_baremetal () {
    support_build_baremetal "$@"
}

# depends.py family of tests
component_test_depends_py_cipher_id () {
    msg "test/build: depends.py cipher_id (gcc)"
    tests/scripts/depends.py cipher_id --unset-use-psa
}

component_test_depends_py_cipher_chaining () {
    msg "test/build: depends.py cipher_chaining (gcc)"
    tests/scripts/depends.py cipher_chaining --unset-use-psa
}

component_test_depends_py_cipher_padding () {
    msg "test/build: depends.py cipher_padding (gcc)"
    tests/scripts/depends.py cipher_padding --unset-use-psa
}

component_test_depends_py_curves () {
    msg "test/build: depends.py curves (gcc)"
    tests/scripts/depends.py curves --unset-use-psa
}

component_test_depends_py_hashes () {
    msg "test/build: depends.py hashes (gcc)"
    tests/scripts/depends.py hashes --unset-use-psa
}

component_test_depends_py_kex () {
    msg "test/build: depends.py kex (gcc)"
    tests/scripts/depends.py kex --unset-use-psa
}

component_test_depends_py_pkalgs () {
    msg "test/build: depends.py pkalgs (gcc)"
    tests/scripts/depends.py pkalgs --unset-use-psa
}

# PSA equivalents of the depends.py tests
component_test_depends_py_cipher_id_psa () {
    msg "test/build: depends.py cipher_id (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py cipher_id
}

component_test_depends_py_cipher_chaining_psa () {
    msg "test/build: depends.py cipher_chaining (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py cipher_chaining
}

component_test_depends_py_cipher_padding_psa () {
    msg "test/build: depends.py cipher_padding (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py cipher_padding
}

component_test_depends_py_curves_psa () {
    msg "test/build: depends.py curves (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py curves
}

component_test_depends_py_hashes_psa () {
    msg "test/build: depends.py hashes (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py hashes
}

component_test_depends_py_kex_psa () {
    msg "test/build: depends.py kex (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py kex
}

component_test_depends_py_pkalgs_psa () {
    msg "test/build: depends.py pkalgs (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py pkalgs
}

component_build_no_pk_rsa_alt_support () {
    msg "build: !MBEDTLS_PK_RSA_ALT_SUPPORT" # ~30s

    scripts/config.py full
    scripts/config.py unset MBEDTLS_PK_RSA_ALT_SUPPORT
    scripts/config.py set MBEDTLS_RSA_C
    scripts/config.py set MBEDTLS_X509_CRT_WRITE_C

    # Only compile - this is primarily to test for compile issues
    make CFLAGS='-Werror -Wall -Wextra -I../tests/include/alt-dummy'
}

component_build_module_alt () {
    msg "build: MBEDTLS_XXX_ALT" # ~30s
    scripts/config.py full

    # Disable options that are incompatible with some ALT implementations:
    # aesni.c and padlock.c reference mbedtls_aes_context fields directly.
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_PADLOCK_C
    scripts/config.py unset MBEDTLS_AESCE_C
    # MBEDTLS_ECP_RESTARTABLE is documented as incompatible.
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE
    # You can only have one threading implementation: alt or pthread, not both.
    scripts/config.py unset MBEDTLS_THREADING_PTHREAD
    # The SpecifiedECDomain parsing code accesses mbedtls_ecp_group fields
    # directly and assumes the implementation works with partial groups.
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_EXTENDED
    # MBEDTLS_SHA256_*ALT can't be used with MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_*
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY
    # MBEDTLS_SHA512_*ALT can't be used with MBEDTLS_SHA512_USE_A64_CRYPTO_*
    scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT
    scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY

    # Enable all MBEDTLS_XXX_ALT for whole modules. Do not enable
    # MBEDTLS_XXX_YYY_ALT which are for single functions.
    scripts/config.py set-all 'MBEDTLS_([A-Z0-9]*|NIST_KW)_ALT'
    scripts/config.py unset MBEDTLS_DHM_ALT #incompatible with MBEDTLS_DEBUG_C

    # We can only compile, not link, since we don't have any implementations
    # suitable for testing with the dummy alt headers.
    make CFLAGS='-Werror -Wall -Wextra -I../tests/include/alt-dummy' lib
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

component_test_psa_crypto_config_accel_ecdsa () {
    msg "build: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated ECDSA"

    # Algorithms and key types to accelerate
    loc_accel_list="ALG_ECDSA ALG_DETERMINISTIC_ECDSA \
                    $(helper_get_psa_key_type_list "ECC") \
                    $(helper_get_psa_curve_list)"

    # Configure
    # ---------

    # Start from default config (no USE_PSA) + TLS 1.3
    helper_libtestdriver1_adjust_config "default"

    # Disable the module that's accelerated
    scripts/config.py unset MBEDTLS_ECDSA_C

    # Disable things that depend on it
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED

    # Build
    # -----

    # These hashes are needed for some ECDSA signature tests.
    loc_extra_list="ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"

    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ library/ecdsa.o

    # Run the tests
    # -------------

    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated ECDSA"
    make test
}

component_test_psa_crypto_config_accel_ecdh () {
    msg "build: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated ECDH"

    # Algorithms and key types to accelerate
    loc_accel_list="ALG_ECDH \
                    $(helper_get_psa_key_type_list "ECC") \
                    $(helper_get_psa_curve_list)"

    # Configure
    # ---------

    # Start from default config (no USE_PSA)
    helper_libtestdriver1_adjust_config "default"

    # Disable the module that's accelerated
    scripts/config.py unset MBEDTLS_ECDH_C

    # Disable things that depend on it
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_ecdh_ library/ecdh.o

    # Run the tests
    # -------------

    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated ECDH"
    make test
}

# Test that the given .o file builds with all (valid) combinations of the given options.
#
# Syntax: build_test_config_combos FILE VALIDATOR_FUNCTION OPT1 OPT2 ...
#
# The validator function is the name of a function to validate the combination of options.
# It may be "" if all combinations are valid.
# It receives a string containing a combination of options, as passed to the compiler,
# e.g. "-DOPT1 -DOPT2 ...". It must return 0 iff the combination is valid, non-zero if invalid.
build_test_config_combos() {
    file=$1
    shift
    validate_options=$1
    shift
    options=("$@")

    # clear all of the options so that they can be overridden on the clang commandline
    for opt in "${options[@]}"; do
        ./scripts/config.py unset ${opt}
    done

    # enter the directory containing the target file & strip the dir from the filename
    cd $(dirname ${file})
    file=$(basename ${file})

    # The most common issue is unused variables/functions, so ensure -Wunused is set.
    warning_flags="-Werror -Wall -Wextra -Wwrite-strings -Wpointer-arith -Wimplicit-fallthrough -Wshadow -Wvla -Wformat=2 -Wno-format-nonliteral -Wshadow -Wasm-operand-widths -Wunused"

    # Extract the command generated by the Makefile to build the target file.
    # This ensures that we have any include paths, macro definitions, etc
    # that may be applied by make.
    # Add -fsyntax-only as we only want a syntax check and don't need to generate a file.
    compile_cmd="clang \$(LOCAL_CFLAGS) ${warning_flags} -fsyntax-only -c"

    makefile=$(TMPDIR=. mktemp)
    deps=""

    len=${#options[@]}
    source_file=${file%.o}.c

    targets=0
    echo 'include Makefile' >${makefile}

    for ((i = 0; i < $((2**${len})); i++)); do
        # generate each of 2^n combinations of options
        # each bit of $i is used to determine if options[i] will be set or not
        target="t"
        clang_args=""
        for ((j = 0; j < ${len}; j++)); do
            if (((i >> j) & 1)); then
                opt=-D${options[$j]}
                clang_args="${clang_args} ${opt}"
                target="${target}${opt}"
            fi
        done

        # if combination is not known to be invalid, add it to the makefile
        if [[ -z $validate_options ]] || $validate_options "${clang_args}"; then
            cmd="${compile_cmd} ${clang_args}"
            echo "${target}: ${source_file}; $cmd ${source_file}" >> ${makefile}

            deps="${deps} ${target}"
            ((++targets))
        fi
    done

    echo "build_test_config_combos: ${deps}" >> ${makefile}

    # execute all of the commands via Make (probably in parallel)
    make -s -f ${makefile} build_test_config_combos
    echo "$targets targets checked"

    # clean up the temporary makefile
    rm ${makefile}
}

validate_aes_config_variations() {
    if [[ "$1" == *"MBEDTLS_AES_USE_HARDWARE_ONLY"* ]]; then
        if [[ "$1" == *"MBEDTLS_PADLOCK_C"* ]]; then
            return 1
        fi
        if [[ !(("$HOSTTYPE" == "aarch64" && "$1" != *"MBEDTLS_AESCE_C"*) || \
                ("$HOSTTYPE" == "x86_64"  && "$1" != *"MBEDTLS_AESNI_C"*)) ]]; then
            return 1
        fi
    fi
    return 0
}

component_build_aes_variations() {
    # 18s - around 90ms per clang invocation on M1 Pro
    #
    # aes.o has many #if defined(...) guards that intersect in complex ways.
    # Test that all the combinations build cleanly.

    MBEDTLS_ROOT_DIR="$PWD"
    msg "build: aes.o for all combinations of relevant config options"

    build_test_config_combos library/aes.o validate_aes_config_variations \
        "MBEDTLS_AES_SETKEY_ENC_ALT" "MBEDTLS_AES_DECRYPT_ALT" \
        "MBEDTLS_AES_ROM_TABLES" "MBEDTLS_AES_ENCRYPT_ALT" "MBEDTLS_AES_SETKEY_DEC_ALT" \
        "MBEDTLS_AES_FEWER_TABLES" "MBEDTLS_PADLOCK_C" "MBEDTLS_AES_USE_HARDWARE_ONLY" \
        "MBEDTLS_AESNI_C" "MBEDTLS_AESCE_C" "MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH"

    cd "$MBEDTLS_ROOT_DIR"
    msg "build: aes.o for all combinations of relevant config options + BLOCK_CIPHER_NO_DECRYPT"

    # MBEDTLS_BLOCK_CIPHER_NO_DECRYPT is incompatible with ECB in PSA, CBC/XTS/NIST_KW/DES,
    # manually set or unset those configurations to check
    # MBEDTLS_BLOCK_CIPHER_NO_DECRYPT with various combinations in aes.o.
    scripts/config.py set MBEDTLS_BLOCK_CIPHER_NO_DECRYPT
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CBC
    scripts/config.py unset MBEDTLS_CIPHER_MODE_XTS
    scripts/config.py unset MBEDTLS_DES_C
    scripts/config.py unset MBEDTLS_NIST_KW_C
    build_test_config_combos library/aes.o validate_aes_config_variations \
        "MBEDTLS_AES_SETKEY_ENC_ALT" "MBEDTLS_AES_DECRYPT_ALT" \
        "MBEDTLS_AES_ROM_TABLES" "MBEDTLS_AES_ENCRYPT_ALT" "MBEDTLS_AES_SETKEY_DEC_ALT" \
        "MBEDTLS_AES_FEWER_TABLES" "MBEDTLS_PADLOCK_C" "MBEDTLS_AES_USE_HARDWARE_ONLY" \
        "MBEDTLS_AESNI_C" "MBEDTLS_AESCE_C" "MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH"
}
support_build_aes_armce() {
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

support_build_sha_armce() {
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

component_test_aes_only_128_bit_keys () {
    msg "build: default config + AES_ONLY_128_BIT_KEY_LENGTH"
    scripts/config.py set MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH
    scripts/config.py unset MBEDTLS_PADLOCK_C

    make CFLAGS='-O2 -Werror -Wall -Wextra'

    msg "test: default config + AES_ONLY_128_BIT_KEY_LENGTH"
    make test
}

component_test_no_ctr_drbg_aes_only_128_bit_keys () {
    msg "build: default config + AES_ONLY_128_BIT_KEY_LENGTH - CTR_DRBG_C"
    scripts/config.py set MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH
    scripts/config.py unset MBEDTLS_CTR_DRBG_C
    scripts/config.py unset MBEDTLS_PADLOCK_C

    make CC=clang CFLAGS='-Werror -Wall -Wextra'

    msg "test: default config + AES_ONLY_128_BIT_KEY_LENGTH - CTR_DRBG_C"
    make test
}

component_test_aes_only_128_bit_keys_have_builtins () {
    msg "build: default config + AES_ONLY_128_BIT_KEY_LENGTH - AESNI_C - AESCE_C"
    scripts/config.py set MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH
    scripts/config.py unset MBEDTLS_PADLOCK_C
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C

    make CFLAGS='-O2 -Werror -Wall -Wextra'

    msg "test: default config + AES_ONLY_128_BIT_KEY_LENGTH - AESNI_C - AESCE_C"
    make test

    msg "selftest: default config + AES_ONLY_128_BIT_KEY_LENGTH - AESNI_C - AESCE_C"
    programs/test/selftest
}

component_test_gcm_largetable () {
    msg "build: default config + GCM_LARGE_TABLE - AESNI_C - AESCE_C"
    scripts/config.py set MBEDTLS_GCM_LARGE_TABLE
    scripts/config.py unset MBEDTLS_PADLOCK_C
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C

    make CFLAGS='-O2 -Werror -Wall -Wextra'

    msg "test: default config - GCM_LARGE_TABLE - AESNI_C - AESCE_C"
    make test
}

component_test_aes_fewer_tables () {
    msg "build: default config with AES_FEWER_TABLES enabled"
    scripts/config.py set MBEDTLS_AES_FEWER_TABLES
    make CFLAGS='-O2 -Werror -Wall -Wextra'

    msg "test: AES_FEWER_TABLES"
    make test
}

component_test_aes_rom_tables () {
    msg "build: default config with AES_ROM_TABLES enabled"
    scripts/config.py set MBEDTLS_AES_ROM_TABLES
    make CFLAGS='-O2 -Werror -Wall -Wextra'

    msg "test: AES_ROM_TABLES"
    make test
}

component_test_aes_fewer_tables_and_rom_tables () {
    msg "build: default config with AES_ROM_TABLES and AES_FEWER_TABLES enabled"
    scripts/config.py set MBEDTLS_AES_FEWER_TABLES
    scripts/config.py set MBEDTLS_AES_ROM_TABLES
    make CFLAGS='-O2 -Werror -Wall -Wextra'

    msg "test: AES_FEWER_TABLES + AES_ROM_TABLES"
    make test
}

# helper for common_block_cipher_no_decrypt() which:
# - enable/disable the list of config options passed from -s/-u respectively.
# - build
# - test for tests_suite_xxx
# - selftest
#
# Usage: helper_block_cipher_no_decrypt_build_test
#        [-s set_opts] [-u unset_opts] [-c cflags] [-l ldflags] [option [...]]
# Options:  -s set_opts     the list of config options to enable
#           -u unset_opts   the list of config options to disable
#           -c cflags       the list of options passed to CFLAGS
#           -l ldflags      the list of options passed to LDFLAGS
helper_block_cipher_no_decrypt_build_test () {
    while [ $# -gt 0 ]; do
        case "$1" in
            -s)
                shift; local set_opts="$1";;
            -u)
                shift; local unset_opts="$1";;
            -c)
                shift; local cflags="-Werror -Wall -Wextra $1";;
            -l)
                shift; local ldflags="$1";;
        esac
        shift
    done
    set_opts="${set_opts:-}"
    unset_opts="${unset_opts:-}"
    cflags="${cflags:-}"
    ldflags="${ldflags:-}"

    [ -n "$set_opts" ] && echo "Enabling: $set_opts" && scripts/config.py set-all $set_opts
    [ -n "$unset_opts" ] && echo "Disabling: $unset_opts" && scripts/config.py unset-all $unset_opts

    msg "build: default config + BLOCK_CIPHER_NO_DECRYPT${set_opts:+ + $set_opts}${unset_opts:+ - $unset_opts} with $cflags${ldflags:+, $ldflags}"
    make clean
    make CFLAGS="-O2 $cflags" LDFLAGS="$ldflags"

    # Make sure we don't have mbedtls_xxx_setkey_dec in AES/ARIA/CAMELLIA
    not grep mbedtls_aes_setkey_dec library/aes.o
    not grep mbedtls_aria_setkey_dec library/aria.o
    not grep mbedtls_camellia_setkey_dec library/camellia.o
    # Make sure we don't have mbedtls_internal_aes_decrypt in AES
    not grep mbedtls_internal_aes_decrypt library/aes.o
    # Make sure we don't have mbedtls_aesni_inverse_key in AESNI
    not grep mbedtls_aesni_inverse_key library/aesni.o

    msg "test: default config + BLOCK_CIPHER_NO_DECRYPT${set_opts:+ + $set_opts}${unset_opts:+ - $unset_opts} with $cflags${ldflags:+, $ldflags}"
    make test

    msg "selftest: default config + BLOCK_CIPHER_NO_DECRYPT${set_opts:+ + $set_opts}${unset_opts:+ - $unset_opts} with $cflags${ldflags:+, $ldflags}"
    programs/test/selftest
}

# This is a common configuration function used in:
# - component_test_block_cipher_no_decrypt_aesni_legacy()
# - component_test_block_cipher_no_decrypt_aesni_use_psa()
# in order to test BLOCK_CIPHER_NO_DECRYPT with AESNI intrinsics,
# AESNI assembly and AES C implementation on x86_64 and with AESNI intrinsics
# on x86.
common_block_cipher_no_decrypt () {
    # test AESNI intrinsics
    helper_block_cipher_no_decrypt_build_test \
        -s "MBEDTLS_AESNI_C" \
        -c "-mpclmul -msse2 -maes"

    # test AESNI assembly
    helper_block_cipher_no_decrypt_build_test \
        -s "MBEDTLS_AESNI_C" \
        -c "-mno-pclmul -mno-sse2 -mno-aes"

    # test AES C implementation
    helper_block_cipher_no_decrypt_build_test \
        -u "MBEDTLS_AESNI_C"

    # test AESNI intrinsics for i386 target
    helper_block_cipher_no_decrypt_build_test \
        -s "MBEDTLS_AESNI_C" \
        -c "-m32 -mpclmul -msse2 -maes" \
        -l "-m32"
}

# This is a configuration function used in component_test_block_cipher_no_decrypt_xxx:
# usage: 0: no PSA crypto configuration
#        1: use PSA crypto configuration
config_block_cipher_no_decrypt () {
    use_psa=$1

    scripts/config.py set MBEDTLS_BLOCK_CIPHER_NO_DECRYPT
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CBC
    scripts/config.py unset MBEDTLS_CIPHER_MODE_XTS
    scripts/config.py unset MBEDTLS_DES_C
    scripts/config.py unset MBEDTLS_NIST_KW_C

    if [ "$use_psa" -eq 1 ]; then
        # Enable support for cryptographic mechanisms through the PSA API.
        # Note: XTS, KW are not yet supported via the PSA API in Mbed TLS.
        scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
        scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_NO_PADDING
        scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_PKCS7
        scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_ECB_NO_PADDING
        scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_DES
    fi
}

component_test_block_cipher_no_decrypt_aesni () {
    # This consistently causes an llvm crash on clang 3.8, so use gcc
    export CC=gcc
    config_block_cipher_no_decrypt 0
    common_block_cipher_no_decrypt
}

component_test_block_cipher_no_decrypt_aesni_use_psa () {
    # This consistently causes an llvm crash on clang 3.8, so use gcc
    export CC=gcc
    config_block_cipher_no_decrypt 1
    common_block_cipher_no_decrypt
}

component_test_block_cipher_no_decrypt_aesce_armcc () {
    scripts/config.py baremetal

    # armc[56] don't support SHA-512 intrinsics
    scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT

    # Stop armclang warning about feature detection for A64_CRYPTO.
    # With this enabled, the library does build correctly under armclang,
    # but in baremetal builds (as tested here), feature detection is
    # unavailable, and the user is notified via a #warning. So enabling
    # this feature would prevent us from building with -Werror on
    # armclang. Tracked in #7198.
    scripts/config.py unset MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT
    scripts/config.py set MBEDTLS_HAVE_ASM

    config_block_cipher_no_decrypt 1

    # test AESCE baremetal build
    scripts/config.py set MBEDTLS_AESCE_C
    msg "build: default config + BLOCK_CIPHER_NO_DECRYPT with AESCE"
    armc6_build_test "-O1 --target=aarch64-arm-none-eabi -march=armv8-a+crypto -Werror -Wall -Wextra"

    # Make sure we don't have mbedtls_xxx_setkey_dec in AES/ARIA/CAMELLIA
    not grep mbedtls_aes_setkey_dec library/aes.o
    not grep mbedtls_aria_setkey_dec library/aria.o
    not grep mbedtls_camellia_setkey_dec library/camellia.o
    # Make sure we don't have mbedtls_internal_aes_decrypt in AES
    not grep mbedtls_internal_aes_decrypt library/aes.o
    # Make sure we don't have mbedtls_aesce_inverse_key and aesce_decrypt_block in AESCE
    not grep mbedtls_aesce_inverse_key library/aesce.o
    not grep aesce_decrypt_block library/aesce.o
}

component_test_ctr_drbg_aes_256_sha_256 () {
    msg "build: full + MBEDTLS_ENTROPY_FORCE_SHA256 (ASan build)"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_ENTROPY_FORCE_SHA256
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full + MBEDTLS_ENTROPY_FORCE_SHA256 (ASan build)"
    make test
}

component_test_ctr_drbg_aes_128_sha_512 () {
    msg "build: full + MBEDTLS_CTR_DRBG_USE_128_BIT_KEY (ASan build)"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_CTR_DRBG_USE_128_BIT_KEY
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full + MBEDTLS_CTR_DRBG_USE_128_BIT_KEY (ASan build)"
    make test
}

component_test_ctr_drbg_aes_128_sha_256 () {
    msg "build: full + MBEDTLS_CTR_DRBG_USE_128_BIT_KEY + MBEDTLS_ENTROPY_FORCE_SHA256 (ASan build)"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_CTR_DRBG_USE_128_BIT_KEY
    scripts/config.py set MBEDTLS_ENTROPY_FORCE_SHA256
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full + MBEDTLS_CTR_DRBG_USE_128_BIT_KEY + MBEDTLS_ENTROPY_FORCE_SHA256 (ASan build)"
    make test
}

component_test_se_default () {
    msg "build: default config + MBEDTLS_PSA_CRYPTO_SE_C"
    scripts/config.py set MBEDTLS_PSA_CRYPTO_SE_C
    make CC=clang CFLAGS="$ASAN_CFLAGS -Os" LDFLAGS="$ASAN_CFLAGS"

    msg "test: default config + MBEDTLS_PSA_CRYPTO_SE_C"
    make test
}

component_test_psa_crypto_drivers () {
    msg "build: full + test drivers dispatching to builtins"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_CONFIG
    loc_cflags="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST_ALL"
    loc_cflags="${loc_cflags} '-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/user-config-for-test.h\"'"
    loc_cflags="${loc_cflags} -I../tests/include -O2"

    make CC=$ASAN_CC CFLAGS="${loc_cflags}" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full + test drivers dispatching to builtins"
    make test
}

component_build_psa_config_file () {
    msg "build: make with MBEDTLS_PSA_CRYPTO_CONFIG_FILE" # ~40s
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    cp "$CRYPTO_CONFIG_H" psa_test_config.h
    echo '#error "MBEDTLS_PSA_CRYPTO_CONFIG_FILE is not working"' >"$CRYPTO_CONFIG_H"
    make CFLAGS="-I '$PWD' -DMBEDTLS_PSA_CRYPTO_CONFIG_FILE='\"psa_test_config.h\"'"
    # Make sure this feature is enabled. We'll disable it in the next phase.
    programs/test/query_compile_time_config MBEDTLS_CMAC_C
    make clean

    msg "build: make with MBEDTLS_PSA_CRYPTO_CONFIG_FILE + MBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE" # ~40s
    # In the user config, disable one feature, which will reflect on the
    # mbedtls configuration so we can query it with query_compile_time_config.
    echo '#undef PSA_WANT_ALG_CMAC' >psa_user_config.h
    scripts/config.py unset MBEDTLS_CMAC_C
    make CFLAGS="-I '$PWD' -DMBEDTLS_PSA_CRYPTO_CONFIG_FILE='\"psa_test_config.h\"' -DMBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE='\"psa_user_config.h\"'"
    not programs/test/query_compile_time_config MBEDTLS_CMAC_C

    rm -f psa_test_config.h psa_user_config.h
}

component_build_psa_alt_headers () {
    msg "build: make with PSA alt headers" # ~20s

    # Generate alternative versions of the substitutable headers with the
    # same content except different include guards.
    make -C tests include/alt-extra/psa/crypto_platform_alt.h include/alt-extra/psa/crypto_struct_alt.h

    # Build the library and some programs.
    # Don't build the fuzzers to avoid having to go through hoops to set
    # a correct include path for programs/fuzz/Makefile.
    make CFLAGS="-I ../tests/include/alt-extra -DMBEDTLS_PSA_CRYPTO_PLATFORM_FILE='\"psa/crypto_platform_alt.h\"' -DMBEDTLS_PSA_CRYPTO_STRUCT_FILE='\"psa/crypto_struct_alt.h\"'" lib
    make -C programs -o fuzz CFLAGS="-I ../tests/include/alt-extra -DMBEDTLS_PSA_CRYPTO_PLATFORM_FILE='\"psa/crypto_platform_alt.h\"' -DMBEDTLS_PSA_CRYPTO_STRUCT_FILE='\"psa/crypto_struct_alt.h\"'"

    # Check that we're getting the alternative include guards and not the
    # original include guards.
    programs/test/query_included_headers | grep -x PSA_CRYPTO_PLATFORM_ALT_H
    programs/test/query_included_headers | grep -x PSA_CRYPTO_STRUCT_ALT_H
    programs/test/query_included_headers | not grep -x PSA_CRYPTO_PLATFORM_H
    programs/test/query_included_headers | not grep -x PSA_CRYPTO_STRUCT_H
}
support_test_aesni() {
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

# For timebeing, no aarch64 gcc available in CI and no arm64 CI node.
component_build_aes_aesce_armcc () {
    msg "Build: AESCE test on arm64 platform without plain C."
    scripts/config.py baremetal

    # armc[56] don't support SHA-512 intrinsics
    scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT

    # Stop armclang warning about feature detection for A64_CRYPTO.
    # With this enabled, the library does build correctly under armclang,
    # but in baremetal builds (as tested here), feature detection is
    # unavailable, and the user is notified via a #warning. So enabling
    # this feature would prevent us from building with -Werror on
    # armclang. Tracked in #7198.
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
    scripts/config.py set MBEDTLS_HAVE_ASM

    msg "AESCE, build with default configuration."
    scripts/config.py set MBEDTLS_AESCE_C
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    armc6_build_test "-O1 --target=aarch64-arm-none-eabi -march=armv8-a+crypto"

    msg "AESCE, build AESCE only"
    scripts/config.py set MBEDTLS_AESCE_C
    scripts/config.py set MBEDTLS_AES_USE_HARDWARE_ONLY
    armc6_build_test "-O1 --target=aarch64-arm-none-eabi -march=armv8-a+crypto"
}

component_test_sha3_variations() {
    msg "sha3 loop unroll variations"

    # define minimal config sufficient to test SHA3
    cat > include/mbedtls/mbedtls_config.h << END
        #define MBEDTLS_SELF_TEST
        #define MBEDTLS_SHA3_C
END

    msg "all loops unrolled"
    make clean
    make -C tests test_suite_shax CFLAGS="-DMBEDTLS_SHA3_THETA_UNROLL=1 -DMBEDTLS_SHA3_PI_UNROLL=1 -DMBEDTLS_SHA3_CHI_UNROLL=1 -DMBEDTLS_SHA3_RHO_UNROLL=1"
    ./tests/test_suite_shax

    msg "all loops rolled up"
    make clean
    make -C tests test_suite_shax CFLAGS="-DMBEDTLS_SHA3_THETA_UNROLL=0 -DMBEDTLS_SHA3_PI_UNROLL=0 -DMBEDTLS_SHA3_CHI_UNROLL=0 -DMBEDTLS_SHA3_RHO_UNROLL=0"
    ./tests/test_suite_shax
}

support_test_aesni_m32() {
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
