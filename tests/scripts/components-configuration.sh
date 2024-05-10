# components-configuration.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains the test components that are executed by all.sh

################################################################
#### Configuration Testing
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

    msg "test: selftest (ASan build)" # ~ 10s
    programs/test/selftest

    msg "test: ssl-opt.sh (full config, ASan build)"
    tests/ssl-opt.sh

    msg "test: compat.sh (full config, ASan build)"
    tests/compat.sh

    msg "test: context-info.sh (full config, ASan build)" # ~ 15 sec
    tests/context-info.sh
}


component_test_full_cmake_gcc_asan_new_bignum () {
    msg "build: full config, cmake, gcc, ASan"
    scripts/config.py full
    scripts/config.py set MBEDTLS_ECP_WITH_MPI_UINT
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (inc. selftests) (full config, ASan build)"
    make test

    msg "test: selftest (ASan build)" # ~ 10s
    programs/test/selftest

    msg "test: ssl-opt.sh (full config, ASan build)"
    tests/ssl-opt.sh

    msg "test: compat.sh (full config, ASan build)"
    tests/compat.sh

    msg "test: context-info.sh (full config, ASan build)" # ~ 15 sec
    tests/context-info.sh
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

component_test_tls1_2_default_stream_cipher_only () {
    msg "build: default with only stream cipher"

    # Disable AEAD (controlled by the presence of one of GCM_C, CCM_C, CHACHAPOLY_C
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

    msg "test: default with only stream cipher"
    make test

    # Not running ssl-opt.sh because most tests require a non-NULL ciphersuite.
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

component_test_tls1_2_default_cbc_legacy_cipher_only () {
    msg "build: default with only CBC-legacy cipher"

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

    msg "test: default with only CBC-legacy cipher"
    make test

    msg "test: default with only CBC-legacy cipher - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f "TLS 1.2"
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

component_test_tls1_2_default_cbc_legacy_cbc_etm_cipher_only () {
    msg "build: default with only CBC-legacy and CBC-EtM ciphers"

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

    msg "test: default with only CBC-legacy and CBC-EtM ciphers"
    make test

    msg "test: default with only CBC-legacy and CBC-EtM ciphers - ssl-opt.sh (subset)"
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
    scripts/config.py set MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_ECJPAKE_C
    # Disable all curves
    scripts/config.py unset-all "MBEDTLS_ECP_DP_[0-9A-Z_a-z]*_ENABLED"
    scripts/config.py set MBEDTLS_ECP_DP_CURVE25519_ENABLED

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

    msg "test: compat.sh NULL (full config)" # ~ 2 min
    tests/compat.sh -e '^$' -f 'NULL'

    msg "test: compat.sh ARIA + ChachaPoly"
    env OPENSSL="$OPENSSL_NEXT" tests/compat.sh -e '^$' -f 'ARIA\|CHACHA'
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

component_test_psa_crypto_config_ffdh_2048_only () {
    msg "build: full config - only DH 2048"

    scripts/config.py full

    # Disable all DH groups other than 2048.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_DH_RFC7919_3072
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_DH_RFC7919_4096
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_DH_RFC7919_6144
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_DH_RFC7919_8192

    make CFLAGS="$ASAN_CFLAGS -Werror" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full config - only DH 2048"
    make test

    msg "ssl-opt: full config - only DH 2048"
    tests/ssl-opt.sh -f "ffdh"
}

component_test_psa_crypto_config_accel_ffdh () {
    msg "build: full with accelerated FFDH"

    # Algorithms and key types to accelerate
    loc_accel_list="ALG_FFDH \
                    $(helper_get_psa_key_type_list "DH") \
                    $(helper_get_psa_dh_group_list)"

    # Configure
    # ---------

    # start with full (USE_PSA and TLS 1.3)
    helper_libtestdriver1_adjust_config "full"

    # Disable the module that's accelerated
    scripts/config.py unset MBEDTLS_DHM_C

    # Disable things that depend on it
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_dhm_ library/dhm.o

    # Run the tests
    # -------------

    msg "test: full with accelerated FFDH"
    make test

    msg "ssl-opt: full with accelerated FFDH alg"
    tests/ssl-opt.sh -f "ffdh"
}

component_test_psa_crypto_config_reference_ffdh () {
    msg "build: full with non-accelerated FFDH"

    # Start with full (USE_PSA and TLS 1.3)
    helper_libtestdriver1_adjust_config "full"

    # Disable things that are not supported
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
    make

    msg "test suites: full with non-accelerated FFDH alg"
    make test

    msg "ssl-opt: full with non-accelerated FFDH alg"
    tests/ssl-opt.sh -f "ffdh"
}

component_test_psa_crypto_config_accel_pake() {
    msg "build: full with accelerated PAKE"

    loc_accel_list="ALG_JPAKE \
                    $(helper_get_psa_key_type_list "ECC") \
                    $(helper_get_psa_curve_list)"

    # Configure
    # ---------

    helper_libtestdriver1_adjust_config "full"

    # Make built-in fallback not available
    scripts/config.py unset MBEDTLS_ECJPAKE_C
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_ecjpake_init library/ecjpake.o

    # Run the tests
    # -------------

    msg "test: full with accelerated PAKE"
    make test
}

component_test_psa_crypto_config_accel_ecc_some_key_types () {
    msg "build: full with accelerated EC algs and some key types"

    # Algorithms and key types to accelerate
    # For key types, use an explicitly list to omit GENERATE (and DERIVE)
    loc_accel_list="ALG_ECDSA ALG_DETERMINISTIC_ECDSA \
                    ALG_ECDH \
                    ALG_JPAKE \
                    KEY_TYPE_ECC_PUBLIC_KEY \
                    KEY_TYPE_ECC_KEY_PAIR_BASIC \
                    KEY_TYPE_ECC_KEY_PAIR_IMPORT \
                    KEY_TYPE_ECC_KEY_PAIR_EXPORT \
                    $(helper_get_psa_curve_list)"

    # Configure
    # ---------

    # start with config full for maximum coverage (also enables USE_PSA)
    helper_libtestdriver1_adjust_config "full"

    # Disable modules that are accelerated - some will be re-enabled
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_ECDH_C
    scripts/config.py unset MBEDTLS_ECJPAKE_C
    scripts/config.py unset MBEDTLS_ECP_C

    # Disable all curves - those that aren't accelerated should be re-enabled
    helper_disable_builtin_curves

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE

    # this is not supported by the driver API yet
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # Build
    # -----

    # These hashes are needed for some ECDSA signature tests.
    loc_extra_list="ALG_SHA_1 ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"
    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # ECP should be re-enabled but not the others
    not grep mbedtls_ecdh_ library/ecdh.o
    not grep mbedtls_ecdsa library/ecdsa.o
    not grep mbedtls_ecjpake  library/ecjpake.o
    grep mbedtls_ecp library/ecp.o

    # Run the tests
    # -------------

    msg "test suites: full with accelerated EC algs and some key types"
    make test
}

# Run tests with only (non-)Weierstrass accelerated
# Common code used in:
# - component_test_psa_crypto_config_accel_ecc_weierstrass_curves
# - component_test_psa_crypto_config_accel_ecc_non_weierstrass_curves
common_test_psa_crypto_config_accel_ecc_some_curves () {
    weierstrass=$1
    if [ $weierstrass -eq 1 ]; then
        desc="Weierstrass"
    else
        desc="non-Weierstrass"
    fi

    msg "build: crypto_full minus PK with accelerated EC algs and $desc curves"

    # Note: Curves are handled in a special way by the libtestdriver machinery,
    # so we only want to include them in the accel list when building the main
    # libraries, hence the use of a separate variable.
    # Note: the following loop is a modified version of
    # helper_get_psa_curve_list that only keeps Weierstrass families.
    loc_weierstrass_list=""
    loc_non_weierstrass_list=""
    for item in $(sed -n 's/^#define PSA_WANT_\(ECC_[0-9A-Z_a-z]*\).*/\1/p' <"$CRYPTO_CONFIG_H"); do
        case $item in
            ECC_BRAINPOOL*|ECC_SECP*)
                loc_weierstrass_list="$loc_weierstrass_list $item"
                ;;
            *)
                loc_non_weierstrass_list="$loc_non_weierstrass_list $item"
                ;;
        esac
    done
    if [ $weierstrass -eq 1 ]; then
        loc_curve_list=$loc_weierstrass_list
    else
        loc_curve_list=$loc_non_weierstrass_list
    fi

    # Algorithms and key types to accelerate
    loc_accel_list="ALG_ECDSA ALG_DETERMINISTIC_ECDSA \
                    ALG_ECDH \
                    ALG_JPAKE \
                    $(helper_get_psa_key_type_list "ECC") \
                    $loc_curve_list"

    # Configure
    # ---------

    # Start with config crypto_full and remove PK_C:
    # that's what's supported now, see docs/driver-only-builds.md.
    helper_libtestdriver1_adjust_config "crypto_full"
    scripts/config.py unset MBEDTLS_PK_C
    scripts/config.py unset MBEDTLS_PK_PARSE_C
    scripts/config.py unset MBEDTLS_PK_WRITE_C

    # Disable modules that are accelerated - some will be re-enabled
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_ECDH_C
    scripts/config.py unset MBEDTLS_ECJPAKE_C
    scripts/config.py unset MBEDTLS_ECP_C

    # Disable all curves - those that aren't accelerated should be re-enabled
    helper_disable_builtin_curves

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE

    # this is not supported by the driver API yet
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # Build
    # -----

    # These hashes are needed for some ECDSA signature tests.
    loc_extra_list="ALG_SHA_1 ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"
    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # We expect ECDH to be re-enabled for the missing curves
    grep mbedtls_ecdh_ library/ecdh.o
    # We expect ECP to be re-enabled, however the parts specific to the
    # families of curves that are accelerated should be ommited.
    # - functions with mxz in the name are specific to Montgomery curves
    # - ecp_muladd is specific to Weierstrass curves
    ##nm library/ecp.o | tee ecp.syms
    if [ $weierstrass -eq 1 ]; then
        not grep mbedtls_ecp_muladd library/ecp.o
        grep mxz library/ecp.o
    else
        grep mbedtls_ecp_muladd library/ecp.o
        not grep mxz library/ecp.o
    fi
    # We expect ECDSA and ECJPAKE to be re-enabled only when
    # Weierstrass curves are not accelerated
    if [ $weierstrass -eq 1 ]; then
        not grep mbedtls_ecdsa library/ecdsa.o
        not grep mbedtls_ecjpake  library/ecjpake.o
    else
        grep mbedtls_ecdsa library/ecdsa.o
        grep mbedtls_ecjpake  library/ecjpake.o
    fi

    # Run the tests
    # -------------

    msg "test suites: crypto_full minus PK with accelerated EC algs and $desc curves"
    make test
}

component_test_psa_crypto_config_accel_ecc_weierstrass_curves () {
    common_test_psa_crypto_config_accel_ecc_some_curves 1
}

component_test_psa_crypto_config_accel_ecc_non_weierstrass_curves () {
    common_test_psa_crypto_config_accel_ecc_some_curves 0
}

# Auxiliary function to build config for all EC based algorithms (EC-JPAKE,
# ECDH, ECDSA) with and without drivers.
# The input parameter is a boolean value which indicates:
# - 0 keep built-in EC algs,
# - 1 exclude built-in EC algs (driver only).
#
# This is used by the two following components to ensure they always use the
# same config, except for the use of driver or built-in EC algorithms:
# - component_test_psa_crypto_config_accel_ecc_ecp_light_only;
# - component_test_psa_crypto_config_reference_ecc_ecp_light_only.
# This supports comparing their test coverage with analyze_outcomes.py.
config_psa_crypto_config_ecp_light_only () {
    driver_only="$1"
    # start with config full for maximum coverage (also enables USE_PSA)
    helper_libtestdriver1_adjust_config "full"
    if [ "$driver_only" -eq 1 ]; then
        # Disable modules that are accelerated
        scripts/config.py unset MBEDTLS_ECDSA_C
        scripts/config.py unset MBEDTLS_ECDH_C
        scripts/config.py unset MBEDTLS_ECJPAKE_C
        scripts/config.py unset MBEDTLS_ECP_C
    fi

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE
}

# Keep in sync with component_test_psa_crypto_config_reference_ecc_ecp_light_only
component_test_psa_crypto_config_accel_ecc_ecp_light_only () {
    msg "build: full with accelerated EC algs"

    # Algorithms and key types to accelerate
    loc_accel_list="ALG_ECDSA ALG_DETERMINISTIC_ECDSA \
                    ALG_ECDH \
                    ALG_JPAKE \
                    $(helper_get_psa_key_type_list "ECC") \
                    $(helper_get_psa_curve_list)"

    # Configure
    # ---------

    # Use the same config as reference, only without built-in EC algs
    config_psa_crypto_config_ecp_light_only 1

    # Do not disable builtin curves because that support is required for:
    # - MBEDTLS_PK_PARSE_EC_EXTENDED
    # - MBEDTLS_PK_PARSE_EC_COMPRESSED

    # Build
    # -----

    # These hashes are needed for some ECDSA signature tests.
    loc_extra_list="ALG_SHA_1 ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"
    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure any built-in EC alg was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ library/ecdsa.o
    not grep mbedtls_ecdh_ library/ecdh.o
    not grep mbedtls_ecjpake_ library/ecjpake.o
    not grep mbedtls_ecp_mul library/ecp.o

    # Run the tests
    # -------------

    msg "test suites: full with accelerated EC algs"
    make test

    msg "ssl-opt: full with accelerated EC algs"
    tests/ssl-opt.sh
}

# Keep in sync with component_test_psa_crypto_config_accel_ecc_ecp_light_only
component_test_psa_crypto_config_reference_ecc_ecp_light_only () {
    msg "build: MBEDTLS_PSA_CRYPTO_CONFIG with non-accelerated EC algs"

    config_psa_crypto_config_ecp_light_only 0

    make

    msg "test suites: full with non-accelerated EC algs"
    make test

    msg "ssl-opt: full with non-accelerated EC algs"
    tests/ssl-opt.sh
}

# This helper function is used by:
# - component_test_psa_crypto_config_accel_ecc_no_ecp_at_all()
# - component_test_psa_crypto_config_reference_ecc_no_ecp_at_all()
# to ensure that both tests use the same underlying configuration when testing
# driver's coverage with analyze_outcomes.py.
#
# This functions accepts 1 boolean parameter as follows:
# - 1: building with accelerated EC algorithms (ECDSA, ECDH, ECJPAKE), therefore
#      excluding their built-in implementation as well as ECP_C & ECP_LIGHT
# - 0: include built-in implementation of EC algorithms.
#
# PK_C and RSA_C are always disabled to ensure there is no remaining dependency
# on the ECP module.
config_psa_crypto_no_ecp_at_all () {
    driver_only="$1"
    # start with full config for maximum coverage (also enables USE_PSA)
    helper_libtestdriver1_adjust_config "full"

    if [ "$driver_only" -eq 1 ]; then
        # Disable modules that are accelerated
        scripts/config.py unset MBEDTLS_ECDSA_C
        scripts/config.py unset MBEDTLS_ECDH_C
        scripts/config.py unset MBEDTLS_ECJPAKE_C
        # Disable ECP module (entirely)
        scripts/config.py unset MBEDTLS_ECP_C
    fi

    # Disable all the features that auto-enable ECP_LIGHT (see build_info.h)
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_EXTENDED
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_COMPRESSED
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE
}

# Build and test a configuration where driver accelerates all EC algs while
# all support and dependencies from ECP and ECP_LIGHT are removed on the library
# side.
#
# Keep in sync with component_test_psa_crypto_config_reference_ecc_no_ecp_at_all()
component_test_psa_crypto_config_accel_ecc_no_ecp_at_all () {
    msg "build: full + accelerated EC algs - ECP"

    # Algorithms and key types to accelerate
    loc_accel_list="ALG_ECDSA ALG_DETERMINISTIC_ECDSA \
                    ALG_ECDH \
                    ALG_JPAKE \
                    $(helper_get_psa_key_type_list "ECC") \
                    $(helper_get_psa_curve_list)"

    # Configure
    # ---------

    # Set common configurations between library's and driver's builds
    config_psa_crypto_no_ecp_at_all 1
    # Disable all the builtin curves. All the required algs are accelerated.
    helper_disable_builtin_curves

    # Build
    # -----

    # Things we wanted supported in libtestdriver1, but not accelerated in the main library:
    # SHA-1 and all SHA-2/3 variants, as they are used by ECDSA deterministic.
    loc_extra_list="ALG_SHA_1 ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"

    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure any built-in EC alg was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ library/ecdsa.o
    not grep mbedtls_ecdh_ library/ecdh.o
    not grep mbedtls_ecjpake_ library/ecjpake.o
    # Also ensure that ECP module was not re-enabled
    not grep mbedtls_ecp_ library/ecp.o

    # Run the tests
    # -------------

    msg "test: full + accelerated EC algs - ECP"
    make test

    msg "ssl-opt: full + accelerated EC algs - ECP"
    tests/ssl-opt.sh
}

# Reference function used for driver's coverage analysis in analyze_outcomes.py
# in conjunction with component_test_psa_crypto_config_accel_ecc_no_ecp_at_all().
# Keep in sync with its accelerated counterpart.
component_test_psa_crypto_config_reference_ecc_no_ecp_at_all () {
    msg "build: full + non accelerated EC algs"

    config_psa_crypto_no_ecp_at_all 0

    make

    msg "test: full + non accelerated EC algs"
    make test

    msg "ssl-opt: full + non accelerated EC algs"
    tests/ssl-opt.sh
}

# This is a common configuration helper used directly from:
# - common_test_psa_crypto_config_accel_ecc_ffdh_no_bignum
# - common_test_psa_crypto_config_reference_ecc_ffdh_no_bignum
# and indirectly from:
# - component_test_psa_crypto_config_accel_ecc_no_bignum
#       - accelerate all EC algs, disable RSA and FFDH
# - component_test_psa_crypto_config_reference_ecc_no_bignum
#       - this is the reference component of the above
#       - it still disables RSA and FFDH, but it uses builtin EC algs
# - component_test_psa_crypto_config_accel_ecc_ffdh_no_bignum
#       - accelerate all EC and FFDH algs, disable only RSA
# - component_test_psa_crypto_config_reference_ecc_ffdh_no_bignum
#       - this is the reference component of the above
#       - it still disables RSA, but it uses builtin EC and FFDH algs
#
# This function accepts 2 parameters:
# $1: a boolean value which states if we are testing an accelerated scenario
#     or not.
# $2: a string value which states which components are tested. Allowed values
#     are "ECC" or "ECC_DH".
config_psa_crypto_config_accel_ecc_ffdh_no_bignum() {
    driver_only="$1"
    test_target="$2"
    # start with full config for maximum coverage (also enables USE_PSA)
    helper_libtestdriver1_adjust_config "full"

    if [ "$driver_only" -eq 1 ]; then
        # Disable modules that are accelerated
        scripts/config.py unset MBEDTLS_ECDSA_C
        scripts/config.py unset MBEDTLS_ECDH_C
        scripts/config.py unset MBEDTLS_ECJPAKE_C
        # Disable ECP module (entirely)
        scripts/config.py unset MBEDTLS_ECP_C
        # Also disable bignum
        scripts/config.py unset MBEDTLS_BIGNUM_C
    fi

    # Disable all the features that auto-enable ECP_LIGHT (see build_info.h)
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_EXTENDED
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_COMPRESSED
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # RSA support is intentionally disabled on this test because RSA_C depends
    # on BIGNUM_C.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset-all "PSA_WANT_KEY_TYPE_RSA_[0-9A-Z_a-z]*"
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset-all "PSA_WANT_ALG_RSA_[0-9A-Z_a-z]*"
    scripts/config.py unset MBEDTLS_RSA_C
    scripts/config.py unset MBEDTLS_PKCS1_V15
    scripts/config.py unset MBEDTLS_PKCS1_V21
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT
    # Also disable key exchanges that depend on RSA
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED

    if [ "$test_target" = "ECC" ]; then
        # When testing ECC only, we disable FFDH support, both from builtin and
        # PSA sides, and also disable the key exchanges that depend on DHM.
        scripts/config.py -f include/psa/crypto_config.h unset PSA_WANT_ALG_FFDH
        scripts/config.py -f "$CRYPTO_CONFIG_H" unset-all "PSA_WANT_KEY_TYPE_DH_[0-9A-Z_a-z]*"
        scripts/config.py -f "$CRYPTO_CONFIG_H" unset-all "PSA_WANT_DH_RFC7919_[0-9]*"
        scripts/config.py unset MBEDTLS_DHM_C
        scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
        scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
    else
        # When testing ECC and DH instead, we disable DHM and depending key
        # exchanges only in the accelerated build
        if [ "$driver_only" -eq 1 ]; then
            scripts/config.py unset MBEDTLS_DHM_C
            scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
            scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
        fi
    fi

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE
}

# Common helper used by:
# - component_test_psa_crypto_config_accel_ecc_no_bignum
# - component_test_psa_crypto_config_accel_ecc_ffdh_no_bignum
#
# The goal is to build and test accelerating either:
# - ECC only or
# - both ECC and FFDH
#
# It is meant to be used in conjunction with
# common_test_psa_crypto_config_reference_ecc_ffdh_no_bignum() for drivers
# coverage analysis in the "analyze_outcomes.py" script.
common_test_psa_crypto_config_accel_ecc_ffdh_no_bignum () {
    test_target="$1"

    # This is an internal helper to simplify text message handling
    if [ "$test_target" = "ECC_DH" ]; then
        accel_text="ECC/FFDH"
        removed_text="ECP - DH"
    else
        accel_text="ECC"
        removed_text="ECP"
    fi

    msg "build: full + accelerated $accel_text algs + USE_PSA - $removed_text - BIGNUM"

    # By default we accelerate all EC keys/algs
    loc_accel_list="ALG_ECDSA ALG_DETERMINISTIC_ECDSA \
                    ALG_ECDH \
                    ALG_JPAKE \
                    $(helper_get_psa_key_type_list "ECC") \
                    $(helper_get_psa_curve_list)"
    # Optionally we can also add DH to the list of accelerated items
    if [ "$test_target" = "ECC_DH" ]; then
        loc_accel_list="$loc_accel_list \
                        ALG_FFDH \
                        $(helper_get_psa_key_type_list "DH") \
                        $(helper_get_psa_dh_group_list)"
    fi

    # Configure
    # ---------

    # Set common configurations between library's and driver's builds
    config_psa_crypto_config_accel_ecc_ffdh_no_bignum 1 "$test_target"
    # Disable all the builtin curves. All the required algs are accelerated.
    helper_disable_builtin_curves

    # Build
    # -----

    # Things we wanted supported in libtestdriver1, but not accelerated in the main library:
    # SHA-1 and all SHA-2/3 variants, as they are used by ECDSA deterministic.
    loc_extra_list="ALG_SHA_1 ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"

    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure any built-in EC alg was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ library/ecdsa.o
    not grep mbedtls_ecdh_ library/ecdh.o
    not grep mbedtls_ecjpake_ library/ecjpake.o
    # Also ensure that ECP, RSA, [DHM] or BIGNUM modules were not re-enabled
    not grep mbedtls_ecp_ library/ecp.o
    not grep mbedtls_rsa_ library/rsa.o
    not grep mbedtls_mpi_ library/bignum.o
    not grep mbedtls_dhm_ library/dhm.o

    # Run the tests
    # -------------

    msg "test suites: full + accelerated $accel_text algs + USE_PSA - $removed_text - DHM - BIGNUM"

    make test

    msg "ssl-opt: full + accelerated $accel_text algs + USE_PSA - $removed_text - BIGNUM"
    tests/ssl-opt.sh
}

# Common helper used by:
# - component_test_psa_crypto_config_reference_ecc_no_bignum
# - component_test_psa_crypto_config_reference_ecc_ffdh_no_bignum
#
# The goal is to build and test a reference scenario (i.e. with builtin
# components) compared to the ones used in
# common_test_psa_crypto_config_accel_ecc_ffdh_no_bignum() above.
#
# It is meant to be used in conjunction with
# common_test_psa_crypto_config_accel_ecc_ffdh_no_bignum() for drivers'
# coverage analysis in "analyze_outcomes.py" script.
common_test_psa_crypto_config_reference_ecc_ffdh_no_bignum () {
    test_target="$1"

    # This is an internal helper to simplify text message handling
    if [ "$test_target" = "ECC_DH" ]; then
        accel_text="ECC/FFDH"
    else
        accel_text="ECC"
    fi

    msg "build: full + non accelerated $accel_text algs + USE_PSA"

    config_psa_crypto_config_accel_ecc_ffdh_no_bignum 0 "$test_target"

    make

    msg "test suites: full + non accelerated EC algs + USE_PSA"
    make test

    msg "ssl-opt: full + non accelerated $accel_text algs + USE_PSA"
    tests/ssl-opt.sh
}

component_test_psa_crypto_config_accel_ecc_no_bignum () {
    common_test_psa_crypto_config_accel_ecc_ffdh_no_bignum "ECC"
}

component_test_psa_crypto_config_reference_ecc_no_bignum () {
    common_test_psa_crypto_config_reference_ecc_ffdh_no_bignum "ECC"
}

component_test_psa_crypto_config_accel_ecc_ffdh_no_bignum () {
    common_test_psa_crypto_config_accel_ecc_ffdh_no_bignum "ECC_DH"
}

component_test_psa_crypto_config_reference_ecc_ffdh_no_bignum () {
    common_test_psa_crypto_config_reference_ecc_ffdh_no_bignum "ECC_DH"
}

# Helper for setting common configurations between:
# - component_test_tfm_config_p256m_driver_accel_ec()
# - component_test_tfm_config()
common_tfm_config () {
    # Enable TF-M config
    cp configs/config-tfm.h "$CONFIG_H"
    echo "#undef MBEDTLS_PSA_CRYPTO_CONFIG_FILE" >> "$CONFIG_H"
    cp configs/ext/crypto_config_profile_medium.h "$CRYPTO_CONFIG_H"

    # Other config adjustment to make the tests pass.
    # This should probably be adopted upstream.
    #
    # - USE_PSA_CRYPTO for PK_HAVE_ECC_KEYS
    echo "#define MBEDTLS_USE_PSA_CRYPTO" >> "$CONFIG_H"

    # Config adjustment for better test coverage in our environment.
    # This is not needed just to build and pass tests.
    #
    # Enable filesystem I/O for the benefit of PK parse/write tests.
    echo "#define MBEDTLS_FS_IO" >> "$CONFIG_H"
}

# Keep this in sync with component_test_tfm_config() as they are both meant
# to be used in analyze_outcomes.py for driver's coverage analysis.
component_test_tfm_config_p256m_driver_accel_ec () {
    msg "build: TF-M config + p256m driver + accel ECDH(E)/ECDSA"

    common_tfm_config

    # Build crypto library
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -I../tests/include/spe" LDFLAGS="$ASAN_CFLAGS"

    # Make sure any built-in EC alg was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ library/ecdsa.o
    not grep mbedtls_ecdh_ library/ecdh.o
    not grep mbedtls_ecjpake_ library/ecjpake.o
    # Also ensure that ECP, RSA, DHM or BIGNUM modules were not re-enabled
    not grep mbedtls_ecp_ library/ecp.o
    not grep mbedtls_rsa_ library/rsa.o
    not grep mbedtls_dhm_ library/dhm.o
    not grep mbedtls_mpi_ library/bignum.o
    # Check that p256m was built
    grep -q p256_ecdsa_ library/libmbedcrypto.a

    # In "config-tfm.h" we disabled CIPHER_C tweaking TF-M's configuration
    # files, so we want to ensure that it has not be re-enabled accidentally.
    not grep mbedtls_cipher library/cipher.o

    # Run the tests
    msg "test: TF-M config + p256m driver + accel ECDH(E)/ECDSA"
    make test
}

# Keep this in sync with component_test_tfm_config_p256m_driver_accel_ec() as
# they are both meant to be used in analyze_outcomes.py for driver's coverage
# analysis.
component_test_tfm_config() {
    common_tfm_config

    # Disable P256M driver, which is on by default, so that analyze_outcomes
    # can compare this test with test_tfm_config_p256m_driver_accel_ec
    echo "#undef MBEDTLS_PSA_P256M_DRIVER_ENABLED" >> "$CONFIG_H"

    msg "build: TF-M config"
    make CFLAGS='-Werror -Wall -Wextra -I../tests/include/spe' tests

    # Check that p256m was not built
    not grep p256_ecdsa_ library/libmbedcrypto.a

    # In "config-tfm.h" we disabled CIPHER_C tweaking TF-M's configuration
    # files, so we want to ensure that it has not be re-enabled accidentally.
    not grep mbedtls_cipher library/cipher.o

    msg "test: TF-M config"
    make test
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

# This is an helper used by:
# - component_test_psa_ecc_key_pair_no_derive
# - component_test_psa_ecc_key_pair_no_generate
# The goal is to test with all PSA_WANT_KEY_TYPE_xxx_KEY_PAIR_yyy symbols
# enabled, but one. Input arguments are as follows:
# - $1 is the key type under test, i.e. ECC/RSA/DH
# - $2 is the key option to be unset (i.e. generate, derive, etc)
build_and_test_psa_want_key_pair_partial() {
    key_type=$1
    unset_option=$2
    disabled_psa_want="PSA_WANT_KEY_TYPE_${key_type}_KEY_PAIR_${unset_option}"

    msg "build: full - MBEDTLS_USE_PSA_CRYPTO - ${disabled_psa_want}"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3

    # All the PSA_WANT_KEY_TYPE_xxx_KEY_PAIR_yyy are enabled by default in
    # crypto_config.h so we just disable the one we don't want.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset "$disabled_psa_want"

    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full - MBEDTLS_USE_PSA_CRYPTO - ${disabled_psa_want}"
    make test
}

component_test_psa_ecc_key_pair_no_derive() {
    build_and_test_psa_want_key_pair_partial "ECC" "DERIVE"
}

component_test_psa_ecc_key_pair_no_generate() {
    build_and_test_psa_want_key_pair_partial "ECC" "GENERATE"
}

config_psa_crypto_accel_rsa () {
    driver_only=$1

    # Start from crypto_full config (no X.509, no TLS)
    helper_libtestdriver1_adjust_config "crypto_full"

    if [ "$driver_only" -eq 1 ]; then
        # Remove RSA support and its dependencies
        scripts/config.py unset MBEDTLS_RSA_C
        scripts/config.py unset MBEDTLS_PKCS1_V15
        scripts/config.py unset MBEDTLS_PKCS1_V21

        # We need PEM parsing in the test library as well to support the import
        # of PEM encoded RSA keys.
        scripts/config.py -f "$CONFIG_TEST_DRIVER_H" set MBEDTLS_PEM_PARSE_C
        scripts/config.py -f "$CONFIG_TEST_DRIVER_H" set MBEDTLS_BASE64_C
    fi
}

component_test_psa_crypto_config_accel_rsa_crypto () {
    msg "build: crypto_full with accelerated RSA"

    loc_accel_list="ALG_RSA_OAEP ALG_RSA_PSS \
                    ALG_RSA_PKCS1V15_CRYPT ALG_RSA_PKCS1V15_SIGN \
                    KEY_TYPE_RSA_PUBLIC_KEY \
                    KEY_TYPE_RSA_KEY_PAIR_BASIC \
                    KEY_TYPE_RSA_KEY_PAIR_GENERATE \
                    KEY_TYPE_RSA_KEY_PAIR_IMPORT \
                    KEY_TYPE_RSA_KEY_PAIR_EXPORT"

    # Configure
    # ---------

    config_psa_crypto_accel_rsa 1

    # Build
    # -----

    # These hashes are needed for unit tests.
    loc_extra_list="ALG_SHA_1 ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512 ALG_MD5"
    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_rsa library/rsa.o

    # Run the tests
    # -------------

    msg "test: crypto_full with accelerated RSA"
    make test
}

component_test_psa_crypto_config_reference_rsa_crypto () {
    msg "build: crypto_full with non-accelerated RSA"

    # Configure
    # ---------
    config_psa_crypto_accel_rsa 0

    # Build
    # -----
    make

    # Run the tests
    # -------------
    msg "test: crypto_full with non-accelerated RSA"
    make test
}

# This is a temporary test to verify that full RSA support is present even when
# only one single new symbols (PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC) is defined.
component_test_new_psa_want_key_pair_symbol() {
    msg "Build: crypto config - MBEDTLS_RSA_C + PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC"

    # Create a temporary output file unless there is already one set
    if [ "$MBEDTLS_TEST_OUTCOME_FILE" ]; then
        REMOVE_OUTCOME_ON_EXIT="no"
    else
        REMOVE_OUTCOME_ON_EXIT="yes"
        MBEDTLS_TEST_OUTCOME_FILE="$PWD/out.csv"
        export MBEDTLS_TEST_OUTCOME_FILE
    fi

    # Start from crypto configuration
    scripts/config.py crypto

    # Remove RSA support and its dependencies
    scripts/config.py unset MBEDTLS_PKCS1_V15
    scripts/config.py unset MBEDTLS_PKCS1_V21
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_RSA_C
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT

    # Enable PSA support
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG

    # Keep only PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC enabled in order to ensure
    # that proper translations is done in crypto_legacy.h.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE

    make

    msg "Test: crypto config - MBEDTLS_RSA_C + PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC"
    make test

    # Parse only 1 relevant line from the outcome file, i.e. a test which is
    # performing RSA signature.
    msg "Verify that 'RSA PKCS1 Sign #1 (SHA512, 1536 bits RSA)' is PASS"
    cat $MBEDTLS_TEST_OUTCOME_FILE | grep 'RSA PKCS1 Sign #1 (SHA512, 1536 bits RSA)' | grep -q "PASS"

    if [ "$REMOVE_OUTCOME_ON_EXIT" == "yes" ]; then
        rm $MBEDTLS_TEST_OUTCOME_FILE
    fi
}

component_test_psa_crypto_config_accel_hash () {
    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated hash"

    loc_accel_list="ALG_MD5 ALG_RIPEMD160 ALG_SHA_1 \
                    ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"

    # Configure
    # ---------

    # Start from default config (no USE_PSA)
    helper_libtestdriver1_adjust_config "default"

    # Disable the things that are being accelerated
    scripts/config.py unset MBEDTLS_MD5_C
    scripts/config.py unset MBEDTLS_RIPEMD160_C
    scripts/config.py unset MBEDTLS_SHA1_C
    scripts/config.py unset MBEDTLS_SHA224_C
    scripts/config.py unset MBEDTLS_SHA256_C
    scripts/config.py unset MBEDTLS_SHA384_C
    scripts/config.py unset MBEDTLS_SHA512_C
    scripts/config.py unset MBEDTLS_SHA3_C

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # There's a risk of something getting re-enabled via config_psa.h;
    # make sure it did not happen. Note: it's OK for MD_C to be enabled.
    not grep mbedtls_md5 library/md5.o
    not grep mbedtls_sha1 library/sha1.o
    not grep mbedtls_sha256 library/sha256.o
    not grep mbedtls_sha512 library/sha512.o
    not grep mbedtls_ripemd160 library/ripemd160.o

    # Run the tests
    # -------------

    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated hash"
    make test
}

# Auxiliary function to build config for hashes with and without drivers
config_psa_crypto_hash_use_psa () {
    driver_only="$1"
    # start with config full for maximum coverage (also enables USE_PSA)
    helper_libtestdriver1_adjust_config "full"
    if [ "$driver_only" -eq 1 ]; then
        # disable the built-in implementation of hashes
        scripts/config.py unset MBEDTLS_MD5_C
        scripts/config.py unset MBEDTLS_RIPEMD160_C
        scripts/config.py unset MBEDTLS_SHA1_C
        scripts/config.py unset MBEDTLS_SHA224_C
        scripts/config.py unset MBEDTLS_SHA256_C # see external RNG below
        scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
        scripts/config.py unset MBEDTLS_SHA384_C
        scripts/config.py unset MBEDTLS_SHA512_C
        scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT
        scripts/config.py unset MBEDTLS_SHA3_C
    fi
}

# Note that component_test_psa_crypto_config_reference_hash_use_psa
# is related to this component and both components need to be kept in sync.
# For details please see comments for component_test_psa_crypto_config_reference_hash_use_psa.
component_test_psa_crypto_config_accel_hash_use_psa () {
    msg "test: full with accelerated hashes"

    loc_accel_list="ALG_MD5 ALG_RIPEMD160 ALG_SHA_1 \
                    ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"

    # Configure
    # ---------

    config_psa_crypto_hash_use_psa 1

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # There's a risk of something getting re-enabled via config_psa.h;
    # make sure it did not happen. Note: it's OK for MD_C to be enabled.
    not grep mbedtls_md5 library/md5.o
    not grep mbedtls_sha1 library/sha1.o
    not grep mbedtls_sha256 library/sha256.o
    not grep mbedtls_sha512 library/sha512.o
    not grep mbedtls_ripemd160 library/ripemd160.o

    # Run the tests
    # -------------

    msg "test: full with accelerated hashes"
    make test

    # This is mostly useful so that we can later compare outcome files with
    # the reference config in analyze_outcomes.py, to check that the
    # dependency declarations in ssl-opt.sh and in TLS code are correct.
    msg "test: ssl-opt.sh, full with accelerated hashes"
    tests/ssl-opt.sh

    # This is to make sure all ciphersuites are exercised, but we don't need
    # interop testing (besides, we already got some from ssl-opt.sh).
    msg "test: compat.sh, full with accelerated hashes"
    tests/compat.sh -p mbedTLS -V YES
}

# This component provides reference configuration for test_psa_crypto_config_accel_hash_use_psa
# without accelerated hash. The outcome from both components are used by the analyze_outcomes.py
# script to find regression in test coverage when accelerated hash is used (tests and ssl-opt).
# Both components need to be kept in sync.
component_test_psa_crypto_config_reference_hash_use_psa() {
    msg "test: full without accelerated hashes"

    config_psa_crypto_hash_use_psa 0

    make

    msg "test: full without accelerated hashes"
    make test

    msg "test: ssl-opt.sh, full without accelerated hashes"
    tests/ssl-opt.sh
}

# Auxiliary function to build config for hashes with and without drivers
config_psa_crypto_hmac_use_psa () {
    driver_only="$1"
    # start with config full for maximum coverage (also enables USE_PSA)
    helper_libtestdriver1_adjust_config "full"

    if [ "$driver_only" -eq 1 ]; then
        # Disable MD_C in order to disable the builtin support for HMAC. MD_LIGHT
        # is still enabled though (for ENTROPY_C among others).
        scripts/config.py unset MBEDTLS_MD_C
        # Disable also the builtin hashes since they are supported by the driver
        # and MD module is able to perform PSA dispathing.
        scripts/config.py unset-all MBEDTLS_SHA
        scripts/config.py unset MBEDTLS_MD5_C
        scripts/config.py unset MBEDTLS_RIPEMD160_C
    fi

    # Direct dependencies of MD_C. We disable them also in the reference
    # component to work with the same set of features.
    scripts/config.py unset MBEDTLS_PKCS7_C
    scripts/config.py unset MBEDTLS_PKCS5_C
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_HKDF_C
    # Dependencies of HMAC_DRBG
    scripts/config.py unset MBEDTLS_ECDSA_DETERMINISTIC
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_DETERMINISTIC_ECDSA
}

component_test_psa_crypto_config_accel_hmac() {
    msg "test: full with accelerated hmac"

    loc_accel_list="ALG_HMAC KEY_TYPE_HMAC \
                    ALG_MD5 ALG_RIPEMD160 ALG_SHA_1 \
                    ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"

    # Configure
    # ---------

    config_psa_crypto_hmac_use_psa 1

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Ensure that built-in support for HMAC is disabled.
    not grep mbedtls_md_hmac library/md.o

    # Run the tests
    # -------------

    msg "test: full with accelerated hmac"
    make test
}

component_test_psa_crypto_config_reference_hmac() {
    msg "test: full without accelerated hmac"

    config_psa_crypto_hmac_use_psa 0

    make

    msg "test: full without accelerated hmac"
    make test
}

component_test_psa_crypto_config_accel_des () {
    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated DES"

    # Albeit this components aims at accelerating DES which should only support
    # CBC and ECB modes, we need to accelerate more than that otherwise DES_C
    # would automatically be re-enabled by "config_adjust_legacy_from_psa.c"
    loc_accel_list="ALG_ECB_NO_PADDING ALG_CBC_NO_PADDING ALG_CBC_PKCS7 \
                    ALG_CTR ALG_CFB ALG_OFB ALG_XTS ALG_CMAC \
                    KEY_TYPE_DES"

    # Note: we cannot accelerate all ciphers' key types otherwise we would also
    # have to either disable CCM/GCM or accelerate them, but that's out of scope
    # of this component. This limitation will be addressed by #8598.

    # Configure
    # ---------

    # Start from the full config
    helper_libtestdriver1_adjust_config "full"

    # Disable the things that are being accelerated
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CBC
    scripts/config.py unset MBEDTLS_CIPHER_PADDING_PKCS7
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CTR
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CFB
    scripts/config.py unset MBEDTLS_CIPHER_MODE_OFB
    scripts/config.py unset MBEDTLS_CIPHER_MODE_XTS
    scripts/config.py unset MBEDTLS_DES_C
    scripts/config.py unset MBEDTLS_CMAC_C

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_des* library/des.o

    # Run the tests
    # -------------

    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated DES"
    make test
}

component_test_psa_crypto_config_accel_aead () {
    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated AEAD"

    loc_accel_list="ALG_GCM ALG_CCM ALG_CHACHA20_POLY1305 \
                    KEY_TYPE_AES KEY_TYPE_CHACHA20 KEY_TYPE_ARIA KEY_TYPE_CAMELLIA"

    # Configure
    # ---------

    # Start from full config
    helper_libtestdriver1_adjust_config "full"

    # Disable things that are being accelerated
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py unset MBEDTLS_CCM_C
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C

    # Disable CCM_STAR_NO_TAG because this re-enables CCM_C.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CCM_STAR_NO_TAG

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_ccm library/ccm.o
    not grep mbedtls_gcm library/gcm.o
    not grep mbedtls_chachapoly library/chachapoly.o

    # Run the tests
    # -------------

    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated AEAD"
    make test
}

# This is a common configuration function used in:
# - component_test_psa_crypto_config_accel_cipher_aead_cmac
# - component_test_psa_crypto_config_reference_cipher_aead_cmac
common_psa_crypto_config_accel_cipher_aead_cmac() {
    # Start from the full config
    helper_libtestdriver1_adjust_config "full"

    scripts/config.py unset MBEDTLS_NIST_KW_C
}

# The 2 following test components, i.e.
# - component_test_psa_crypto_config_accel_cipher_aead_cmac
# - component_test_psa_crypto_config_reference_cipher_aead_cmac
# are meant to be used together in analyze_outcomes.py script in order to test
# driver's coverage for ciphers and AEADs.
component_test_psa_crypto_config_accel_cipher_aead_cmac () {
    msg "build: full config with accelerated cipher inc. AEAD and CMAC"

    loc_accel_list="ALG_ECB_NO_PADDING ALG_CBC_NO_PADDING ALG_CBC_PKCS7 ALG_CTR ALG_CFB \
                    ALG_OFB ALG_XTS ALG_STREAM_CIPHER ALG_CCM_STAR_NO_TAG \
                    ALG_GCM ALG_CCM ALG_CHACHA20_POLY1305 ALG_CMAC \
                    KEY_TYPE_DES KEY_TYPE_AES KEY_TYPE_ARIA KEY_TYPE_CHACHA20 KEY_TYPE_CAMELLIA"

    # Configure
    # ---------

    common_psa_crypto_config_accel_cipher_aead_cmac

    # Disable the things that are being accelerated
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CBC
    scripts/config.py unset MBEDTLS_CIPHER_PADDING_PKCS7
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CTR
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CFB
    scripts/config.py unset MBEDTLS_CIPHER_MODE_OFB
    scripts/config.py unset MBEDTLS_CIPHER_MODE_XTS
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py unset MBEDTLS_CCM_C
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    scripts/config.py unset MBEDTLS_CMAC_C
    scripts/config.py unset MBEDTLS_DES_C
    scripts/config.py unset MBEDTLS_AES_C
    scripts/config.py unset MBEDTLS_ARIA_C
    scripts/config.py unset MBEDTLS_CHACHA20_C
    scripts/config.py unset MBEDTLS_CAMELLIA_C

    # Disable CIPHER_C entirely as all ciphers/AEADs are accelerated and PSA
    # does not depend on it.
    scripts/config.py unset MBEDTLS_CIPHER_C

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_cipher library/cipher.o
    not grep mbedtls_des library/des.o
    not grep mbedtls_aes library/aes.o
    not grep mbedtls_aria library/aria.o
    not grep mbedtls_camellia library/camellia.o
    not grep mbedtls_ccm library/ccm.o
    not grep mbedtls_gcm library/gcm.o
    not grep mbedtls_chachapoly library/chachapoly.o
    not grep mbedtls_cmac library/cmac.o

    # Run the tests
    # -------------

    msg "test: full config with accelerated cipher inc. AEAD and CMAC"
    make test

    msg "ssl-opt: full config with accelerated cipher inc. AEAD and CMAC"
    tests/ssl-opt.sh

    msg "compat.sh: full config with accelerated cipher inc. AEAD and CMAC"
    tests/compat.sh -V NO -p mbedTLS
}

component_test_psa_crypto_config_reference_cipher_aead_cmac () {
    msg "build: full config with non-accelerated cipher inc. AEAD and CMAC"
    common_psa_crypto_config_accel_cipher_aead_cmac

    make

    msg "test: full config with non-accelerated cipher inc. AEAD and CMAC"
    make test

    msg "ssl-opt: full config with non-accelerated cipher inc. AEAD and CMAC"
    tests/ssl-opt.sh

    msg "compat.sh: full config with non-accelerated cipher inc. AEAD and CMAC"
    tests/compat.sh -V NO -p mbedTLS
}

common_block_cipher_dispatch() {
    TEST_WITH_DRIVER="$1"

    # Start from the full config
    helper_libtestdriver1_adjust_config "full"

    if [ "$TEST_WITH_DRIVER" -eq 1 ]; then
        # Disable key types that are accelerated (there is no legacy equivalent
        # symbol for ECB)
        scripts/config.py unset MBEDTLS_AES_C
        scripts/config.py unset MBEDTLS_ARIA_C
        scripts/config.py unset MBEDTLS_CAMELLIA_C
    fi

    # Disable cipher's modes that, when not accelerated, cause
    # legacy key types to be re-enabled in "config_adjust_legacy_from_psa.h".
    # Keep this also in the reference component in order to skip the same tests
    # that were skipped in the accelerated one.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CTR
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CFB
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_OFB
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_NO_PADDING
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_PKCS7
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CMAC
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CCM_STAR_NO_TAG

    # Disable direct dependency on AES_C
    scripts/config.py unset MBEDTLS_NIST_KW_C

    # Prevent the cipher module from using deprecated PSA path. The reason is
    # that otherwise there will be tests relying on "aes_info" (defined in
    # "cipher_wrap.c") whose functions are not available when AES_C is
    # not defined. ARIA and Camellia are not a problem in this case because
    # the PSA path is not tested for these key types.
    scripts/config.py set MBEDTLS_DEPRECATED_REMOVED
}

component_test_full_block_cipher_psa_dispatch () {
    msg "build: full + PSA dispatch in block_cipher"

    loc_accel_list="ALG_ECB_NO_PADDING \
                    KEY_TYPE_AES KEY_TYPE_ARIA KEY_TYPE_CAMELLIA"

    # Configure
    # ---------

    common_block_cipher_dispatch 1

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure disabled components were not re-enabled by accident (additive
    # config)
    not grep mbedtls_aes_ library/aes.o
    not grep mbedtls_aria_ library/aria.o
    not grep mbedtls_camellia_ library/camellia.o

    # Run the tests
    # -------------

    msg "test: full + PSA dispatch in block_cipher"
    make test
}

# This is the reference component of component_test_full_block_cipher_psa_dispatch
component_test_full_block_cipher_legacy_dispatch () {
    msg "build: full + legacy dispatch in block_cipher"

    common_block_cipher_dispatch 0

    make

    msg "test: full + legacy dispatch in block_cipher"
    make test
}

component_test_aead_chachapoly_disabled() {
    msg "build: full minus CHACHAPOLY"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CHACHA20_POLY1305
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full minus CHACHAPOLY"
    make test
}

component_test_aead_only_ccm() {
    msg "build: full minus CHACHAPOLY and GCM"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CHACHA20_POLY1305
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_GCM
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full minus CHACHAPOLY and GCM"
    make test
}

component_test_ccm_aes_sha256() {
    msg "build: CCM + AES + SHA256 configuration"

    cp "$CONFIG_TEST_DRIVER_H" "$CONFIG_H"
    cp configs/crypto-config-ccm-aes-sha256.h "$CRYPTO_CONFIG_H"

    make

    msg "test: CCM + AES + SHA256 configuration"
    make test
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

    msg "test: compat.sh default (full minus PSA crypto)"
    tests/compat.sh

    msg "test: compat.sh NULL (full minus PSA crypto)"
    tests/compat.sh -f 'NULL'

    msg "test: compat.sh ARIA + ChachaPoly (full minus PSA crypto)"
    env OPENSSL="$OPENSSL_NEXT" tests/compat.sh -e '^$' -f 'ARIA\|CHACHA'
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
    scripts/config.py unset MBEDTLS_CIPHER_NULL_CIPHER
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CBC
    scripts/config.py unset MBEDTLS_CMAC_C
    make

    msg "test: !MBEDTLS_SSL_SOME_MODES_USE_MAC"
    make test

    msg "test ssl-opt.sh: !MBEDTLS_SSL_SOME_MODES_USE_MAC"
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

component_test_min_mpi_window_size () {
    msg "build: Default + MBEDTLS_MPI_WINDOW_SIZE=1 (ASan build)" # ~ 10s
    scripts/config.py set MBEDTLS_MPI_WINDOW_SIZE 1
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: MBEDTLS_MPI_WINDOW_SIZE=1 - main suites (inc. selftests) (ASan build)" # ~ 10s
    make test
}

component_test_have_int32 () {
    msg "build: gcc, force 32-bit bignum limbs"
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_PADLOCK_C
    scripts/config.py unset MBEDTLS_AESCE_C
    make CC=gcc CFLAGS='-O2 -Werror -Wall -Wextra -DMBEDTLS_HAVE_INT32'

    msg "test: gcc, force 32-bit bignum limbs"
    make test
}

component_test_have_int64 () {
    msg "build: gcc, force 64-bit bignum limbs"
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_PADLOCK_C
    scripts/config.py unset MBEDTLS_AESCE_C
    make CC=gcc CFLAGS='-O2 -Werror -Wall -Wextra -DMBEDTLS_HAVE_INT64'

    msg "test: gcc, force 64-bit bignum limbs"
    make test
}

component_test_have_int32_cmake_new_bignum () {
    msg "build: gcc, force 32-bit bignum limbs, new bignum interface, test hooks (ASan build)"
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_PADLOCK_C
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
