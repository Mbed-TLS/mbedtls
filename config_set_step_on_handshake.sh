#!/usr/bin/env bash

scripts/config.py set MBEDTLS_TEST_HOOKS
scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_2
scripts/config.py set MBEDTLS_SSL_CLI_C
scripts/config.py set MBEDTLS_SSL_SRV_C
scripts/config.py unset MBEDTLS_SSL_PROTO_DTLS
./tf-psa-crypto/scripts/config.py set PSA_WANT_ALG_SHA_384
