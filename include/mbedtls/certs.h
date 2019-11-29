/**
 * \file certs.h
 *
 * \brief Sample certificates and DHM parameters for testing
 */
/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_CERTS_H
#define MBEDTLS_CERTS_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/export.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* List of all PEM-encoded CA certificates, terminated by NULL;
 * PEM encoded if MBEDTLS_PEM_PARSE_C is enabled, DER encoded
 * otherwise. */
MBEDX509_EXTERN const char * mbedtls_test_cas[];
MBEDX509_EXTERN const size_t mbedtls_test_cas_len[];

/* List of all DER-encoded CA certificates, terminated by NULL */
MBEDX509_EXTERN const unsigned char * mbedtls_test_cas_der[];
MBEDX509_EXTERN const size_t mbedtls_test_cas_der_len[];

#if defined(MBEDTLS_PEM_PARSE_C)
/* Concatenation of all CA certificates in PEM format if available */
MBEDX509_EXTERN const char   mbedtls_test_cas_pem[];
MBEDX509_EXTERN const size_t mbedtls_test_cas_pem_len;
#endif /* MBEDTLS_PEM_PARSE_C */

/*
 * CA test certificates
 */

MBEDX509_EXTERN const char mbedtls_test_ca_crt_ec_pem[];
MBEDX509_EXTERN const char mbedtls_test_ca_key_ec_pem[];
MBEDX509_EXTERN const char mbedtls_test_ca_pwd_ec_pem[];
MBEDX509_EXTERN const char mbedtls_test_ca_key_rsa_pem[];
MBEDX509_EXTERN const char mbedtls_test_ca_pwd_rsa_pem[];
MBEDX509_EXTERN const char mbedtls_test_ca_crt_rsa_sha1_pem[];
MBEDX509_EXTERN const char mbedtls_test_ca_crt_rsa_sha256_pem[];

MBEDX509_EXTERN const unsigned char mbedtls_test_ca_crt_ec_der[];
MBEDX509_EXTERN const unsigned char mbedtls_test_ca_key_ec_der[];
MBEDX509_EXTERN const unsigned char mbedtls_test_ca_key_rsa_der[];
MBEDX509_EXTERN const unsigned char mbedtls_test_ca_crt_rsa_sha1_der[];
MBEDX509_EXTERN const unsigned char mbedtls_test_ca_crt_rsa_sha256_der[];

MBEDX509_EXTERN const size_t mbedtls_test_ca_crt_ec_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_key_ec_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_pwd_ec_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_key_rsa_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_pwd_rsa_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_crt_rsa_sha1_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_crt_rsa_sha256_pem_len;

MBEDX509_EXTERN const size_t mbedtls_test_ca_crt_ec_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_key_ec_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_pwd_ec_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_key_rsa_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_pwd_rsa_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_crt_rsa_sha1_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_crt_rsa_sha256_der_len;

/* Config-dependent dispatch between PEM and DER encoding
 * (PEM if enabled, otherwise DER) */

MBEDX509_EXTERN const char mbedtls_test_ca_crt_ec[];
MBEDX509_EXTERN const char mbedtls_test_ca_key_ec[];
MBEDX509_EXTERN const char mbedtls_test_ca_pwd_ec[];
MBEDX509_EXTERN const char mbedtls_test_ca_key_rsa[];
MBEDX509_EXTERN const char mbedtls_test_ca_pwd_rsa[];
MBEDX509_EXTERN const char mbedtls_test_ca_crt_rsa_sha1[];
MBEDX509_EXTERN const char mbedtls_test_ca_crt_rsa_sha256[];

MBEDX509_EXTERN const size_t mbedtls_test_ca_crt_ec_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_key_ec_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_pwd_ec_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_key_rsa_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_pwd_rsa_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_crt_rsa_sha1_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_crt_rsa_sha256_len;

/* Config-dependent dispatch between SHA-1 and SHA-256
 * (SHA-256 if enabled, otherwise SHA-1) */

MBEDX509_EXTERN const char mbedtls_test_ca_crt_rsa[];
MBEDX509_EXTERN const size_t mbedtls_test_ca_crt_rsa_len;

/* Config-dependent dispatch between EC and RSA
 * (RSA if enabled, otherwise EC) */

MBEDX509_EXTERN const char * mbedtls_test_ca_crt;
MBEDX509_EXTERN const char * mbedtls_test_ca_key;
MBEDX509_EXTERN const char * mbedtls_test_ca_pwd;
MBEDX509_EXTERN const size_t mbedtls_test_ca_crt_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_key_len;
MBEDX509_EXTERN const size_t mbedtls_test_ca_pwd_len;

/*
 * Server test certificates
 */

MBEDX509_EXTERN const char mbedtls_test_srv_crt_ec_pem[];
MBEDX509_EXTERN const char mbedtls_test_srv_key_ec_pem[];
MBEDX509_EXTERN const char mbedtls_test_srv_pwd_ec_pem[];
MBEDX509_EXTERN const char mbedtls_test_srv_key_rsa_pem[];
MBEDX509_EXTERN const char mbedtls_test_srv_pwd_rsa_pem[];
MBEDX509_EXTERN const char mbedtls_test_srv_crt_rsa_sha1_pem[];
MBEDX509_EXTERN const char mbedtls_test_srv_crt_rsa_sha256_pem[];

MBEDX509_EXTERN const unsigned char mbedtls_test_srv_crt_ec_der[];
MBEDX509_EXTERN const unsigned char mbedtls_test_srv_key_ec_der[];
MBEDX509_EXTERN const unsigned char mbedtls_test_srv_key_rsa_der[];
MBEDX509_EXTERN const unsigned char mbedtls_test_srv_crt_rsa_sha1_der[];
MBEDX509_EXTERN const unsigned char mbedtls_test_srv_crt_rsa_sha256_der[];

MBEDX509_EXTERN const size_t mbedtls_test_srv_crt_ec_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_key_ec_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_pwd_ec_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_key_rsa_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_pwd_rsa_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_crt_rsa_sha1_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_crt_rsa_sha256_pem_len;

MBEDX509_EXTERN const size_t mbedtls_test_srv_crt_ec_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_key_ec_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_pwd_ec_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_key_rsa_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_pwd_rsa_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_crt_rsa_sha1_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_crt_rsa_sha256_der_len;

/* Config-dependent dispatch between PEM and DER encoding
 * (PEM if enabled, otherwise DER) */

MBEDX509_EXTERN const char mbedtls_test_srv_crt_ec[];
MBEDX509_EXTERN const char mbedtls_test_srv_key_ec[];
MBEDX509_EXTERN const char mbedtls_test_srv_pwd_ec[];
MBEDX509_EXTERN const char mbedtls_test_srv_key_rsa[];
MBEDX509_EXTERN const char mbedtls_test_srv_pwd_rsa[];
MBEDX509_EXTERN const char mbedtls_test_srv_crt_rsa_sha1[];
MBEDX509_EXTERN const char mbedtls_test_srv_crt_rsa_sha256[];

MBEDX509_EXTERN const size_t mbedtls_test_srv_crt_ec_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_key_ec_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_pwd_ec_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_key_rsa_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_pwd_rsa_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_crt_rsa_sha1_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_crt_rsa_sha256_len;

/* Config-dependent dispatch between SHA-1 and SHA-256
 * (SHA-256 if enabled, otherwise SHA-1) */

MBEDX509_EXTERN const char mbedtls_test_srv_crt_rsa[];
MBEDX509_EXTERN const size_t mbedtls_test_srv_crt_rsa_len;

/* Config-dependent dispatch between EC and RSA
 * (RSA if enabled, otherwise EC) */

MBEDX509_EXTERN const char * mbedtls_test_srv_crt;
MBEDX509_EXTERN const char * mbedtls_test_srv_key;
MBEDX509_EXTERN const char * mbedtls_test_srv_pwd;
MBEDX509_EXTERN const size_t mbedtls_test_srv_crt_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_key_len;
MBEDX509_EXTERN const size_t mbedtls_test_srv_pwd_len;

/*
 * Client test certificates
 */

MBEDX509_EXTERN const char mbedtls_test_cli_crt_ec_pem[];
MBEDX509_EXTERN const char mbedtls_test_cli_key_ec_pem[];
MBEDX509_EXTERN const char mbedtls_test_cli_pwd_ec_pem[];
MBEDX509_EXTERN const char mbedtls_test_cli_key_rsa_pem[];
MBEDX509_EXTERN const char mbedtls_test_cli_pwd_rsa_pem[];
MBEDX509_EXTERN const char mbedtls_test_cli_crt_rsa_pem[];

MBEDX509_EXTERN const unsigned char mbedtls_test_cli_crt_ec_der[];
MBEDX509_EXTERN const unsigned char mbedtls_test_cli_key_ec_der[];
MBEDX509_EXTERN const unsigned char mbedtls_test_cli_key_rsa_der[];
MBEDX509_EXTERN const unsigned char mbedtls_test_cli_crt_rsa_der[];

MBEDX509_EXTERN const size_t mbedtls_test_cli_crt_ec_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_key_ec_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_pwd_ec_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_key_rsa_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_pwd_rsa_pem_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_crt_rsa_pem_len;

MBEDX509_EXTERN const size_t mbedtls_test_cli_crt_ec_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_key_ec_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_key_rsa_der_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_crt_rsa_der_len;

/* Config-dependent dispatch between PEM and DER encoding
 * (PEM if enabled, otherwise DER) */

MBEDX509_EXTERN const char mbedtls_test_cli_crt_ec[];
MBEDX509_EXTERN const char mbedtls_test_cli_key_ec[];
MBEDX509_EXTERN const char mbedtls_test_cli_pwd_ec[];
MBEDX509_EXTERN const char mbedtls_test_cli_key_rsa[];
MBEDX509_EXTERN const char mbedtls_test_cli_pwd_rsa[];
MBEDX509_EXTERN const char mbedtls_test_cli_crt_rsa[];

MBEDX509_EXTERN const size_t mbedtls_test_cli_crt_ec_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_key_ec_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_pwd_ec_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_key_rsa_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_pwd_rsa_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_crt_rsa_len;

/* Config-dependent dispatch between EC and RSA
 * (RSA if enabled, otherwise EC) */

MBEDX509_EXTERN const char * mbedtls_test_cli_crt;
MBEDX509_EXTERN const char * mbedtls_test_cli_key;
MBEDX509_EXTERN const char * mbedtls_test_cli_pwd;
MBEDX509_EXTERN const size_t mbedtls_test_cli_crt_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_key_len;
MBEDX509_EXTERN const size_t mbedtls_test_cli_pwd_len;

#ifdef __cplusplus
}
#endif

#endif /* certs.h */
