/**
 * \file x509_internal.h
 *
 * \brief Internal X.509 functions
 */
/*
 *  Copyright (C) 2006-2019, ARM Limited, All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 *
 */
#ifndef MBEDTLS_X509_INTERNAL_H
#define MBEDTLS_X509_INTERNAL_H

#include "x509.h"
#include "threading.h"

/* Internal structure used for caching parsed data from an X.509 CRT. */

struct mbedtls_x509_crt;
struct mbedtls_pk_context;
struct mbedtls_x509_crt_frame;
#define MBEDTLS_X509_CACHE_PK_READERS_MAX    ((uint32_t) -1)
#define MBEDTLS_X509_CACHE_FRAME_READERS_MAX ((uint32_t) -1)

/* Internal X.509 CRT cache handling functions. */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
static int mbedtls_x509_crt_flush_cache_frame( struct mbedtls_x509_crt const *crt );
static int mbedtls_x509_crt_flush_cache_pk( struct mbedtls_x509_crt const *crt );

static int mbedtls_x509_crt_cache_provide_frame( struct mbedtls_x509_crt const *crt );
static int mbedtls_x509_crt_cache_provide_pk( struct mbedtls_x509_crt const *crt );
#endif /* MBEDTLS_X509_CRT_PARSE_C */

/* Uncategorized internal X.509 functions */
static int mbedtls_x509_get_name( unsigned char *p, size_t len,
                           mbedtls_x509_name *cur );

#if defined(MBEDTLS_X509_CRL_PARSE_C) || defined(MBEDTLS_X509_CSR_PARSE_C) || \
    ( !defined(MBEDTLS_X509_ON_DEMAND_PARSING) && defined(MBEDTLS_X509_CRT_PARSE_C) )
static int mbedtls_x509_get_alg( unsigned char **p, const unsigned char *end,
                  mbedtls_x509_buf *alg, mbedtls_x509_buf *params );
#endif /* defined(MBEDTLS_X509_CRL_PARSE_C) || defined(MBEDTLS_X509_CSR_PARSE_C) ||
          ( !defined(MBEDTLS_X509_ON_DEMAND_PARSING) && defined(MBEDTLS_X509_CRT_PARSE_C) ) */

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
static int mbedtls_x509_get_alg_null( unsigned char **p, const unsigned char *end,
                       mbedtls_x509_buf *alg );
static int mbedtls_x509_get_rsassa_pss_params( const mbedtls_x509_buf *params,
                                mbedtls_md_type_t *md_alg, mbedtls_md_type_t *mgf_md,
                                int *salt_len );
#endif
static int mbedtls_x509_get_sig( unsigned char **p, const unsigned char *end, mbedtls_x509_buf *sig );
static int mbedtls_x509_get_sig_alg_raw( unsigned char **p, unsigned char const *end,
                                  mbedtls_md_type_t *md_alg,
                                  mbedtls_pk_type_t *pk_alg,
                                  void **sig_opts );
static int mbedtls_x509_get_sig_alg( const mbedtls_x509_buf *sig_oid, const mbedtls_x509_buf *sig_params,
                      mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg,
                      void **sig_opts );

#if ( !defined(MBEDTLS_X509_CRT_REMOVE_TIME) && defined(MBEDTLS_X509_CRT_PARSE_C) ) || \
    defined(MBEDTLS_X509_CRL_PARSE_C)
static int mbedtls_x509_get_time( unsigned char **p, const unsigned char *end,
                   mbedtls_x509_time *t );
#endif /* ( !defined(MBEDTLS_X509_CRT_REMOVE_TIME) && defined(MBEDTLS_X509_CRT_PARSE_C) ) ||
          defined(MBEDTLS_X509_CRL_PARSE_C) */

static int mbedtls_x509_get_serial( unsigned char **p, const unsigned char *end,
                     mbedtls_x509_buf *serial );
static int mbedtls_x509_name_cmp_raw( mbedtls_x509_buf_raw const *a,
                               mbedtls_x509_buf_raw const *b,
                               int (*check)( void *ctx,
                                             mbedtls_x509_buf *oid,
                                             mbedtls_x509_buf *val,
                                             int next_merged ),
                               void *check_ctx );
static int mbedtls_x509_memcasecmp( const void *s1, const void *s2,
                             size_t len1, size_t len2 );

#if defined(MBEDTLS_X509_CRL_PARSE_C)
static int mbedtls_x509_get_ext( unsigned char **p, const unsigned char *end,
                  mbedtls_x509_buf *ext, int tag );
#endif /* defined(MBEDTLS_X509_CRL_PARSE_C) */

#if !defined(MBEDTLS_X509_REMOVE_INFO)
static int mbedtls_x509_sig_alg_gets( char *buf, size_t size,
                       mbedtls_pk_type_t pk_alg, mbedtls_md_type_t md_alg,
                       const void *sig_opts );
#endif
#if !defined(MBEDTLS_X509_REMOVE_INFO)
static int mbedtls_x509_key_size_helper( char *buf, size_t buf_size, const char *name );
#endif /* !defined(MBEDTLS_X509_REMOVE_INFO) */

#if defined(MBEDTLS_X509_CREATE_C)
static int mbedtls_x509_string_to_names( mbedtls_asn1_named_data **head, const char *name );
static int mbedtls_x509_set_extension( mbedtls_asn1_named_data **head, const char *oid, size_t oid_len,
                        int critical, const unsigned char *val,
                        size_t val_len );
static int mbedtls_x509_write_extensions( unsigned char **p, unsigned char *start,
                           mbedtls_asn1_named_data *first );
int mbedtls_x509_write_names( unsigned char **p, unsigned char *start,
                      mbedtls_asn1_named_data *first );
static int mbedtls_x509_write_sig( unsigned char **p, unsigned char *start,
                    const char *oid, size_t oid_len,
                    unsigned char *sig, size_t size );
#endif /* MBEDTLS_X509_CREATE_C */
#endif /* MBEDTLS_X509_INTERNAL_H */
