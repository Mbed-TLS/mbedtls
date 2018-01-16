/*
 *  Common code for SSL test programs
 *
 *  Copyright (C) 2018, ARM Limited, All Rights Reserved
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

#ifndef POLARSSL_PROGRAMS_SSL_SSL_TEST_LIB_H
#define POLARSSL_PROGRAMS_SSL_SSL_TEST_LIB_H

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define polarssl_free       free
#define polarssl_malloc     malloc
#define polarssl_printf     printf
#define polarssl_fprintf    fprintf
#define polarssl_printf     printf
#define polarssl_snprintf   snprintf
#endif

#if defined(POLARSSL_ENTROPY_C) && \
    defined(POLARSSL_SSL_TLS_C) && \
    defined(POLARSSL_NET_C) && \
    defined(POLARSSL_CTR_DRBG_C)
#define POLARSSL_PROGRAMS_SSL__PREREQUISITES

#include <string.h>
#include <stdint.h>

#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/error.h"
#include "polarssl/debug.h"

#if defined(POLARSSL_TIMING_C)
#include "polarssl/timing.h"
#endif

#if defined(_MSC_VER) && !defined(EFIX64) && !defined(EFI32)
#if !defined  snprintf
#define  snprintf  _snprintf
#endif
#endif

#define STRINGIFY_( arg ) #arg
#define STRINGIFY( arg ) STRINGIFY_( arg )


/* Default values for some options that are intrinsically shared by
 * the client and the server. */
#define DFL_SERVER_ADDR         NULL
#define DFL_SERVER_PORT         4433
#define DFL_PSK                 ""
#define DFL_PSK_IDENTITY        "Client_identity"


void polarssl_ssl_test_debug( void *ctx, int level, const char *str );

/* Test if fake entropy is provided.
 *
 * The fake entropy mode is designed to make tests reproducible,
 * mostly for debugging purposes. It offers no security whatsoever.
 * Note that to achieve reproducible tests, you must also either
 * undefine POLARSSL_HAVE_TIME or arrange to set a constant fake time
 * (e.g. with faketime). */
int polarssl_ssl_test_rng_use_fake_entropy( const char *fake_entropy );

/* Initialize ctr_drbg, either from fake_entropy (if this is a
 * non-empty string) or from the default entropy sources (otherwise). */
int polarssl_ssl_test_rng_init( const char *fake_entropy,
                                const char *pers,
                                entropy_context *entropy,
                                ctr_drbg_context *ctr_drbg );
/* Reinitialize ctr_drbg from fake_entropy, if this is a non-empty string.
 * Do nothing otherwise. */
void polarssl_ssl_test_rng_reset_if_fake( const char *fake_entropy,
                                          const char *pers,
                                          ctr_drbg_context *ctr_drbg );

/*
 * Test recv/send functions that make sure each try returns
 * WANT_READ/WANT_WRITE at least once before sucesseding
 */
int polarssl_ssl_test_recv( void *ctx, unsigned char *buf, size_t len );
int polarssl_ssl_test_send( void *ctx, const unsigned char *buf, size_t len );

int polarssl_ssl_test_forced_ciphersuite( int force_ciphersuite,
                                          int min_version,
                                          int max_version );

#define POLARSSL_SSL_TEST_BAD_VERSION ( -1 )
/* Return TLS minor version from string, or -1 on error. */
int polarssl_ssl_test_parse_version( const char *p, const char *q );

/*
 * Return authmode from string, or -1 on error
 */
int polarssl_ssl_test_get_auth_mode( const char *s );

/*
 * Convert a hex string to bytes.
 * Return 0 on success, -1 on error.
 */
int polarssl_ssl_test_unhexify( const char *input,
                                unsigned char *output, size_t osize,
                                size_t *olen );

#if defined(POLARSSL_SSL_SET_CURVES)
#define CURVE_LIST_SIZE 20
int polarssl_ssl_test_parse_curves( char *p,
                                    ecp_group_id *curve_list );
#endif /* POLARSSL_SSL_SET_CURVES */

#if defined(POLARSSL_SSL_ALPN)
#define ALPN_LIST_SIZE  10
int polarssl_ssl_test_parse_alpn( char *p,
                                 const char *alpn_list[] );
#endif /* POLARSSL_SSL_ALPN */

#endif /* POLARSSL_PROGRAMS_SSL__PREREQUISITES */
#endif /* POLARSSL_PROGRAMS_SSL_SSL_TEST_LIB_H */
