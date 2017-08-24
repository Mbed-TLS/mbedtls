/*
 *  OCSP response parsing and verification
 *
 *  Copyright (C) 2017, ARM Limited, All Rights Reserved
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
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_free        free
#define mbedtls_calloc      calloc
#define mbedtls_snprintf    snprintf
#endif

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_ocsp.h"
#include "mbedtls/asn1.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/oid.h"

#include <stdint.h>
#include <string.h>

int mbedtls_x509_ocsp_parse_response( mbedtls_x509_ocsp_response *resp,
                                      unsigned char *buf, size_t buflen )
{
    return( 0 );
}

int mbedtls_x509_ocsp_response_info( char *buf, size_t size,
                                     const char *prefix,
                                     const mbedtls_x509_ocsp_response *resp )
{
    return( 0 );
}

int mbedtls_x509_ocsp_parse_response_file( mbedtls_x509_ocsp_response *resp,
                                           const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = mbedtls_x509_ocsp_parse_response( resp, buf, n );

    mbedtls_zeroize( buf, n );
    mbedtls_free( buf );

    return( ret );
}
