/*
 *  PSA crypto layer on top of Mbed TLS crypto
 */
/*  Copyright (C) 2018, ARM Limited, All Rights Reserved
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

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include "psa/crypto.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"


/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n )
{
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

typedef struct {
    int initialized;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} psa_global_data_t;

static psa_global_data_t global_data;

static psa_status_t mbedtls_to_psa_error( int ret )
{
    switch( ret )
    {
        case 0:
            return( PSA_SUCCESS );
        case MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED:
        case MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE:
        case MBEDTLS_ERR_ENTROPY_SOURCE_FAILED:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );
        default:
            return( PSA_ERROR_UNKNOWN_ERROR );
    }
}

void mbedtls_psa_crypto_free( void )
{
    mbedtls_ctr_drbg_free( &global_data.ctr_drbg );
    mbedtls_entropy_free( &global_data.entropy );
    mbedtls_zeroize( &global_data, sizeof( global_data ) );
}

psa_status_t psa_crypto_init( void )
{
    int ret;
    const unsigned char drbg_seed[] = "PSA";

    if( global_data.initialized != 0 )
        return( PSA_SUCCESS );

    mbedtls_zeroize( &global_data, sizeof( global_data ) );
    mbedtls_entropy_init( &global_data.entropy );
    mbedtls_ctr_drbg_init( &global_data.ctr_drbg );

    ret = mbedtls_ctr_drbg_seed( &global_data.ctr_drbg,
                                 mbedtls_entropy_func,
                                 &global_data.entropy,
                                 drbg_seed, sizeof( drbg_seed ) - 1 );
    if( ret != 0 )
        goto exit;

exit:
    if( ret != 0 )
        mbedtls_psa_crypto_free( );
    return( mbedtls_to_psa_error( ret ) );
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
