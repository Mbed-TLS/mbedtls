/*
 *  ECDH with curve-optimized implementation multiplexing
 *
 *  Copyright 2016-2018 INRIA and Microsoft Corporation
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

#if defined(MBEDTLS_ECDH_C)

#include <mbedtls/ecdh.h>

#include <Hacl_Curve25519.h>
#include <mbedtls/platform_util.h>

#include "x25519.h"

#include <string.h>

/*
 * Initialize context
 */
void mbedtls_x25519_init( mbedtls_x25519_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_x25519_context ) );
}

/*
 * Free context
 */
void mbedtls_x25519_free( mbedtls_x25519_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx->our_secret, 32 );
    mbedtls_platform_zeroize( ctx->peer_point, 32 );
}

int mbedtls_x25519_make_params( mbedtls_x25519_context *ctx, size_t *olen,
                        unsigned char *buf, size_t blen,
                        int( *f_rng )(void *, unsigned char *, size_t),
                        void *p_rng )
{
    int ret = 0;

    uint8_t base[32] = {0};

    if( ( ret = f_rng( p_rng, ctx->our_secret, 32 ) ) != 0 )
        return ret;

    *olen = 36;
    if( blen < *olen )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    *buf++ = MBEDTLS_ECP_TLS_NAMED_CURVE;
    *buf++ = MBEDTLS_ECP_TLS_CURVE25519 >> 8;
    *buf++ = MBEDTLS_ECP_TLS_CURVE25519 & 0xFF;
    *buf++ = 32;

    base[0] = 9;
    Hacl_Curve25519_crypto_scalarmult( buf, ctx->our_secret, base );

    base[0] = 0;
    if( memcmp( buf, base, 32) == 0 )
        return MBEDTLS_ERR_ECP_RANDOM_FAILED;

    return( 0 );
}

int mbedtls_x25519_read_params( mbedtls_x25519_context *ctx,
                        const unsigned char **buf, const unsigned char *end )
{
    if( end - *buf < 33 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( *(*buf)++ != 32 ) )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    memcpy( ctx->peer_point, *buf, 32 );
    *buf += 32;
    return( 0 );
}

int mbedtls_x25519_get_params( mbedtls_x25519_context *ctx, const mbedtls_ecp_keypair *key,
                               mbedtls_x25519_ecdh_side side )
{
    size_t olen = 0;

    switch( side ) {
    case MBEDTLS_X25519_ECDH_THEIRS:
        mbedtls_ecp_point_write_binary( &key->grp, &key->Q, MBEDTLS_ECP_PF_COMPRESSED, &olen, ctx->peer_point, 32 );
        /* untested; defensively throw an error for now. */
        return(MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE);
    case MBEDTLS_X25519_ECDH_OURS:
        mbedtls_mpi_write_binary( &key->d, ctx->our_secret, 32 );
        /* CMW: key->Q = key->d * base; do we need to set up ctx.peer_point here? */
        /* untested; defensively throw an error for now. */
        return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
    default:
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }
}

int mbedtls_x25519_calc_secret( mbedtls_x25519_context *ctx, size_t *olen,
                        unsigned char *buf, size_t blen,
                        int( *f_rng )(void *, unsigned char *, size_t),
                        void *p_rng )
{
    /* CMW: Is it okay that f_rng, p_rng are not used? */
    (( void )f_rng);
    (( void )p_rng);

    *olen = 32;

    if( blen < *olen )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    Hacl_Curve25519_crypto_scalarmult( buf, ctx->our_secret, ctx->peer_point);

    /* Wipe the DH secret and don't let the peer chose a small subgroup point */
    memset( ctx->our_secret, 0, 32 );
    if( memcmp( buf, ctx->our_secret, 32) == 0 )
        return MBEDTLS_ERR_ECP_RANDOM_FAILED;

    return( 0 );
}

int mbedtls_x25519_make_public( mbedtls_x25519_context *ctx, size_t *olen,
                        unsigned char *buf, size_t blen,
                        int( *f_rng )(void *, unsigned char *, size_t),
                        void *p_rng )
{
    unsigned char base[32] = { 0 };

    /* CMW: Is it okay that f_rng, p_rng are not used? */
    (( void )f_rng);
    (( void )p_rng);

    if( ctx == NULL )
        return(MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    *olen = 33;
    if( blen < *olen )
        return(MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL);
    *buf++ = 32;

    base[0] = 9;
    Hacl_Curve25519_crypto_scalarmult( buf, ctx->our_secret, base );

    base[0] = 0;
    if( memcmp( buf, base, 32 ) == 0 )
        return MBEDTLS_ERR_ECP_RANDOM_FAILED;

    return(0);
}

int mbedtls_x25519_read_public( mbedtls_x25519_context *ctx,
                        const unsigned char *buf, size_t blen )
{
    if( blen < 33 )
        return(MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL);
    if( (*buf++ != 32) )
        return(MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
    memcpy( ctx->peer_point, buf, 32 );
    return(0);
}


#endif /* MBEDTLS_ECDH_C */
