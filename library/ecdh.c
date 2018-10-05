/*
 *  Elliptic curve Diffie-Hellman
 *
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

/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 * RFC 4492
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECDH_C)

#include "mbedtls/ecdh.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
typedef mbedtls_ecdh_context mbedtls_ecdh_context_mbed;
#endif

#if !defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT)
/*
 * Generate public key: simple wrapper around mbedtls_ecp_gen_keypair
 */
int mbedtls_ecdh_gen_public( mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    return mbedtls_ecp_gen_keypair( grp, d, Q, f_rng, p_rng );
}
#endif /* MBEDTLS_ECDH_GEN_PUBLIC_ALT */

#if !defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
/*
 * Compute shared secret (SEC1 3.3.1)
 */
int mbedtls_ecdh_compute_shared( mbedtls_ecp_group *grp, mbedtls_mpi *z,
                         const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng )
{
    int ret;
    mbedtls_ecp_point P;

    mbedtls_ecp_point_init( &P );

    /*
     * Make sure Q is a valid pubkey before using it
     */
    MBEDTLS_MPI_CHK( mbedtls_ecp_check_pubkey( grp, Q ) );

    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( grp, &P, d, Q, f_rng, p_rng ) );

    if( mbedtls_ecp_is_zero( &P ) )
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( z, &P.X ) );

cleanup:
    mbedtls_ecp_point_free( &P );

    return( ret );
}
#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

/*
 * Initialize context
 */
void mbedtls_ecdh_init( mbedtls_ecdh_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_ecdh_context ) );
}

static int mbedtls_ecdh_setup_internal( mbedtls_ecdh_context_mbed *ctx,
                                        mbedtls_ecp_group_id grp_id )
{
    int ret;

    ret = mbedtls_ecp_group_load( &ctx->grp, grp_id );
    if( ret != 0 )
    {
        return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
    }

    return( 0 );
}

/*
 * Setup context
 */
int mbedtls_ecdh_setup( mbedtls_ecdh_context *ctx, mbedtls_ecp_group_id grp_id )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_setup_internal( ctx, grp_id ) );
#else
    switch( grp_id )
    {
        default:
            ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;
            ctx->var = MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0;
            ctx->grp_id = grp_id;
            return( mbedtls_ecdh_setup_internal( &ctx->ctx.mbed_ecdh,
                                                 grp_id ) );
    }
#endif
}

static void mbedtls_ecdh_free_internal( mbedtls_ecdh_context_mbed *ctx )
{
    mbedtls_ecp_group_free( &ctx->grp );
    mbedtls_ecp_point_free( &ctx->Q   );
    mbedtls_ecp_point_free( &ctx->Qp  );
    mbedtls_mpi_free( &ctx->d  );
    mbedtls_mpi_free( &ctx->z  );
}

/*
 * Free context
 */
void mbedtls_ecdh_free( mbedtls_ecdh_context *ctx )
{
    if( ctx == NULL )
        return;

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    mbedtls_ecp_point_free( &ctx->Vi );
    mbedtls_ecp_point_free( &ctx->Vf );
    mbedtls_mpi_free( &ctx->_d );
    mbedtls_ecdh_free_internal( ctx );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            mbedtls_ecdh_free_internal( &ctx->ctx.mbed_ecdh );
            break;
        default:
            break;
    }

    ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;
    ctx->var = MBEDTLS_ECDH_VARIANT_NONE;
    ctx->grp_id = MBEDTLS_ECP_DP_NONE;
#endif
}

static int mbedtls_ecdh_make_params_internal( mbedtls_ecdh_context_mbed *ctx,
                                              size_t *olen, int point_format,
                                              unsigned char *buf, size_t blen,
                                              int (*f_rng)(void *,
                                                           unsigned char *,
                                                           size_t),
                                              void *p_rng )
{
    int ret;
    size_t grp_len, pt_len;

    if( ctx->grp.pbits == 0 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q, f_rng,
                                         p_rng ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_ecp_tls_write_group( &ctx->grp, &grp_len, buf,
                                             blen ) ) != 0 )
        return( ret );

    buf += grp_len;
    blen -= grp_len;

    if( ( ret = mbedtls_ecp_tls_write_point( &ctx->grp, &ctx->Q, point_format,
                                             &pt_len, buf, blen ) ) != 0 )
        return( ret );

    *olen = grp_len + pt_len;
    return( 0 );
}

/*
 * Setup and write the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int mbedtls_ecdh_make_params( mbedtls_ecdh_context *ctx, size_t *olen,
                              unsigned char *buf, size_t blen,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_make_params_internal( ctx, olen, ctx->point_format,
                                               buf, blen, f_rng, p_rng ) );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( mbedtls_ecdh_make_params_internal( &ctx->ctx.mbed_ecdh,
                                                       olen, ctx->point_format,
                                                       buf, blen, f_rng,
                                                       p_rng ) );
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int mbedtls_ecdh_read_params_internal( mbedtls_ecdh_context_mbed *ctx,
                                              const unsigned char **buf,
                                              const unsigned char *end )
{
    return( mbedtls_ecp_tls_read_point( &ctx->grp, &ctx->Qp, buf,
                                        end - *buf ) );
}

/*
 * Read the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int mbedtls_ecdh_read_params( mbedtls_ecdh_context *ctx,
                              const unsigned char **buf,
                              const unsigned char *end )
{
    int ret;
    mbedtls_ecp_group_id grp_id;

    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecp_tls_read_group_id( &grp_id, buf, end - *buf ) )
            != 0 )
        return( ret );

    if( ( ret = mbedtls_ecdh_setup( ctx, grp_id ) ) != 0 )
        return( ret );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_read_params_internal( ctx, buf, end ) );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( mbedtls_ecdh_read_params_internal( &ctx->ctx.mbed_ecdh,
                                                       buf, end ) );
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int mbedtls_ecdh_get_params_internal( mbedtls_ecdh_context_mbed *ctx,
                                             const mbedtls_ecp_keypair *key,
                                             mbedtls_ecdh_side side )
{
    int ret;

    /* If it's not our key, just import the public part as Qp */
    if( side == MBEDTLS_ECDH_THEIRS )
        return( mbedtls_ecp_copy( &ctx->Qp, &key->Q ) );

    /* Our key: import public (as Q) and private parts */
    if( side != MBEDTLS_ECDH_OURS )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecp_copy( &ctx->Q, &key->Q ) ) != 0 ||
        ( ret = mbedtls_mpi_copy( &ctx->d, &key->d ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Get parameters from a keypair
 */
int mbedtls_ecdh_get_params( mbedtls_ecdh_context *ctx,
                             const mbedtls_ecp_keypair *key,
                             mbedtls_ecdh_side side )
{
    int ret;

    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecdh_setup( ctx, key->grp.id ) ) != 0 )
        return( ret );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_get_params_internal( ctx, key, side ) );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( mbedtls_ecdh_get_params_internal( &ctx->ctx.mbed_ecdh,
                                                      key, side ) );
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int mbedtls_ecdh_make_public_internal( mbedtls_ecdh_context_mbed *ctx,
                                              size_t *olen, int point_format,
                                              unsigned char *buf, size_t blen,
                                              int (*f_rng)(void *,
                                                           unsigned char *,
                                                           size_t),
                                              void *p_rng )
{
    int ret;

    if( ctx->grp.pbits == 0 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecdh_gen_public( &ctx->grp, &ctx->d,
                                         &ctx->Q, f_rng, p_rng ) ) != 0 )
        return( ret );

    return mbedtls_ecp_tls_write_point( &ctx->grp, &ctx->Q, point_format, olen,
                                        buf, blen );
}

/*
 * Setup and export the client public value
 */
int mbedtls_ecdh_make_public( mbedtls_ecdh_context *ctx, size_t *olen,
                              unsigned char *buf, size_t blen,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_make_public_internal( ctx, olen, ctx->point_format,
                                               buf, blen, f_rng, p_rng ) );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( mbedtls_ecdh_make_public_internal( &ctx->ctx.mbed_ecdh,
                                                       olen, ctx->point_format,
                                                       buf, blen,
                                                       f_rng, p_rng ) );
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int mbedtls_ecdh_read_public_internal( mbedtls_ecdh_context_mbed *ctx,
                                              const unsigned char *buf,
                                              size_t blen )
{
    int ret;
    const unsigned char *p = buf;

    if( ( ret = mbedtls_ecp_tls_read_point( &ctx->grp, &ctx->Qp, &p,
                                            blen ) ) != 0 )
        return( ret );

    if( (size_t)( p - buf ) != blen )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    return( 0 );
}

/*
 * Parse and import the client's public value
 */
int mbedtls_ecdh_read_public( mbedtls_ecdh_context *ctx,
                              const unsigned char *buf, size_t blen )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_read_public_internal( ctx, buf, blen ) );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( mbedtls_ecdh_read_public_internal( &ctx->ctx.mbed_ecdh,
                                                       buf, blen ) );
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int mbedtls_ecdh_calc_secret_internal( mbedtls_ecdh_context_mbed *ctx,
                                              size_t *olen, unsigned char *buf,
                                              size_t blen,
                                              int (*f_rng)(void *,
                                                           unsigned char *,
                                                           size_t),
                                              void *p_rng )
{
    int ret;

    if( ( ret = mbedtls_ecdh_compute_shared( &ctx->grp, &ctx->z, &ctx->Qp,
                                             &ctx->d, f_rng, p_rng ) ) != 0 )
    {
        return( ret );
    }

    if( mbedtls_mpi_size( &ctx->z ) > blen )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    *olen = ctx->grp.pbits / 8 + ( ( ctx->grp.pbits % 8 ) != 0 );
    return mbedtls_mpi_write_binary( &ctx->z, buf, *olen );
}

/*
 * Derive and export the shared secret
 */
int mbedtls_ecdh_calc_secret( mbedtls_ecdh_context *ctx, size_t *olen,
                              unsigned char *buf, size_t blen,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_calc_secret_internal( ctx, olen, buf, blen, f_rng,
                                               p_rng ) );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( mbedtls_ecdh_calc_secret_internal( &ctx->ctx.mbed_ecdh,
                                                       olen, buf, blen,
                                                       f_rng, p_rng ) );
        default:
            return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }
#endif
}

#endif /* MBEDTLS_ECDH_C */
