/*
 * The LM-OTS one-time public-key signature scheme
 *
 * Copyright The Mbed TLS Contributors
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
 */

/*
 *  The following sources were referenced in the design of this implementation
 *  of the LM-OTS algorithm:
 *
 *  [1] IETF RFC8554
 *      D. McGrew, M. Curcio, S.Fluhrer
 *      https://datatracker.ietf.org/doc/html/rfc8554
 *
 *  [2] NIST Special Publication 800-208
 *      David A. Cooper et. al.
 *      https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf
 */

#include "common.h"

#ifdef MBEDTLS_LMS_C

#include <string.h>

#include "lmots.h"

#include "mbedtls/lms.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include "psa/crypto.h"

#define MBEDTLS_LMOTS_SIG_C_RANDOM_OFFSET  (MBEDTLS_LMOTS_SIG_TYPE_OFFSET     + MBEDTLS_LMOTS_TYPE_LEN)
#define MBEDTLS_LMOTS_SIG_SIGNATURE_OFFSET (MBEDTLS_LMOTS_SIG_C_RANDOM_OFFSET + MBEDTLS_LMOTS_C_RANDOM_VALUE_LEN)

#define MBEDTLS_LMOTS_PUBLIC_KEY_TYPE_OFFSET      (0)
#define MBEDTLS_LMOTS_PUBLIC_KEY_I_KEY_ID_OFFSET  (MBEDTLS_LMOTS_PUBLIC_KEY_TYPE_OFFSET      + MBEDTLS_LMOTS_TYPE_LEN)
#define MBEDTLS_LMOTS_PUBLIC_KEY_Q_LEAF_ID_OFFSET (MBEDTLS_LMOTS_PUBLIC_KEY_I_KEY_ID_OFFSET  + MBEDTLS_LMOTS_I_KEY_ID_LEN)
#define MBEDTLS_LMOTS_PUBLIC_KEY_KEY_HASH_OFFSET  (MBEDTLS_LMOTS_PUBLIC_KEY_Q_LEAF_ID_OFFSET + MBEDTLS_LMOTS_Q_LEAF_ID_LEN)

/* We only support parameter sets that use 8-bit digits, as it does not require
 * translation logic between digits and bytes */
#define W_WINTERNITZ_PARAMETER (8u)
#define CHECKSUM_LEN           (2)
#define I_DIGIT_IDX_LEN        (2)
#define J_HASH_IDX_LEN         (1)
#define D_CONST_LEN            (2)

#define DIGIT_MAX_VALUE          ((1u << W_WINTERNITZ_PARAMETER) - 1u)

#define D_CONST_LEN           (2)
static const unsigned char D_PUBLIC_CONSTANT_BYTES[D_CONST_LEN] = {0x80, 0x80};
static const unsigned char D_MESSAGE_CONSTANT_BYTES[D_CONST_LEN] = {0x81, 0x81};

void unsigned_int_to_network_bytes(unsigned int val, size_t len, unsigned char *bytes)
{
    size_t idx;

    for (idx = 0; idx < len; idx++) {
        bytes[idx] = (val >> ((len - 1 - idx) * 8)) & 0xFF;
    }
}

unsigned int network_bytes_to_unsigned_int(size_t len, const unsigned char *bytes)
{
    size_t idx;
    unsigned int val = 0;

    for (idx = 0; idx < len; idx++) {
        val |= ((unsigned int)bytes[idx]) << (8 * (len - 1 - idx));
    }

    return val;
}

static unsigned short lmots_checksum_calculate( const unsigned char* digest )
{
    size_t idx;
    unsigned sum = 0;

    for ( idx = 0; idx < MBEDTLS_LMOTS_N_HASH_LEN; idx++ )
    {
        sum += DIGIT_MAX_VALUE - digest[idx];
    }

    return sum;
}

static int create_digit_array_with_checksum( const mbedtls_lmots_parameters_t *params,
                                             const unsigned char *msg,
                                             size_t msg_len,
                                             const unsigned char C_random_value[MBEDTLS_LMOTS_C_RANDOM_VALUE_LEN],
                                             unsigned char out[MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT] )
{
    psa_hash_operation_t op;
    psa_status_t status;
    size_t output_hash_len;
    unsigned short checksum;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    op = psa_hash_operation_init();
    status = psa_hash_setup( &op, PSA_ALG_SHA_256 );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    status = psa_hash_update( &op, params->I_key_identifier,
                              MBEDTLS_LMOTS_I_KEY_ID_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    status = psa_hash_update( &op, params->q_leaf_identifier,
                              MBEDTLS_LMOTS_Q_LEAF_ID_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    status = psa_hash_update( &op, D_MESSAGE_CONSTANT_BYTES, D_CONST_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    status = psa_hash_update( &op, C_random_value, MBEDTLS_LMOTS_C_RANDOM_VALUE_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    status = psa_hash_update( &op, msg, msg_len );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    status = psa_hash_finish( &op, out, MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT,
                              &output_hash_len );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    checksum = lmots_checksum_calculate( out );
    unsigned_int_to_network_bytes( checksum, CHECKSUM_LEN, out + MBEDTLS_LMOTS_N_HASH_LEN );

exit:
    psa_hash_abort( &op );

    return( ret );
}

static int hash_digit_array( const mbedtls_lmots_parameters_t *params,
                             const unsigned char x_digit_array[MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT][MBEDTLS_LMOTS_N_HASH_LEN],
                             const unsigned char *hash_idx_min_values,
                             const unsigned char *hash_idx_max_values,
                             unsigned char output[MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT][MBEDTLS_LMOTS_N_HASH_LEN] )
{
    unsigned char i_digit_idx;
    unsigned char j_hash_idx;
    unsigned char i_digit_idx_bytes[I_DIGIT_IDX_LEN];
    unsigned char j_hash_idx_bytes[1];
    /* These can't be unsigned chars, because they are sometimes set to
     * #DIGIT_MAX_VALUE, which has a value of 256
     */
    unsigned int j_hash_idx_min;
    unsigned int j_hash_idx_max;
    psa_hash_operation_t op;
    psa_status_t status;
    size_t output_hash_len;
    unsigned char tmp_hash[MBEDTLS_LMOTS_N_HASH_LEN];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    op = psa_hash_operation_init();

    for ( i_digit_idx = 0; i_digit_idx < MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT; i_digit_idx++ )
    {

        memcpy( tmp_hash, &x_digit_array[i_digit_idx], MBEDTLS_LMOTS_N_HASH_LEN );

        j_hash_idx_min = hash_idx_min_values != NULL ? hash_idx_min_values[i_digit_idx] : 0;
        j_hash_idx_max = hash_idx_max_values != NULL ? hash_idx_max_values[i_digit_idx] : DIGIT_MAX_VALUE;

        for ( j_hash_idx = (unsigned char)j_hash_idx_min; j_hash_idx < j_hash_idx_max; j_hash_idx++ )
        {
            status = psa_hash_setup( &op, PSA_ALG_SHA_256 );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
                goto exit;

            status = psa_hash_update( &op,
                                      params->I_key_identifier,
                                      MBEDTLS_LMOTS_I_KEY_ID_LEN );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
                goto exit;

            status = psa_hash_update( &op,
                                      params->q_leaf_identifier,
                                      MBEDTLS_LMOTS_Q_LEAF_ID_LEN );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
                goto exit;

            unsigned_int_to_network_bytes( i_digit_idx, I_DIGIT_IDX_LEN, i_digit_idx_bytes );
            status = psa_hash_update( &op, i_digit_idx_bytes, I_DIGIT_IDX_LEN );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
                goto exit;

            unsigned_int_to_network_bytes( j_hash_idx, J_HASH_IDX_LEN, j_hash_idx_bytes );
            status = psa_hash_update( &op, j_hash_idx_bytes, J_HASH_IDX_LEN );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
                goto exit;

            status = psa_hash_update( &op, tmp_hash, MBEDTLS_LMOTS_N_HASH_LEN );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
                goto exit;

            status = psa_hash_finish( &op, tmp_hash, sizeof( tmp_hash ), &output_hash_len );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
                goto exit;

            psa_hash_abort( &op );
        }

        memcpy( &output[i_digit_idx], tmp_hash, MBEDTLS_LMOTS_N_HASH_LEN );
    }

exit:
    if( ret )
    {
        psa_hash_abort( &op );
        return( ret );
    }

    mbedtls_platform_zeroize( tmp_hash, sizeof( tmp_hash ) );

    return ret;
}

static int public_key_from_hashed_digit_array( const mbedtls_lmots_parameters_t *params,
                                               const unsigned char y_hashed_digits[MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT][MBEDTLS_LMOTS_N_HASH_LEN],
                                               unsigned char *pub_key )
{
    psa_hash_operation_t op;
    psa_status_t status;
    size_t output_hash_len;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    op = psa_hash_operation_init( );
    status = psa_hash_setup( &op, PSA_ALG_SHA_256 );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    status = psa_hash_update( &op,
                              params->I_key_identifier,
                              MBEDTLS_LMOTS_I_KEY_ID_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    status = psa_hash_update( &op, params->q_leaf_identifier,
                              MBEDTLS_LMOTS_Q_LEAF_ID_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    status = psa_hash_update( &op, D_PUBLIC_CONSTANT_BYTES, D_CONST_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    status = psa_hash_update( &op, ( unsigned char * )y_hashed_digits,
                              MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT * MBEDTLS_LMOTS_N_HASH_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    status = psa_hash_finish( &op, pub_key, 32, &output_hash_len );
    ret = mbedtls_lms_error_from_psa( status );

exit:
    psa_hash_abort( &op );
    return( ret );
}

int mbedtls_lms_error_from_psa(psa_status_t status)
{
    switch( status ) {
        case PSA_SUCCESS:
            return( 0 );
        case PSA_ERROR_HARDWARE_FAILURE:
            return( MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED );
        case PSA_ERROR_NOT_SUPPORTED:
            return( MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED );
        case PSA_ERROR_BUFFER_TOO_SMALL:
            return( MBEDTLS_ERR_LMS_BUFFER_TOO_SMALL );
        case PSA_ERROR_INVALID_ARGUMENT:
            return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
        default:
            return( MBEDTLS_ERR_ERROR_GENERIC_ERROR );
    }
}

void mbedtls_lmots_init_public( mbedtls_lmots_public_t *ctx )
{
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_lmots_public_t  ) ) ;
}

void mbedtls_lmots_free_public( mbedtls_lmots_public_t *ctx )
{
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_lmots_public_t  ) ) ;
}

int mbedtls_lmots_import_public_key( mbedtls_lmots_public_t *ctx,
                                 const unsigned char *key, size_t key_len )
{
    if ( key_len < MBEDTLS_LMOTS_PUBLIC_KEY_LEN )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    ctx->params.type =
        network_bytes_to_unsigned_int( MBEDTLS_LMOTS_TYPE_LEN,
                                       key + MBEDTLS_LMOTS_SIG_TYPE_OFFSET );

    memcpy( ctx->params.I_key_identifier,
            key + MBEDTLS_LMOTS_PUBLIC_KEY_I_KEY_ID_OFFSET, MBEDTLS_LMOTS_I_KEY_ID_LEN );

    memcpy( ctx->params.q_leaf_identifier,
            key + MBEDTLS_LMOTS_PUBLIC_KEY_Q_LEAF_ID_OFFSET, MBEDTLS_LMOTS_Q_LEAF_ID_LEN );

    memcpy( ctx->public_key,
            key + MBEDTLS_LMOTS_PUBLIC_KEY_KEY_HASH_OFFSET,
            MBEDTLS_LMOTS_N_HASH_LEN );

    ctx->have_public_key = 1;

    return( 0 );
}

int mbedtls_lmots_calculate_public_key_candidate( const mbedtls_lmots_parameters_t *params,
                                                  const unsigned char  *msg,
                                                  size_t msg_size,
                                                  const unsigned char *sig,
                                                  size_t sig_size,
                                                  unsigned char *out,
                                                  size_t out_size,
                                                  size_t *out_len)
{
    unsigned char tmp_digit_array[MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT];
    unsigned char y_hashed_digits[MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT][MBEDTLS_LMOTS_N_HASH_LEN];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ( msg == NULL && msg_size != 0 )
    {
        return ( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if ( sig_size != MBEDTLS_LMOTS_SIG_LEN || out_size < MBEDTLS_LMOTS_N_HASH_LEN )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    ret = create_digit_array_with_checksum( params, msg, msg_size,
                                            sig + MBEDTLS_LMOTS_SIG_C_RANDOM_OFFSET,
                                            tmp_digit_array );
    if ( ret )
    {
        return ( ret );
    }

    ret = hash_digit_array( params,
                             ( const unsigned char( *)[MBEDTLS_LMOTS_N_HASH_LEN] )(sig + MBEDTLS_LMOTS_SIG_SIGNATURE_OFFSET),
                             tmp_digit_array, NULL, y_hashed_digits );
    if ( ret )
    {
        return ( ret );
    }

    ret = public_key_from_hashed_digit_array( params, y_hashed_digits, out );
    if ( ret )
    {
        return ( ret );
    }

    if ( out_len != NULL )
    {
        *out_len = MBEDTLS_LMOTS_N_HASH_LEN;
    }

    return( 0 );
}

int mbedtls_lmots_verify( mbedtls_lmots_public_t *ctx, const unsigned char *msg,
                          size_t msg_size, const unsigned char *sig,
                          size_t sig_size )
{
    unsigned char Kc_public_key_candidate[MBEDTLS_LMOTS_N_HASH_LEN];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ( msg == NULL && msg_size != 0 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if ( !ctx->have_public_key )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->params.MBEDTLS_PRIVATE( type )
        != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if ( network_bytes_to_unsigned_int( MBEDTLS_LMOTS_TYPE_LEN,
                               sig + MBEDTLS_LMOTS_SIG_TYPE_OFFSET ) != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_VERIFY_FAILED );
    }

    ret = mbedtls_lmots_calculate_public_key_candidate( &ctx->params,
                                                        msg, msg_size, sig, sig_size,
                                                        Kc_public_key_candidate,
                                                        MBEDTLS_LMOTS_N_HASH_LEN,
                                                        NULL);
    if ( ret )
    {
        return( ret );
    }

    if ( memcmp( &Kc_public_key_candidate, ctx->public_key,
                 sizeof( ctx->public_key ) ) )
    {
        return( MBEDTLS_ERR_LMS_VERIFY_FAILED );
    }

    return( 0 );
}

void mbedtls_lmots_init_private( mbedtls_lmots_private_t *ctx )
{
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_lmots_private_t  ) ) ;
}

void mbedtls_lmots_free_private( mbedtls_lmots_private_t *ctx )
{
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_lmots_private_t  ) ) ;
}

int mbedtls_lmots_generate_private_key( mbedtls_lmots_private_t *ctx,
                                        mbedtls_lmots_algorithm_type_t type,
                                        const unsigned char I_key_identifier[MBEDTLS_LMOTS_I_KEY_ID_LEN],
                                        uint32_t q_leaf_identifier,
                                        const unsigned char *seed,
                                        size_t seed_size )
{
    psa_hash_operation_t op;
    psa_status_t status;
    size_t output_hash_len;
    unsigned int i_digit_idx;
    unsigned char i_digit_idx_bytes[2];
    unsigned char const_bytes[1];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ( ctx->have_private_key )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if ( type != MBEDTLS_LMOTS_SHA256_N32_W8 ) {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    ctx->params.type = type;

    memcpy( ctx->params.I_key_identifier,
            I_key_identifier,
            sizeof( ctx->params.I_key_identifier ) );

    unsigned_int_to_network_bytes(q_leaf_identifier,
                                  MBEDTLS_LMOTS_Q_LEAF_ID_LEN,
                                  ctx->params.q_leaf_identifier );

    unsigned_int_to_network_bytes( 0xFF, sizeof( const_bytes ), const_bytes );

    for ( i_digit_idx = 0; i_digit_idx < MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT; i_digit_idx++ )
    {
        op = psa_hash_operation_init( );
        status = psa_hash_setup( &op, PSA_ALG_SHA_256 );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret != 0 )
            goto exit;

        ret = psa_hash_update( &op,
                               ctx->params.I_key_identifier,
                               sizeof( ctx->params.I_key_identifier ) );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret )
            goto exit;

        status = psa_hash_update( &op,
                                  ctx->params.q_leaf_identifier,
                                  MBEDTLS_LMOTS_Q_LEAF_ID_LEN );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret )
            goto exit;

        unsigned_int_to_network_bytes( i_digit_idx, I_DIGIT_IDX_LEN, i_digit_idx_bytes );
        status = psa_hash_update( &op, i_digit_idx_bytes, I_DIGIT_IDX_LEN );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret )
            goto exit;

        status = psa_hash_update( &op, const_bytes, sizeof( const_bytes) );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret )
            goto exit;

        status = psa_hash_update( &op, seed, seed_size );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret )
            goto exit;

        status = psa_hash_finish( &op,
                                  ctx->private_key[i_digit_idx],
                                  32, &output_hash_len );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret )
            goto exit;

        psa_hash_abort( &op );
    }

    ctx->have_private_key = 1;

exit:
    if( ret )
    {
        psa_hash_abort( &op );
        return( ret );
    }

    return ret;
}

int mbedtls_lmots_calculate_public_key( mbedtls_lmots_public_t *ctx,
                                        mbedtls_lmots_private_t *priv_ctx)
{
    unsigned char y_hashed_digits[MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT][MBEDTLS_LMOTS_N_HASH_LEN];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Check that a private key is loaded */
    if ( !priv_ctx->have_private_key )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    ret = hash_digit_array( &priv_ctx->params, priv_ctx->private_key, NULL,
                            NULL, y_hashed_digits );
    if ( ret )
    {
        return( ret );
    }

    ret = public_key_from_hashed_digit_array( &priv_ctx->params,
                                              y_hashed_digits,
                                              ctx->public_key );
    if ( ret )
    {
        return( ret );
    }

    memcpy( &ctx->params, &priv_ctx->params,
            sizeof( ctx->params ) );

    ctx->MBEDTLS_PRIVATE(have_public_key = 1);

    return( ret );
}


int mbedtls_lmots_export_public_key( mbedtls_lmots_public_t *ctx,
                                     unsigned char *key, size_t key_size,
                                     size_t *key_len )
{
    if( key_size < MBEDTLS_LMS_PUBLIC_KEY_LEN )
    {
        return( MBEDTLS_ERR_LMS_BUFFER_TOO_SMALL );
    }

    if( ! ctx->have_public_key )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    unsigned_int_to_network_bytes( ctx->params.type,
                                   MBEDTLS_LMOTS_TYPE_LEN,
                                   key + MBEDTLS_LMOTS_SIG_TYPE_OFFSET );

    memcpy( key + MBEDTLS_LMOTS_PUBLIC_KEY_I_KEY_ID_OFFSET,
            ctx->params.I_key_identifier,
            MBEDTLS_LMOTS_I_KEY_ID_LEN );

    memcpy(key + MBEDTLS_LMOTS_PUBLIC_KEY_Q_LEAF_ID_OFFSET,
           ctx->params.q_leaf_identifier,
           MBEDTLS_LMOTS_Q_LEAF_ID_LEN);

    memcpy( key + MBEDTLS_LMOTS_PUBLIC_KEY_KEY_HASH_OFFSET, ctx->public_key,
            MBEDTLS_LMOTS_N_HASH_LEN );

    if( key_len != NULL )
    {
        *key_len = MBEDTLS_LMS_PUBLIC_KEY_LEN;
    }

    return( 0 );
}

int mbedtls_lmots_sign( mbedtls_lmots_private_t *ctx,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng, const unsigned char *msg, size_t msg_size,
                        unsigned char *sig, size_t sig_size, size_t* sig_len )
{
    unsigned char tmp_digit_array[MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT];
    /* Create a temporary buffer to prepare the signature in. This allows us to
     * finish creating a signature (ensuring the process doesn't fail), and then
     * erase the private key **before** writing any data into the sig parameter
     * buffer. If data were directly written into the sig buffer, it might leak
     * a partial signature on failure, which effectively compromises the private
     * key.
     */
    unsigned char tmp_sig[MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT][MBEDTLS_LMOTS_N_HASH_LEN];
    unsigned char tmp_c_random[MBEDTLS_LMOTS_C_RANDOM_VALUE_LEN];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ( msg == NULL && msg_size != 0 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( sig_size < MBEDTLS_LMOTS_SIG_LEN )
    {
        return( MBEDTLS_ERR_LMS_BUFFER_TOO_SMALL );
    }

    /* Check that a private key is loaded */
    if ( !ctx->have_private_key )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    ret = f_rng( p_rng, tmp_c_random, MBEDTLS_LMOTS_N_HASH_LEN );
    if ( ret )
    {
        return( ret );
    }

    ret = create_digit_array_with_checksum( &ctx->params,
                                            msg, msg_size,
                                            tmp_c_random,
                                            tmp_digit_array );
    if ( ret )
    {
        return( ret );
    }

    ret = hash_digit_array( &ctx->params,
                             ctx->private_key,
                             NULL, tmp_digit_array, tmp_sig );
    if ( ret )
    {
        return( ret );
    }

    unsigned_int_to_network_bytes( ctx->params.type,
                                   MBEDTLS_LMOTS_TYPE_LEN,
                                   sig + MBEDTLS_LMOTS_SIG_TYPE_OFFSET );

    /* We've got a valid signature now, so it's time to make sure the private
     * key can't be reused.
     */
    ctx->have_private_key = 0;
    mbedtls_platform_zeroize(ctx->private_key,
                             sizeof(ctx->private_key));

    memcpy( sig + MBEDTLS_LMOTS_SIG_C_RANDOM_OFFSET, tmp_c_random,
            MBEDTLS_LMOTS_C_RANDOM_VALUE_LEN );

    memcpy( sig + MBEDTLS_LMOTS_SIG_SIGNATURE_OFFSET, tmp_sig,
            MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT * MBEDTLS_LMOTS_N_HASH_LEN );

    if( sig_len != NULL )
    {
        *sig_len = MBEDTLS_LMS_SIG_LEN;
    }

    return( 0 );
}

#endif /* MBEDTLS_LMS_C */
