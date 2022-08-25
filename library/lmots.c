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

#define W_SYMBOL_BIT_LEN      (8)
#define CHECKSUM_LEN          (2)
#define I_SYMBOL_IDX_LEN      (2)
#define J_HASH_IDX_LEN        (1)
#define D_CONST_LEN           (2)

#define SYMBOL_MAX_VAL        ((1 << W_SYMBOL_BIT_LEN) - 1)

#define D_PBLC_CONSTANT       (0x8080)
#define D_MESG_CONSTANT       (0x8181)

static void val_to_network_bytes(unsigned int val, size_t len, unsigned char *bytes)
{
    size_t idx;

    for (idx = 0; idx < len; idx++) {
        bytes[idx] = (val >> ((len - 1 - idx) * 8)) & 0xFF;
    }
}

static unsigned int network_bytes_to_val(size_t len, const unsigned char *bytes)
{
    size_t idx;
    unsigned int val = 0;

    for (idx = 0; idx < len; idx++) {
        val |= ((unsigned int)bytes[idx]) << (8 * (len - 1 - idx));
    }

    return val;
}

static unsigned short lmots_checksum_generate( const unsigned char* digest )
{
    size_t idx;
    unsigned short sum = 0;

    for ( idx = 0; idx < MBEDTLS_LMOTS_N_HASH_LEN; idx++ )
    {
        sum += ( 1 << W_SYMBOL_BIT_LEN ) - 1 - digest[idx];
    }

    return sum;
}

static int create_symbol_array( const unsigned char I_key_identifier[MBEDTLS_LMOTS_I_KEY_ID_LEN],
                                const unsigned char q_leaf_identifier[MBEDTLS_LMOTS_Q_LEAF_ID_LEN],
                                const unsigned char *msg,
                                size_t msg_len,
                                const unsigned char C_random_value[MBEDTLS_LMOTS_C_RANDOM_VALUE_LEN],
                                unsigned char out[MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN] )
{
    psa_hash_operation_t op;
    psa_status_t status;
    size_t output_hash_len;
    unsigned char D_MESG_BYTES[D_CONST_LEN];
    unsigned short checksum;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    op = psa_hash_operation_init();
    status = psa_hash_setup( &op, PSA_ALG_SHA_256 );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
    {
        goto out;
    }

    status = psa_hash_update( &op, I_key_identifier, MBEDTLS_LMOTS_I_KEY_ID_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
    {
        goto out;
    }

    status = psa_hash_update( &op, q_leaf_identifier, MBEDTLS_LMOTS_Q_LEAF_ID_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
    {
        goto out;
    }

    val_to_network_bytes( D_MESG_CONSTANT, D_CONST_LEN, D_MESG_BYTES );
    status = psa_hash_update( &op, D_MESG_BYTES, sizeof( D_MESG_BYTES ) );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
    {
        goto out;
    }

    status = psa_hash_update( &op, C_random_value, MBEDTLS_LMOTS_C_RANDOM_VALUE_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
    {
        goto out;
    }

    status = psa_hash_update( &op, msg, msg_len );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
    {
        goto out;
    }

    status = psa_hash_finish( &op, out, MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN,
                              &output_hash_len );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
    {
        goto out;
    }

    checksum = lmots_checksum_generate( out );
    val_to_network_bytes( checksum, CHECKSUM_LEN, out + MBEDTLS_LMOTS_N_HASH_LEN );

out:
    psa_hash_abort( &op );

    return( ret );
}

static int hash_symbol_array( const unsigned char I_key_identifier[MBEDTLS_LMOTS_I_KEY_ID_LEN],
                              const unsigned char q_leaf_identifier[MBEDTLS_LMOTS_Q_LEAF_ID_LEN],
                              const unsigned char x_symbol_array[MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN][32],
                              const unsigned char hash_idx_min_values[MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN],
                              const unsigned char hash_idx_max_values[MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN],
                              unsigned char output[MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN][32] )
{
    unsigned char i_symbol_idx;
    unsigned char j_hash_idx;
    unsigned char i_symbol_idx_bytes[I_SYMBOL_IDX_LEN];
    unsigned char j_hash_idx_bytes[1];
    unsigned short j_hash_idx_min;
    unsigned short j_hash_idx_max;
    psa_hash_operation_t op;
    psa_status_t status;
    size_t output_hash_len;
    unsigned char tmp_hash[32];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    for ( i_symbol_idx = 0; i_symbol_idx < MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN; i_symbol_idx++ )
    {

        memcpy( tmp_hash, &x_symbol_array[i_symbol_idx], MBEDTLS_LMOTS_N_HASH_LEN );

        j_hash_idx_min = hash_idx_min_values != NULL ? hash_idx_min_values[i_symbol_idx] : 0;
        j_hash_idx_max = hash_idx_max_values != NULL ? hash_idx_max_values[i_symbol_idx] : SYMBOL_MAX_VAL;

        for ( j_hash_idx = (unsigned char)j_hash_idx_min; j_hash_idx < j_hash_idx_max; j_hash_idx++ )
        {
            op = psa_hash_operation_init();
            status = psa_hash_setup( &op, PSA_ALG_SHA_256 );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
            {
                goto out;
            }

            status = psa_hash_update( &op, I_key_identifier, MBEDTLS_LMOTS_I_KEY_ID_LEN );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
            {
                goto out;
            }

            status = psa_hash_update( &op, q_leaf_identifier, MBEDTLS_LMOTS_Q_LEAF_ID_LEN );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
            {
                goto out;
            }

            val_to_network_bytes( i_symbol_idx, I_SYMBOL_IDX_LEN, i_symbol_idx_bytes );
            status = psa_hash_update( &op, i_symbol_idx_bytes, I_SYMBOL_IDX_LEN );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
            {
                goto out;
            }

            val_to_network_bytes( j_hash_idx, J_HASH_IDX_LEN, j_hash_idx_bytes );
            status = psa_hash_update( &op, j_hash_idx_bytes, J_HASH_IDX_LEN );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
            {
                goto out;
            }

            status = psa_hash_update( &op, tmp_hash, MBEDTLS_LMOTS_N_HASH_LEN );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
            {
                goto out;
            }

            status = psa_hash_finish( &op, tmp_hash, sizeof( tmp_hash ), &output_hash_len );
            ret = mbedtls_lms_error_from_psa( status );
            if ( ret != 0 )
            {
                goto out;
            }

            psa_hash_abort( &op );
        }

        memcpy( &output[i_symbol_idx], tmp_hash, MBEDTLS_LMOTS_N_HASH_LEN );
    }

out:
    if( ret )
    {
        psa_hash_abort( &op );
        return( ret );
    }

    return ret;
}

static int public_key_from_hashed_symbol_array( const unsigned char I_key_identifier[MBEDTLS_LMOTS_I_KEY_ID_LEN],
                                                const unsigned char q_leaf_identifier[MBEDTLS_LMOTS_Q_LEAF_ID_LEN],
                                                const unsigned char  y_hashed_symbols[MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN][32],
                                                unsigned char *pub_key )
{
    unsigned char D_PBLC_bytes[D_CONST_LEN];
    psa_hash_operation_t op;
    psa_status_t status;
    size_t output_hash_len;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    op = psa_hash_operation_init( );
    status = psa_hash_setup( &op, PSA_ALG_SHA_256 );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
    {
        goto out;
    }

    status = psa_hash_update( &op, I_key_identifier, MBEDTLS_LMOTS_I_KEY_ID_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
    {
        goto out;
    }

    status = psa_hash_update( &op, q_leaf_identifier, MBEDTLS_LMOTS_Q_LEAF_ID_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
    {
        goto out;
    }

    val_to_network_bytes( D_PBLC_CONSTANT, D_CONST_LEN, D_PBLC_bytes );
    status = psa_hash_update( &op, D_PBLC_bytes, D_CONST_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
    {
        goto out;
    }

    status = psa_hash_update( &op, ( unsigned char * )y_hashed_symbols,
                              MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN * MBEDTLS_LMOTS_N_HASH_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
    {
        goto out;
    }

    status = psa_hash_finish( &op, pub_key, 32, &output_hash_len );
    ret = mbedtls_lms_error_from_psa( status );

out:
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

void mbedtls_lmots_init( mbedtls_lmots_context *ctx )
{
    if( ctx == NULL ) {
        return;
    }

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_lmots_context  ) ) ;
}

void mbedtls_lmots_free( mbedtls_lmots_context *ctx )
{
    if( ctx == NULL )
    {
        return;
    }

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_lmots_context  ) ) ;
}

int mbedtls_lmots_set_algorithm_type( mbedtls_lmots_context *ctx,
                                      mbedtls_lmots_algorithm_type_t type )
{
    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    ctx->MBEDTLS_PRIVATE(type) = type;

    return( 0 );
}

int mbedtls_lmots_generate_pub_key_candidate( const unsigned char I_key_identifier[MBEDTLS_LMOTS_I_KEY_ID_LEN],
                                              const unsigned char q_leaf_identifier[MBEDTLS_LMOTS_Q_LEAF_ID_LEN],
                                              const unsigned char  *msg,
                                              size_t msg_len,
                                              const unsigned char *sig,
                                              unsigned char *out )
{
    unsigned char tmp_symbol_array[MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN];
    unsigned char y_hashed_symbols[MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN][32];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (I_key_identifier == NULL || msg == NULL || sig == NULL || out == NULL)
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    ret = create_symbol_array( I_key_identifier, q_leaf_identifier, msg, msg_len,
                               sig + MBEDTLS_LMOTS_SIG_C_RANDOM_OFFSET, tmp_symbol_array );
    if ( ret )
    {
        return ( ret );
    }

    ret = hash_symbol_array( I_key_identifier, q_leaf_identifier,
                             ( const unsigned char( *)[32] )(sig + MBEDTLS_LMOTS_SIG_SIGNATURE_OFFSET),
                             tmp_symbol_array, NULL, y_hashed_symbols );
    if ( ret )
    {
        return ( ret );
    }

    ret = public_key_from_hashed_symbol_array( I_key_identifier, q_leaf_identifier,
                                               ( const unsigned char( *)[32] )y_hashed_symbols,
                                               out );
    if ( ret )
    {
        return ( ret );
    }

    return( 0 );
}

int mbedtls_lmots_sign( mbedtls_lmots_context *ctx,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng, const unsigned char *msg, size_t msg_len,
                        unsigned char *sig )
{
    unsigned char tmp_symbol_array[MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN];
    unsigned char tmp_sig[MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN][MBEDTLS_LMOTS_N_HASH_LEN];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ctx == NULL || f_rng == NULL || p_rng == NULL || msg == NULL || sig == NULL)
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    /* Check that a private key is loaded */
    if ( !ctx->MBEDTLS_PRIVATE(have_privkey) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    ret = f_rng( p_rng, sig + MBEDTLS_LMOTS_SIG_C_RANDOM_OFFSET, MBEDTLS_LMOTS_N_HASH_LEN );
    if ( ret )
    {
        return( ret );
    }

    ret = create_symbol_array( ctx->MBEDTLS_PRIVATE(I_key_identifier),
                               ctx->MBEDTLS_PRIVATE(q_leaf_identifier_bytes),
                               msg, msg_len, sig + MBEDTLS_LMOTS_SIG_C_RANDOM_OFFSET,
                               tmp_symbol_array );
    if ( ret )
    {
        return( ret );
    }

    ret = hash_symbol_array( ctx->MBEDTLS_PRIVATE(I_key_identifier),
                             ctx->MBEDTLS_PRIVATE(q_leaf_identifier_bytes),
                             ( const unsigned char( *)[32] )(ctx->MBEDTLS_PRIVATE(priv_key)),
                             NULL, tmp_symbol_array, tmp_sig );
    if ( ret )
    {
        return( ret );
    }

    val_to_network_bytes( ctx->MBEDTLS_PRIVATE(type), MBEDTLS_LMOTS_TYPE_LEN,
                          sig + MBEDTLS_LMOTS_SIG_TYPE_OFFSET );

    /* We've got a valid signature now, so it's time to make sure the private
     * key can't be reused.
     */
    ctx->MBEDTLS_PRIVATE(have_privkey) = 0;
    mbedtls_platform_zeroize(ctx->MBEDTLS_PRIVATE(priv_key),
                             sizeof(ctx->MBEDTLS_PRIVATE(priv_key)));

    memcpy(sig + MBEDTLS_LMOTS_SIG_SIGNATURE_OFFSET, tmp_sig,
           MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN * MBEDTLS_LMOTS_N_HASH_LEN);

    return( 0 );
}

int mbedtls_lmots_verify( mbedtls_lmots_context *ctx, const unsigned char *msg,
                          size_t msg_len, const unsigned char *sig )
{
    unsigned char Kc_public_key_candidate[32];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ctx == NULL || msg == NULL || sig == NULL)
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if ( !ctx->MBEDTLS_PRIVATE(have_pubkey) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(type ) != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if ( network_bytes_to_val( MBEDTLS_LMOTS_TYPE_LEN,
                               sig + MBEDTLS_LMOTS_SIG_TYPE_OFFSET ) != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_VERIFY_FAILED );
    }

    ret = mbedtls_lmots_generate_pub_key_candidate( ctx->MBEDTLS_PRIVATE(I_key_identifier),
                                                    ctx->MBEDTLS_PRIVATE(q_leaf_identifier_bytes),
                                                    msg, msg_len, sig,
                                                    Kc_public_key_candidate );
    if ( ret )
    {
        return( ret );
    }

    if ( memcmp( &Kc_public_key_candidate, ctx->MBEDTLS_PRIVATE(pub_key),
                 sizeof( ctx->MBEDTLS_PRIVATE(pub_key) ) ) )
    {
        return( MBEDTLS_ERR_LMS_VERIFY_FAILED );
    }

    return( 0 );
}

int mbedtls_lmots_import_pubkey( mbedtls_lmots_context *ctx,
                                 const unsigned char *key )
{
    if ( ctx == NULL || key == NULL)
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    ctx->MBEDTLS_PRIVATE(type) = network_bytes_to_val( MBEDTLS_LMOTS_TYPE_LEN,
                                                       key + MBEDTLS_LMOTS_SIG_TYPE_OFFSET );

    memcpy( ctx->MBEDTLS_PRIVATE(I_key_identifier), key + MBEDTLS_LMOTS_PUBKEY_I_KEY_ID_OFFSET,
            MBEDTLS_LMOTS_I_KEY_ID_LEN );

    memcpy( ctx->MBEDTLS_PRIVATE(q_leaf_identifier_bytes), key + MBEDTLS_LMOTS_PUBKEY_Q_LEAF_ID_OFFSET,
            MBEDTLS_LMOTS_Q_LEAF_ID_LEN );
    ctx->MBEDTLS_PRIVATE(q_leaf_identifier) = network_bytes_to_val( MBEDTLS_LMOTS_Q_LEAF_ID_LEN,
                                                                    ctx->MBEDTLS_PRIVATE(q_leaf_identifier_bytes) );

    memcpy( ctx->MBEDTLS_PRIVATE(pub_key), key + MBEDTLS_LMOTS_PUBKEY_KEY_HASH_OFFSET, MBEDTLS_LMOTS_N_HASH_LEN );

    ctx->MBEDTLS_PRIVATE(have_pubkey) = 1;

    return( 0 );
}

int mbedtls_lmots_export_pubkey( mbedtls_lmots_context *ctx,
                                 unsigned char *key )
{
    if ( ctx == NULL || key == NULL)
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if ( ! ctx->MBEDTLS_PRIVATE(have_pubkey) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    val_to_network_bytes( ctx->MBEDTLS_PRIVATE(type), MBEDTLS_LMOTS_TYPE_LEN,
                          key + MBEDTLS_LMOTS_SIG_TYPE_OFFSET );

    memcpy( key + MBEDTLS_LMOTS_PUBKEY_I_KEY_ID_OFFSET, ctx->MBEDTLS_PRIVATE(I_key_identifier),
            MBEDTLS_LMOTS_I_KEY_ID_LEN );

    memcpy( key + MBEDTLS_LMOTS_PUBKEY_Q_LEAF_ID_OFFSET, ctx->MBEDTLS_PRIVATE(q_leaf_identifier_bytes),
            MBEDTLS_LMOTS_Q_LEAF_ID_LEN );

    memcpy( key + MBEDTLS_LMOTS_PUBKEY_KEY_HASH_OFFSET, ctx->MBEDTLS_PRIVATE(pub_key),
            MBEDTLS_LMOTS_N_HASH_LEN );

    return( 0 );
}


int mbedtls_lmots_gen_pubkey( mbedtls_lmots_context *ctx )
{
    unsigned char y_hashed_symbols[MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN][32];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    /* Check that a private key is loaded */
    if ( !ctx->MBEDTLS_PRIVATE(have_privkey) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    ret = hash_symbol_array( ctx->MBEDTLS_PRIVATE(I_key_identifier),
                             ctx->MBEDTLS_PRIVATE(q_leaf_identifier_bytes),
                             ( const unsigned char( *)[32] )(ctx->MBEDTLS_PRIVATE(priv_key)),
                             NULL, NULL, y_hashed_symbols );
    if ( ret )
    {
        return( ret );
    }

    ret = public_key_from_hashed_symbol_array( ctx->MBEDTLS_PRIVATE(I_key_identifier),
                                               ctx->MBEDTLS_PRIVATE(q_leaf_identifier_bytes),
                                               ( const unsigned char( *)[32] )y_hashed_symbols,
                                               ctx->MBEDTLS_PRIVATE(pub_key) );
    if ( ret )
    {
        return( ret );
    }

    ctx->MBEDTLS_PRIVATE(have_pubkey = 1);

    return( ret );
}

int mbedtls_lmots_gen_privkey( mbedtls_lmots_context *ctx,
                               const unsigned char I_key_identifier[MBEDTLS_LMOTS_I_KEY_ID_LEN],
                               unsigned int q_leaf_identifier,
                               const unsigned char *seed,
                               size_t seed_len )
{
    psa_hash_operation_t op;
    psa_status_t status;
    size_t output_hash_len;
    unsigned int i_symbol_idx;
    unsigned char i_symbol_idx_bytes[2];
    unsigned char const_bytes[1];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ctx == NULL || I_key_identifier == NULL || seed == NULL)
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if ( ctx->MBEDTLS_PRIVATE(have_privkey) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if ( ctx->MBEDTLS_PRIVATE(type) != MBEDTLS_LMOTS_SHA256_N32_W8 ) {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    memcpy( ctx->MBEDTLS_PRIVATE(I_key_identifier), I_key_identifier,
            sizeof( ctx->MBEDTLS_PRIVATE(I_key_identifier) ) );

    ctx->MBEDTLS_PRIVATE(q_leaf_identifier) = q_leaf_identifier;

    val_to_network_bytes( ctx->MBEDTLS_PRIVATE(q_leaf_identifier), MBEDTLS_LMOTS_Q_LEAF_ID_LEN,
                          ctx->MBEDTLS_PRIVATE(q_leaf_identifier_bytes) );

    val_to_network_bytes( 0xFF, sizeof( const_bytes ), const_bytes );

    for ( i_symbol_idx = 0; i_symbol_idx < MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN; i_symbol_idx++ )
    {
        op = psa_hash_operation_init( );
        status = psa_hash_setup( &op, PSA_ALG_SHA_256 );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret != 0 )
        {
            goto out;
        }

        ret = psa_hash_update( &op, ctx->MBEDTLS_PRIVATE(I_key_identifier),
                               sizeof( ctx->MBEDTLS_PRIVATE(I_key_identifier) ) );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret ) {
            goto out;
        }

        status = psa_hash_update( &op, ctx->MBEDTLS_PRIVATE(q_leaf_identifier_bytes),
                               sizeof( ctx->MBEDTLS_PRIVATE(q_leaf_identifier_bytes) ) );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret )
        {
            goto out;
        }

        val_to_network_bytes( i_symbol_idx, I_SYMBOL_IDX_LEN, i_symbol_idx_bytes );
        status = psa_hash_update( &op, i_symbol_idx_bytes, I_SYMBOL_IDX_LEN );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret )
        {
            goto out;
        }

        status = psa_hash_update( &op, const_bytes, sizeof( const_bytes) );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret )
        {
            goto out;
        }

        status = psa_hash_update( &op, seed, seed_len );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret )
        {
            goto out;
        }

        status = psa_hash_finish( &op, ctx->MBEDTLS_PRIVATE(priv_key)[i_symbol_idx],
                                  32, &output_hash_len );
        ret = mbedtls_lms_error_from_psa( status );
        if ( ret )
        {
            goto out;
        }

        psa_hash_abort( &op );
    }

    ctx->MBEDTLS_PRIVATE(have_privkey) = 1;

out:
    if( ret )
    {
        psa_hash_abort( &op );
        return( ret );
    }

    return ret;
}

#endif /* MBEDTLS_LMS_C */
