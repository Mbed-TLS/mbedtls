/*
 *  The LMS stateful-hash public-key signature scheme
 *
 *  Copyright The Mbed TLS Contributors
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
 *  of the LMS algorithm:
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

#include "psa/crypto.h"

#include "mbedtls/lms.h"
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_printf printf
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

#define MBEDTLS_LMS_SIG_Q_LEAF_ID_OFFSET    (0)
#define MBEDTLS_LMS_SIG_OTS_SIG_OFFSET      (MBEDTLS_LMS_SIG_Q_LEAF_ID_OFFSET + MBEDTLS_LMOTS_Q_LEAF_ID_LEN)
#define MBEDTLS_LMS_SIG_TYPE_OFFSET         (MBEDTLS_LMS_SIG_OTS_SIG_OFFSET   + MBEDTLS_LMOTS_SIG_LEN)
#define MBEDTLS_LMS_SIG_PATH_OFFSET         (MBEDTLS_LMS_SIG_TYPE_OFFSET      + MBEDTLS_LMS_TYPE_LEN)

#define MBEDTLS_LMS_PUBLIC_KEY_TYPE_OFFSET      (0)
#define MBEDTLS_LMS_PUBLIC_KEY_OTSTYPE_OFFSET   (MBEDTLS_LMS_PUBLIC_KEY_TYPE_OFFSET     + MBEDTLS_LMS_TYPE_LEN)
#define MBEDTLS_LMS_PUBLIC_KEY_I_KEY_ID_OFFSET  (MBEDTLS_LMS_PUBLIC_KEY_OTSTYPE_OFFSET  + MBEDTLS_LMOTS_TYPE_LEN)
#define MBEDTLS_LMS_PUBLIC_KEY_ROOT_NODE_OFFSET (MBEDTLS_LMS_PUBLIC_KEY_I_KEY_ID_OFFSET + MBEDTLS_LMOTS_I_KEY_ID_LEN)


#define MERKLE_TREE_NODE_AM (1u << (MBEDTLS_LMS_H_TREE_HEIGHT + 1u))
#define MERKLE_TREE_LEAF_NODE_AM (1u << MBEDTLS_LMS_H_TREE_HEIGHT)
#define MERKLE_TREE_INTERNAL_NODE_AM (1u << MBEDTLS_LMS_H_TREE_HEIGHT)

#define D_CONST_LEN           (2)
static const unsigned char D_LEAF_CONSTANT_BYTES[D_CONST_LEN] = {0x82, 0x82};
static const unsigned char D_INTERNAL_CONSTANT_BYTES[D_CONST_LEN] = {0x83, 0x83};

static int create_merkle_leaf_node( const unsigned char I_key_identifier[MBEDTLS_LMOTS_I_KEY_ID_LEN],
                                    unsigned char pub_key[MBEDTLS_LMOTS_N_HASH_LEN],
                                    unsigned int r_node_idx,
                                    unsigned char out[MBEDTLS_LMS_M_NODE_BYTES] )
{
    psa_hash_operation_t op;
    psa_status_t status;
    size_t output_hash_len;
    unsigned char r_node_idx_bytes[4];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    op = psa_hash_operation_init( );
    status = psa_hash_setup( &op, PSA_ALG_SHA_256 );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    status = psa_hash_update( &op, I_key_identifier, MBEDTLS_LMOTS_I_KEY_ID_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if( ret )
        goto exit;

    unsigned_int_to_network_bytes( r_node_idx, 4, r_node_idx_bytes );
    status = psa_hash_update( &op, r_node_idx_bytes, 4 );
    ret = mbedtls_lms_error_from_psa( status );
    if( ret )
        goto exit;

    status = psa_hash_update( &op, D_LEAF_CONSTANT_BYTES, D_CONST_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if( ret )
        goto exit;

    status = psa_hash_update( &op, pub_key, MBEDTLS_LMOTS_N_HASH_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if( ret )
        goto exit;

    status = psa_hash_finish( &op, out, MBEDTLS_LMS_M_NODE_BYTES, &output_hash_len);
    ret = mbedtls_lms_error_from_psa( status );
    if( ret )
        goto exit;

exit:
    psa_hash_abort( &op );

    return( ret );
}

static int create_merkle_internal_node( const unsigned char I_key_identifier[MBEDTLS_LMOTS_I_KEY_ID_LEN],
                                        const unsigned char left_node[MBEDTLS_LMS_M_NODE_BYTES],
                                        const unsigned char right_node[MBEDTLS_LMS_M_NODE_BYTES],
                                        unsigned int r_node_idx,
                                        unsigned char out[MBEDTLS_LMS_M_NODE_BYTES] )
{
    psa_hash_operation_t op;
    psa_status_t status;
    size_t output_hash_len;
    unsigned char r_node_idx_bytes[4];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    op = psa_hash_operation_init( );
    status = psa_hash_setup( &op, PSA_ALG_SHA_256 );
    ret = mbedtls_lms_error_from_psa( status );
    if ( ret != 0 )
        goto exit;

    status = psa_hash_update( &op, I_key_identifier, MBEDTLS_LMOTS_I_KEY_ID_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if( ret )
        goto exit;

    unsigned_int_to_network_bytes( r_node_idx, 4, r_node_idx_bytes );
    status = psa_hash_update( &op, r_node_idx_bytes, 4 );
    ret = mbedtls_lms_error_from_psa( status );
    if( ret )
        goto exit;

    status = psa_hash_update( &op, D_INTERNAL_CONSTANT_BYTES, D_CONST_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if( ret )
        goto exit;

    status = psa_hash_update( &op, left_node, MBEDTLS_LMOTS_N_HASH_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if( ret )
        goto exit;

    status = psa_hash_update( &op, right_node, MBEDTLS_LMOTS_N_HASH_LEN );
    ret = mbedtls_lms_error_from_psa( status );
    if( ret )
        goto exit;

    ret = psa_hash_finish( &op, out, MBEDTLS_LMS_M_NODE_BYTES, &output_hash_len);
    ret = mbedtls_lms_error_from_psa( status );
    if( ret )
        goto exit;

exit:
    psa_hash_abort( &op );

    return ret;
}

static int calculate_merkle_tree( mbedtls_lms_private_t *ctx,
                                 unsigned char tree[MERKLE_TREE_NODE_AM][MBEDTLS_LMS_M_NODE_BYTES] )
{
    unsigned int priv_key_idx;
    unsigned int r_node_idx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* First create the leaf nodes, in ascending order */
    for( priv_key_idx = 0; priv_key_idx < MERKLE_TREE_INTERNAL_NODE_AM;
         priv_key_idx++ )
    {
        r_node_idx = MERKLE_TREE_INTERNAL_NODE_AM + priv_key_idx;

        ret = create_merkle_leaf_node(
            ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(I_key_identifier),
            ctx->MBEDTLS_PRIVATE(ots_public_keys)[priv_key_idx].MBEDTLS_PRIVATE(public_key),
            r_node_idx, tree[r_node_idx] );
        if( ret )
        {
            return( ret );
        }
    }

    /* Then the internal nodes, in reverse order so that we can guarantee the
     * parent has been created */
    for( r_node_idx = MERKLE_TREE_INTERNAL_NODE_AM - 1; r_node_idx > 0;
         r_node_idx-- )
    {
        ret = create_merkle_internal_node(
            ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(I_key_identifier),
            tree[(r_node_idx * 2)], tree[(r_node_idx * 2 + 1)], r_node_idx, tree[r_node_idx] );
        if( ret )
        {
            return( ret );
        }
    }

    return( 0 );
}

static int get_merkle_path( mbedtls_lms_private_t *ctx,
                            unsigned int leaf_node_id,
                            unsigned char path[MBEDTLS_LMS_H_TREE_HEIGHT][MBEDTLS_LMS_M_NODE_BYTES] )
{
    unsigned char tree[MERKLE_TREE_NODE_AM][MBEDTLS_LMS_M_NODE_BYTES];
    unsigned int curr_node_id = leaf_node_id;
    unsigned int adjacent_node_id;
    unsigned int height;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = calculate_merkle_tree( ctx, tree);
    if( ret )
    {
        return( ret );
    }

    for( height = 0; height < MBEDTLS_LMS_H_TREE_HEIGHT; height++ )
    {
        adjacent_node_id = curr_node_id ^ 1;

        memcpy( &path[height], &tree[adjacent_node_id], MBEDTLS_LMOTS_N_HASH_LEN );

        curr_node_id >>=1;
    }

    return( 0 );
}

void mbedtls_lms_init_public( mbedtls_lms_public_t *ctx )
{
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_lms_public_t ) ) ;
}

void mbedtls_lms_free_public( mbedtls_lms_public_t *ctx )
{
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_lms_public_t ) );
}

int mbedtls_lms_import_public_key( mbedtls_lms_public_t *ctx,
                               const unsigned char *key, size_t key_size )
{
    mbedtls_lms_algorithm_type_t type;
    mbedtls_lmots_algorithm_type_t otstype;

    if( key_size < MBEDTLS_LMS_PUBLIC_KEY_LEN )
    {
        return( MBEDTLS_ERR_LMS_BUFFER_TOO_SMALL );
    }

    type = network_bytes_to_unsigned_int( MBEDTLS_LMS_TYPE_LEN, key + MBEDTLS_LMS_PUBLIC_KEY_TYPE_OFFSET );
    if( type != MBEDTLS_LMS_SHA256_M32_H10 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }
    ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(type) = type;

    otstype = network_bytes_to_unsigned_int( MBEDTLS_LMOTS_TYPE_LEN,
                                    key + MBEDTLS_LMS_PUBLIC_KEY_OTSTYPE_OFFSET );
    if( otstype != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }
    ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(otstype) = otstype;

    memcpy( ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(I_key_identifier),
            key + MBEDTLS_LMS_PUBLIC_KEY_I_KEY_ID_OFFSET,
            MBEDTLS_LMOTS_I_KEY_ID_LEN );
    memcpy( ctx->MBEDTLS_PRIVATE(T_1_pub_key), key + MBEDTLS_LMS_PUBLIC_KEY_ROOT_NODE_OFFSET,
            MBEDTLS_LMOTS_N_HASH_LEN );

    ctx->MBEDTLS_PRIVATE(have_public_key) = 1;

    return( 0 );
}

int mbedtls_lms_verify( const mbedtls_lms_public_t *ctx,
                        const unsigned char *msg, size_t msg_size,
                        const unsigned char *sig, size_t sig_size )
{
    unsigned int q_leaf_identifier;
    unsigned char Kc_candidate_ots_pub_key[MBEDTLS_LMOTS_N_HASH_LEN];
    unsigned char Tc_candidate_root_node[MBEDTLS_LMS_M_NODE_BYTES];
    unsigned int height;
    unsigned int curr_node_id;
    unsigned int parent_node_id;
    const unsigned char* left_node;
    const unsigned char* right_node;
    mbedtls_lmots_parameters_t ots_params;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ! ctx->MBEDTLS_PRIVATE(have_public_key) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( sig_size != MBEDTLS_LMS_SIG_LEN )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(type)
        != MBEDTLS_LMS_SHA256_M32_H10 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(otstype)
        != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( network_bytes_to_unsigned_int( MBEDTLS_LMS_TYPE_LEN,
                              sig + MBEDTLS_LMS_SIG_TYPE_OFFSET) != MBEDTLS_LMS_SHA256_M32_H10 )
    {
        return( MBEDTLS_ERR_LMS_VERIFY_FAILED );
    }

    if( network_bytes_to_unsigned_int( MBEDTLS_LMOTS_TYPE_LEN,
                              sig + MBEDTLS_LMS_SIG_OTS_SIG_OFFSET + MBEDTLS_LMOTS_SIG_TYPE_OFFSET)
        != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_VERIFY_FAILED );
    }


    q_leaf_identifier = network_bytes_to_unsigned_int( MBEDTLS_LMOTS_Q_LEAF_ID_LEN,
                                              sig + MBEDTLS_LMS_SIG_Q_LEAF_ID_OFFSET );

    if( q_leaf_identifier >= MERKLE_TREE_LEAF_NODE_AM )
    {
        return( MBEDTLS_ERR_LMS_VERIFY_FAILED );
    }

    memcpy(ots_params.MBEDTLS_PRIVATE(I_key_identifier),
           ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(I_key_identifier),
           MBEDTLS_LMOTS_I_KEY_ID_LEN);
    unsigned_int_to_network_bytes( q_leaf_identifier,
                                   MBEDTLS_LMOTS_Q_LEAF_ID_LEN,
                                   ots_params.MBEDTLS_PRIVATE(q_leaf_identifier) );
    ots_params.type = ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(otstype);

    ret = mbedtls_lmots_calculate_public_key_candidate( &ots_params, msg, msg_size,
                                                        sig + MBEDTLS_LMS_SIG_OTS_SIG_OFFSET,
                                                        MBEDTLS_LMOTS_SIG_LEN,
                                                        Kc_candidate_ots_pub_key,
                                                        sizeof(Kc_candidate_ots_pub_key),
                                                        NULL );
    if( ret )
    {
        return( ret );
    }

    create_merkle_leaf_node(
            ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(I_key_identifier),
            Kc_candidate_ots_pub_key, MERKLE_TREE_INTERNAL_NODE_AM + q_leaf_identifier,
            Tc_candidate_root_node );

    curr_node_id = MERKLE_TREE_INTERNAL_NODE_AM + q_leaf_identifier;

    for( height = 0; height < MBEDTLS_LMS_H_TREE_HEIGHT; height++ )
    {
        parent_node_id = curr_node_id / 2;

        /* Left/right node ordering matters for the hash */
        if( curr_node_id & 1 )
        {
            left_node = ( ( const unsigned char( * )[MBEDTLS_LMS_M_NODE_BYTES] )( sig + MBEDTLS_LMS_SIG_PATH_OFFSET ) )[height];
            right_node = Tc_candidate_root_node;
        }
        else
        {
            left_node = Tc_candidate_root_node;
            right_node = ( ( const unsigned char( * )[MBEDTLS_LMS_M_NODE_BYTES] )( sig + MBEDTLS_LMS_SIG_PATH_OFFSET ) )[height];
        }

        create_merkle_internal_node(
            ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(I_key_identifier),
            left_node, right_node, parent_node_id, Tc_candidate_root_node);

        curr_node_id /= 2;
    }

    if( memcmp( Tc_candidate_root_node, ctx->MBEDTLS_PRIVATE(T_1_pub_key),
                MBEDTLS_LMOTS_N_HASH_LEN) )
    {
        return( MBEDTLS_ERR_LMS_VERIFY_FAILED );
    }

    return( 0 );
}

void mbedtls_lms_init_private( mbedtls_lms_private_t *ctx )
{
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_lms_public_t ) ) ;
}

void mbedtls_lms_free_private( mbedtls_lms_private_t *ctx )
{
    unsigned int idx;

    if( ctx->MBEDTLS_PRIVATE(have_private_key) )
    {
        for( idx = 0; idx < MERKLE_TREE_LEAF_NODE_AM; idx++ )
        {
            mbedtls_lmots_free_private( &ctx->MBEDTLS_PRIVATE(ots_private_keys)[idx] );
            mbedtls_lmots_free_public( &ctx->MBEDTLS_PRIVATE(ots_public_keys)[idx] );
        }

        mbedtls_free( ctx->MBEDTLS_PRIVATE(ots_private_keys) );
        mbedtls_free( ctx->MBEDTLS_PRIVATE(ots_public_keys) );
    }

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_lms_public_t ) );
}


int mbedtls_lms_generate_private_key( mbedtls_lms_private_t *ctx,
                                      mbedtls_lms_algorithm_type_t type,
                                      mbedtls_lmots_algorithm_type_t otstype,
                                      int (*f_rng)(void *, unsigned char *, size_t),
                                      void* p_rng, unsigned char *seed,
                                      size_t seed_size )
{
    unsigned int idx = 0;
    unsigned int free_idx = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( type != MBEDTLS_LMS_SHA256_M32_H10 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( otstype != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(have_private_key) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(type) = type;
    ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(otstype) = otstype;

    f_rng( p_rng,
           ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(I_key_identifier),
           MBEDTLS_LMOTS_I_KEY_ID_LEN );

    ctx->MBEDTLS_PRIVATE(ots_private_keys) = mbedtls_calloc( MERKLE_TREE_LEAF_NODE_AM,
                                                             sizeof( mbedtls_lmots_private_t));
    if( ctx->MBEDTLS_PRIVATE(ots_private_keys) == NULL )
    {
        ret = MBEDTLS_ERR_LMS_ALLOC_FAILED;
        goto exit;
    }

    ctx->MBEDTLS_PRIVATE(ots_public_keys) = mbedtls_calloc( MERKLE_TREE_LEAF_NODE_AM,
                                                            sizeof( mbedtls_lmots_public_t));
    if( ctx->MBEDTLS_PRIVATE(ots_public_keys) == NULL )
    {
        ret = MBEDTLS_ERR_LMS_ALLOC_FAILED;
        goto exit;
    }

    for( idx = 0; idx < MERKLE_TREE_LEAF_NODE_AM; idx++ )
    {
        mbedtls_lmots_init_private( &ctx->MBEDTLS_PRIVATE(ots_private_keys)[idx] );
        mbedtls_lmots_init_public( &ctx->MBEDTLS_PRIVATE(ots_public_keys)[idx] );
    }


    for( idx = 0; idx < MERKLE_TREE_LEAF_NODE_AM; idx++ )
    {
        ret = mbedtls_lmots_generate_private_key( &ctx->MBEDTLS_PRIVATE(ots_private_keys)[idx],
                                                  otstype,
                                                  ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(I_key_identifier),
                                                  idx, seed, seed_size );
        if( ret)
            goto exit;

        ret = mbedtls_lmots_calculate_public_key( &ctx->MBEDTLS_PRIVATE(ots_public_keys)[idx],
                                                  &ctx->MBEDTLS_PRIVATE(ots_private_keys)[idx] );
        if( ret)
            goto exit;
    }

    ctx->MBEDTLS_PRIVATE(q_next_usable_key) = 0;
    ctx->MBEDTLS_PRIVATE(have_private_key) = 1;

exit:
    if( ret )
    {
        for ( free_idx = 0; free_idx < idx; free_idx++ ) {
            mbedtls_lmots_free_private( &ctx->MBEDTLS_PRIVATE(ots_private_keys)[free_idx] );
            mbedtls_lmots_free_public( &ctx->MBEDTLS_PRIVATE(ots_public_keys)[free_idx] );
        }

        mbedtls_free( ctx->MBEDTLS_PRIVATE(ots_private_keys) );
        mbedtls_free( ctx->MBEDTLS_PRIVATE(ots_public_keys) );
        return( ret );
    }

    return( 0 );
}

int mbedtls_lms_calculate_public_key( mbedtls_lms_public_t *ctx,
                                      mbedtls_lms_private_t *priv_ctx )
{
    unsigned char tree[MERKLE_TREE_NODE_AM][MBEDTLS_LMS_M_NODE_BYTES];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ! priv_ctx->MBEDTLS_PRIVATE( have_private_key ) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( priv_ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(type)
        != MBEDTLS_LMS_SHA256_M32_H10 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( priv_ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(otstype)
        != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    memcpy( &ctx->MBEDTLS_PRIVATE(params), &priv_ctx->MBEDTLS_PRIVATE(params),
            sizeof(mbedtls_lmots_parameters_t) );

    ret = calculate_merkle_tree( priv_ctx, tree);
    if( ret )
    {
        return( ret );
    }

    /* Root node is always at position 1, due to 1-based indexing */
    memcpy( ctx->MBEDTLS_PRIVATE(T_1_pub_key), &tree[1], MBEDTLS_LMOTS_N_HASH_LEN );

    ctx->MBEDTLS_PRIVATE(have_public_key) = 1;

    return( 0 );
}


int mbedtls_lms_export_public_key( mbedtls_lms_public_t *ctx, unsigned char *key,
                                   size_t key_size, size_t *key_len )
{
    if( key_size < MBEDTLS_LMS_PUBLIC_KEY_LEN ) {
        return( MBEDTLS_ERR_LMS_BUFFER_TOO_SMALL );
    }

    if( ! ctx->MBEDTLS_PRIVATE(have_public_key) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    unsigned_int_to_network_bytes(
            ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(type),
            MBEDTLS_LMS_TYPE_LEN, key + MBEDTLS_LMS_PUBLIC_KEY_TYPE_OFFSET );
    unsigned_int_to_network_bytes(
            ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(otstype),
            MBEDTLS_LMOTS_TYPE_LEN, key + MBEDTLS_LMS_PUBLIC_KEY_OTSTYPE_OFFSET );
    memcpy( key + MBEDTLS_LMS_PUBLIC_KEY_I_KEY_ID_OFFSET,
            ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(I_key_identifier),
            MBEDTLS_LMOTS_I_KEY_ID_LEN );
    memcpy( key + MBEDTLS_LMS_PUBLIC_KEY_ROOT_NODE_OFFSET,
            ctx->MBEDTLS_PRIVATE(T_1_pub_key),
            MBEDTLS_LMOTS_N_HASH_LEN );

    if( key_len != NULL ) {
        *key_len = MBEDTLS_LMS_PUBLIC_KEY_LEN;
    }

    return( 0 );
}


int mbedtls_lms_sign( mbedtls_lms_private_t *ctx,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void* p_rng, unsigned char *msg, unsigned int msg_size,
                      unsigned char *sig, size_t sig_size, size_t *sig_len)
{
    uint32_t q_leaf_identifier;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ! ctx->MBEDTLS_PRIVATE(have_private_key) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( sig_size < MBEDTLS_LMS_SIG_LEN )
    {
        return( MBEDTLS_ERR_LMS_BUFFER_TOO_SMALL );
    }

    if( ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(type) != MBEDTLS_LMS_SHA256_M32_H10 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(otstype)
        != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(q_next_usable_key) >= MERKLE_TREE_LEAF_NODE_AM )
    {
        return( MBEDTLS_ERR_LMS_OUT_OF_PRIVATE_KEYS );
    }


    q_leaf_identifier = ctx->MBEDTLS_PRIVATE(q_next_usable_key);
    /* This new value must _always_ be written back to the disk before the
     * signature is returned.
     */
    ctx->MBEDTLS_PRIVATE(q_next_usable_key) += 1;

    ret = mbedtls_lmots_sign( &ctx->MBEDTLS_PRIVATE(ots_private_keys)[q_leaf_identifier],
                              f_rng, p_rng, msg, msg_size,
                              sig + MBEDTLS_LMS_SIG_OTS_SIG_OFFSET,
                              MBEDTLS_LMS_SIG_LEN, NULL );
    if( ret )
    {
        return( ret );
    }

    unsigned_int_to_network_bytes( ctx->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(type),
                                   MBEDTLS_LMS_TYPE_LEN, sig + MBEDTLS_LMS_SIG_TYPE_OFFSET );
    unsigned_int_to_network_bytes( q_leaf_identifier, MBEDTLS_LMOTS_Q_LEAF_ID_LEN,
                                   sig + MBEDTLS_LMS_SIG_Q_LEAF_ID_OFFSET);

    ret = get_merkle_path( ctx, MERKLE_TREE_INTERNAL_NODE_AM + q_leaf_identifier,
                           ( unsigned char( * )[MBEDTLS_LMS_M_NODE_BYTES] )( sig + MBEDTLS_LMS_SIG_PATH_OFFSET ) );
    if( ret )
    {
        return( ret );
    }

    if( sig_len != NULL ) {
        *sig_len = MBEDTLS_LMS_SIG_LEN;
    }


    return( 0 );
}

#endif /* MBEDTLS_LMS_C */
