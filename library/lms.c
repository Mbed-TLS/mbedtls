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

#include "mbedtls/lms.h"
#include "mbedtls/lmots.h"
#include "mbedtls/md.h"
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

#define MERKLE_TREE_NODE_AM (1 << (MBEDTLS_LMS_H_TREE_HEIGHT + 1))
#define MERKLE_TREE_LEAF_AM (1 << MBEDTLS_LMS_H_TREE_HEIGHT)
#define MERKLE_TREE_INTR_AM (1 << MBEDTLS_LMS_H_TREE_HEIGHT)

#define D_CONST_LEN           (2)

#define D_LEAF_CONSTANT     (0x8282)
#define D_INTR_CONSTANT     (0x8383)

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

static int create_merkle_leaf_node( const mbedtls_lms_context *ctx,
                                    unsigned char pub_key[MBEDTLS_LMOTS_N_HASH_LEN],
                                    unsigned int r_node_idx,
                                    unsigned char out[32] )
{
    mbedtls_md_context_t hash_ctx;
    unsigned char D_LEAF_bytes[D_CONST_LEN];
    unsigned char r_node_idx_bytes[4];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_md_init( &hash_ctx );
    ret = mbedtls_md_setup( &hash_ctx, mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), 0 );
    if( ret )
    {
        goto out;
    }
    ret = mbedtls_md_starts( &hash_ctx );
    if( ret )
    {
        goto out;
    }

    ret = mbedtls_md_update( &hash_ctx,
                             ctx->MBEDTLS_PRIVATE(I_key_identifier),
                             MBEDTLS_LMOTS_I_KEY_ID_LEN );
    if( ret )
    {
        goto out;
    }

    val_to_network_bytes( r_node_idx, 4, r_node_idx_bytes );
    ret = mbedtls_md_update( &hash_ctx, r_node_idx_bytes, 4 );
    if( ret )
    {
        goto out;
    }

    val_to_network_bytes( D_LEAF_CONSTANT, D_CONST_LEN, D_LEAF_bytes );
    ret = mbedtls_md_update( &hash_ctx, D_LEAF_bytes, D_CONST_LEN );
    if( ret )
    {
        goto out;
    }

    ret = mbedtls_md_update( &hash_ctx, pub_key, MBEDTLS_LMOTS_N_HASH_LEN );
    if( ret )
    {
        goto out;
    }

    ret = mbedtls_md_finish( &hash_ctx, out );
    if( ret )
    {
        goto out;
    }

out:
    mbedtls_md_free( &hash_ctx );

    return( ret );
}

static int create_merkle_intr_node( const mbedtls_lms_context *ctx,
                                    const unsigned char left_node[32],
                                    const unsigned char rght_node[32],
                                    unsigned int r_node_idx,
                                    unsigned char out[32] )
{
    mbedtls_md_context_t hash_ctx;
    unsigned char D_INTR_bytes[D_CONST_LEN];
    unsigned char r_node_idx_bytes[4];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_md_init( &hash_ctx );
    ret = mbedtls_md_setup( &hash_ctx, mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), 0 );
    if( ret )
    {
        goto out;
    }
    ret = mbedtls_md_starts( &hash_ctx );
    if( ret )
    {
        goto out;
    }

    ret = mbedtls_md_update( &hash_ctx, ctx->MBEDTLS_PRIVATE(I_key_identifier),
                             MBEDTLS_LMOTS_I_KEY_ID_LEN );
    if( ret )
    {
        goto out;
    }

    val_to_network_bytes( r_node_idx, 4, r_node_idx_bytes );
    ret = mbedtls_md_update( &hash_ctx, r_node_idx_bytes, 4 );
    if( ret )
    {
        goto out;
    }

    val_to_network_bytes( D_INTR_CONSTANT, D_CONST_LEN, D_INTR_bytes );
    ret = mbedtls_md_update( &hash_ctx, D_INTR_bytes, D_CONST_LEN );
    if( ret )
    {
        goto out;
    }

    ret = mbedtls_md_update( &hash_ctx, left_node, MBEDTLS_LMOTS_N_HASH_LEN );
    if( ret )
    {
        goto out;
    }

    ret = mbedtls_md_update( &hash_ctx, rght_node, MBEDTLS_LMOTS_N_HASH_LEN );
    if( ret )
    {
        goto out;
    }

    ret = mbedtls_md_finish( &hash_ctx, out );
    if( ret )
    {
        goto out;
    }

out:
    mbedtls_md_free( &hash_ctx );

    return ret;
}

static int generate_merkle_tree( mbedtls_lms_context *ctx,
                                 unsigned char tree[MERKLE_TREE_NODE_AM][32] )
{
    unsigned int priv_key_idx;
    unsigned int r_node_idx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* First create the leaf nodes, in ascending order */
    for( priv_key_idx = 0; priv_key_idx < MERKLE_TREE_INTR_AM; priv_key_idx++ )
    {
        r_node_idx = MERKLE_TREE_INTR_AM + priv_key_idx;

        ret = create_merkle_leaf_node( ctx, ctx->MBEDTLS_PRIVATE(priv_keys)[priv_key_idx].pub_key,
                                       r_node_idx, tree[r_node_idx] );
        if( ret )
        {
            return( ret );
        }
    }

    /* Then the internal nodes, in reverse order so that we can guarantee the
     * parent has been created */
    for( r_node_idx = MERKLE_TREE_INTR_AM - 1; r_node_idx > 0; r_node_idx-- )
    {
        ret = create_merkle_intr_node( ctx, tree[(r_node_idx * 2)],
                                       tree[(r_node_idx * 2 + 1)],
                                       r_node_idx, tree[r_node_idx] );
        if( ret )
        {
            return( ret );
        }
    }

    return( 0 );
}

static int get_merkle_path( mbedtls_lms_context *ctx,
                            unsigned int leaf_node_id, unsigned char path[MBEDTLS_LMS_H_TREE_HEIGHT][32] )
{
    unsigned char tree[MERKLE_TREE_NODE_AM][32];
    unsigned int curr_node_id = leaf_node_id;
    unsigned int parent_node_id;
    unsigned char sibling_relative_id;
    unsigned int adjacent_node_id;
    unsigned int height;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = generate_merkle_tree( ctx, tree);
    if( ret )
    {
        return( ret );
    }

    for( height = 0; height < MBEDTLS_LMS_H_TREE_HEIGHT; height++ )
    {
        parent_node_id = ( curr_node_id / 2 );

        /* 0 if the node is a left child, 1 if the node is a right child */
        sibling_relative_id = curr_node_id & 1;

        adjacent_node_id = ( parent_node_id * 2 ) + ( 1 - sibling_relative_id );

        memcpy( &path[height], &tree[adjacent_node_id], MBEDTLS_LMOTS_N_HASH_LEN );

        curr_node_id = parent_node_id;
    }

    return( 0 );
}

void mbedtls_lms_init( mbedtls_lms_context *ctx )
{
    if( ctx == NULL )
    {
        return;
    }

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_lms_context ) ) ;
}

void mbedtls_lms_free( mbedtls_lms_context *ctx )
{
    unsigned int idx;

    if( ctx == NULL )
    {
        return;
    }

    if( ctx->MBEDTLS_PRIVATE(have_privkey) )
    {
        for( idx = 0; idx < MERKLE_TREE_LEAF_AM; idx++ )
        {
            mbedtls_lmots_free( &ctx->MBEDTLS_PRIVATE(priv_keys)[idx] );
        }

        mbedtls_free( ctx->MBEDTLS_PRIVATE(priv_keys) );
    }

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_lms_context ) );
}

int mbedtls_lms_set_algorithm_type( mbedtls_lms_context *ctx,
                                    mbedtls_lms_algorithm_type_t type,
                                    mbedtls_lmots_algorithm_type_t otstype )
{
    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    ctx->MBEDTLS_PRIVATE(type) = type;
    ctx->MBEDTLS_PRIVATE(otstype) = otstype;

    return( 0 );
}

int mbedtls_lms_sign( mbedtls_lms_context *ctx,
                      int ( *f_rng)(void *, unsigned char *, size_t),
                      void* p_rng, unsigned char *msg, unsigned int msg_len,
                      unsigned char *sig )
{
    unsigned int q_leaf_identifier;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ! ctx->MBEDTLS_PRIVATE(have_privkey) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( msg == NULL )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( sig == NULL )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }


    if( ctx->MBEDTLS_PRIVATE(type) != MBEDTLS_LMS_SHA256_M32_H10 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(otstype) != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }


    if( ctx->MBEDTLS_PRIVATE(q_next_usable_key) >= MERKLE_TREE_LEAF_AM )
    {
        return( MBEDTLS_ERR_LMS_OUT_OF_PRIV_KEYS );
    }


    q_leaf_identifier = ctx->MBEDTLS_PRIVATE(q_next_usable_key);
    /* This new value must _always_ be written back to the disk before the
     * signature is returned.
     */
    ctx->MBEDTLS_PRIVATE(q_next_usable_key) += 1;

    ret = mbedtls_lmots_sign( &ctx->MBEDTLS_PRIVATE(priv_keys)[q_leaf_identifier],
                              f_rng, p_rng, msg, msg_len,
                              sig + MBEDTLS_LMS_SIG_OTS_SIG_OFFSET );
    if( ret )
    {
        return( ret );
    }

    val_to_network_bytes( ctx->MBEDTLS_PRIVATE(type), MBEDTLS_LMS_TYPE_LEN,
                          sig + MBEDTLS_LMS_SIG_TYPE_OFFSET );
    val_to_network_bytes( q_leaf_identifier, MBEDTLS_LMOTS_Q_LEAF_ID_LEN,
                          sig + MBEDTLS_LMS_SIG_Q_LEAF_ID_OFFSET);

    ret = get_merkle_path( ctx, MERKLE_TREE_INTR_AM + q_leaf_identifier,
                           ( unsigned char( * )[32] )( sig + MBEDTLS_LMS_SIG_PATH_OFFSET ) );
    if( ret )
    {
        return( ret );
    }

    return( 0 );
}

int mbedtls_lms_verify( const mbedtls_lms_context *ctx,
                        const unsigned char *msg, unsigned int msg_len,
                        const unsigned char *sig )
{
    unsigned int q_leaf_identifier;
    unsigned char Kc_candidate_ots_pub_key[MBEDTLS_LMOTS_N_HASH_LEN];
    unsigned char Tc_candidate_root_node[32];
    unsigned int height;
    unsigned int curr_node_id;
    unsigned int parent_node_id;
    const unsigned char* left_node;
    const unsigned char* rght_node;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ! ctx->MBEDTLS_PRIVATE(have_pubkey) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( msg == NULL)
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( sig == NULL)
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(type) != MBEDTLS_LMS_SHA256_M32_H10 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(otstype) != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }


    if( network_bytes_to_val( MBEDTLS_LMS_TYPE_LEN,
                              sig + MBEDTLS_LMS_SIG_TYPE_OFFSET) != MBEDTLS_LMS_SHA256_M32_H10 )
    {
        return( MBEDTLS_ERR_LMS_VERIFY_FAILED );
    }

    if( network_bytes_to_val( MBEDTLS_LMOTS_TYPE_LEN,
                              sig + MBEDTLS_LMS_SIG_OTS_SIG_OFFSET + MBEDTLS_LMOTS_SIG_TYPE_OFFSET)
        != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_VERIFY_FAILED );
    }


    q_leaf_identifier = network_bytes_to_val( MBEDTLS_LMOTS_Q_LEAF_ID_LEN,
                                              sig + MBEDTLS_LMS_SIG_Q_LEAF_ID_OFFSET );

    if( q_leaf_identifier >= MERKLE_TREE_LEAF_AM )
    {
        return( MBEDTLS_ERR_LMS_VERIFY_FAILED );
    }

    ret = mbedtls_lmots_generate_pub_key_candidate( ctx->MBEDTLS_PRIVATE(I_key_identifier),
                                                    sig + MBEDTLS_LMS_SIG_Q_LEAF_ID_OFFSET,
                                                    msg, msg_len,
                                                    sig + MBEDTLS_LMS_SIG_OTS_SIG_OFFSET,
                                                    Kc_candidate_ots_pub_key );
    if( ret )
    {
        return( ret );
    }

    create_merkle_leaf_node( ctx, Kc_candidate_ots_pub_key,
                             MERKLE_TREE_INTR_AM + q_leaf_identifier,
                             Tc_candidate_root_node );

    curr_node_id = MERKLE_TREE_INTR_AM + q_leaf_identifier;

    for( height = 0; height < MBEDTLS_LMS_H_TREE_HEIGHT; height++ )
    {
        parent_node_id = curr_node_id / 2;

        /* Left/right node ordering matters for the hash */
        if( curr_node_id & 1 )
        {
            left_node = ( ( const unsigned char( * )[32] )( sig + MBEDTLS_LMS_SIG_PATH_OFFSET ) )[height];
            rght_node = Tc_candidate_root_node;
        }
        else
        {
            left_node = Tc_candidate_root_node;
            rght_node = ( ( const unsigned char( * )[32] )( sig + MBEDTLS_LMS_SIG_PATH_OFFSET ) )[height];
        }

        create_merkle_intr_node( ctx, left_node, rght_node, parent_node_id,
                                 Tc_candidate_root_node);

        curr_node_id /= 2;
    }

    if( memcmp( Tc_candidate_root_node, ctx->MBEDTLS_PRIVATE(T_1_pub_key),
                MBEDTLS_LMOTS_N_HASH_LEN) )
    {
        return( MBEDTLS_ERR_LMS_VERIFY_FAILED );
    }

    return( 0 );
}

int mbedtls_lms_import_pubkey( mbedtls_lms_context *ctx,
                               const unsigned char *key )
{
    mbedtls_lms_algorithm_type_t type;
    mbedtls_lmots_algorithm_type_t otstype;

    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( key == NULL )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    type = network_bytes_to_val( MBEDTLS_LMS_TYPE_LEN, key + MBEDTLS_LMS_PUBKEY_TYPE_OFFSET );
    if( type != MBEDTLS_LMS_SHA256_M32_H10 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }
    ctx->MBEDTLS_PRIVATE(type) = type;

    otstype = network_bytes_to_val( MBEDTLS_LMOTS_TYPE_LEN,
                                    key + MBEDTLS_LMS_PUBKEY_OTSTYPE_OFFSET );
    if( otstype != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }
    ctx->MBEDTLS_PRIVATE(otstype) = otstype;

    memcpy( ctx->MBEDTLS_PRIVATE(I_key_identifier), key + MBEDTLS_LMS_PUBKEY_I_KEY_ID_OFFSET,
            MBEDTLS_LMOTS_I_KEY_ID_LEN );
    memcpy( ctx->MBEDTLS_PRIVATE(T_1_pub_key), key + MBEDTLS_LMS_PUBKEY_ROOT_NODE_OFFSET,
            MBEDTLS_LMOTS_N_HASH_LEN );

    ctx->MBEDTLS_PRIVATE(have_pubkey) = 1;

    return( 0 );
}

int mbedtls_lms_export_pubkey( mbedtls_lms_context *ctx,
                               unsigned char *key )
{
    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( key == NULL )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ! ctx->MBEDTLS_PRIVATE(have_pubkey) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    val_to_network_bytes( ctx->MBEDTLS_PRIVATE(type),
                          MBEDTLS_LMS_TYPE_LEN, key + MBEDTLS_LMS_PUBKEY_TYPE_OFFSET );
    val_to_network_bytes( ctx->MBEDTLS_PRIVATE(otstype),
                          MBEDTLS_LMOTS_TYPE_LEN, key + MBEDTLS_LMS_PUBKEY_OTSTYPE_OFFSET );
    memcpy( key + MBEDTLS_LMS_PUBKEY_I_KEY_ID_OFFSET,
            ctx->MBEDTLS_PRIVATE(I_key_identifier),
            MBEDTLS_LMOTS_I_KEY_ID_LEN );
    memcpy( key + MBEDTLS_LMS_PUBKEY_ROOT_NODE_OFFSET,
            ctx->MBEDTLS_PRIVATE(T_1_pub_key),
            MBEDTLS_LMOTS_N_HASH_LEN );

    return( 0 );
}

int mbedtls_lms_gen_pubkey( mbedtls_lms_context *ctx )
{
    unsigned char tree[MERKLE_TREE_NODE_AM][32];
    unsigned int idx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ! ctx->MBEDTLS_PRIVATE( have_privkey ) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(type) != MBEDTLS_LMS_SHA256_M32_H10 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(otstype) != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    for( idx = 0; idx < MERKLE_TREE_LEAF_AM; idx++ )
    {
        ret = mbedtls_lmots_gen_pubkey( &ctx->MBEDTLS_PRIVATE(priv_keys)[idx] );
        if( ret )
        {
            return( ret );
        }
    }

    ret = generate_merkle_tree( ctx, tree);
    if( ret )
    {
        return( ret );
    }

    /* Root node is always at position 1, due to 1-based indexing */
    memcpy( ctx->MBEDTLS_PRIVATE(T_1_pub_key), &tree[1], MBEDTLS_LMOTS_N_HASH_LEN );

    ctx->MBEDTLS_PRIVATE(have_pubkey) = 1;

    return( 0 );
}

int mbedtls_lms_gen_privkey( mbedtls_lms_context *ctx,
                             int ( *f_rng)(void *, unsigned char *, size_t),
                             void* p_rng, unsigned char *seed,
                             size_t seed_len )
{
    unsigned int idx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(type) != MBEDTLS_LMS_SHA256_M32_H10 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(otstype) != MBEDTLS_LMOTS_SHA256_N32_W8 )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    if( ctx->MBEDTLS_PRIVATE(have_privkey) )
    {
        return( MBEDTLS_ERR_LMS_BAD_INPUT_DATA );
    }

    f_rng( p_rng, ctx->MBEDTLS_PRIVATE(I_key_identifier),
           sizeof( ctx->MBEDTLS_PRIVATE(I_key_identifier) ) );

    ctx->MBEDTLS_PRIVATE(priv_keys) = mbedtls_calloc( MERKLE_TREE_LEAF_AM,
                                                      sizeof( mbedtls_lmots_context));
    if( ctx->MBEDTLS_PRIVATE(priv_keys) == NULL )
    {
        ret = MBEDTLS_ERR_LMS_ALLOC_FAILED;
        goto out;
    }

    for( idx = 0; idx < MERKLE_TREE_LEAF_AM; idx++ )
    {
        mbedtls_lmots_init( &ctx->MBEDTLS_PRIVATE(priv_keys)[idx] );
        ret = mbedtls_lmots_set_algorithm_type( &ctx->MBEDTLS_PRIVATE(priv_keys)[idx],
                                                ctx->MBEDTLS_PRIVATE(otstype) );
        if( ret)
        {
            goto out;
        }
    }


    for( idx = 0; idx < MERKLE_TREE_LEAF_AM; idx++ )
    {
        ret = mbedtls_lmots_gen_privkey( &ctx->MBEDTLS_PRIVATE(priv_keys)[idx],
                                         ctx->MBEDTLS_PRIVATE(I_key_identifier),
                                         idx, seed, seed_len );
        if( ret)
        {
            goto out;
        }
    }

    ctx->MBEDTLS_PRIVATE(q_next_usable_key) = 0;
    ctx->MBEDTLS_PRIVATE(have_privkey) = 1;

out:
    if( ret )
    {
        mbedtls_free( ctx->MBEDTLS_PRIVATE(priv_keys) );
        return( ret );
    }

    return( 0 );
}

#endif /* MBEDTLS_LMS_C */
