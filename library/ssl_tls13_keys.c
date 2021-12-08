/*
 *  TLS 1.3 key schedule
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 ( the "License" ); you may
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

#include "common.h"

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

#include <stdint.h>
#include <string.h>

#include "mbedtls/hkdf.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#include "ssl_misc.h"
#include "ssl_tls13_keys.h"

#define MBEDTLS_SSL_TLS1_3_LABEL( name, string )       \
    .name = string,

struct mbedtls_ssl_tls13_labels_struct const mbedtls_ssl_tls13_labels =
{
    /* This seems to work in C, despite the string literal being one
     * character too long due to the 0-termination. */
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};

#undef MBEDTLS_SSL_TLS1_3_LABEL

/*
 * This function creates a HkdfLabel structure used in the TLS 1.3 key schedule.
 *
 * The HkdfLabel is specified in RFC 8446 as follows:
 *
 * struct HkdfLabel {
 *   uint16 length;            // Length of expanded key material
 *   opaque label<7..255>;     // Always prefixed by "tls13 "
 *   opaque context<0..255>;   // Usually a communication transcript hash
 * };
 *
 * Parameters:
 * - desired_length: Length of expanded key material
 *                   Even though the standard allows expansion to up to
 *                   2**16 Bytes, TLS 1.3 never uses expansion to more than
 *                   255 Bytes, so we require `desired_length` to be at most
 *                   255. This allows us to save a few Bytes of code by
 *                   hardcoding the writing of the high bytes.
 * - (label, label_len): label + label length, without "tls13 " prefix
 *                       The label length MUST be less than or equal to
 *                       MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN
 *                       It is the caller's responsibility to ensure this.
 *                       All (label, label length) pairs used in TLS 1.3
 *                       can be obtained via MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN().
 * - (ctx, ctx_len): context + context length
 *                   The context length MUST be less than or equal to
 *                   MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN
 *                   It is the caller's responsibility to ensure this.
 * - dst: Target buffer for HkdfLabel structure,
 *        This MUST be a writable buffer of size
 *        at least SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN Bytes.
 * - dst_len: Pointer at which to store the actual length of
 *            the HkdfLabel structure on success.
 */

static const char tls13_label_prefix[6] = "tls13 ";

#define SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN( label_len, context_len ) \
    (   2                  /* expansion length           */ \
      + 1                  /* label length               */ \
      + label_len                                           \
      + 1                  /* context length             */ \
      + context_len )

#define SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN                      \
    SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN(                             \
                     sizeof(tls13_label_prefix) +                       \
                     MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN,     \
                     MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )

static void ssl_tls13_hkdf_encode_label(
                            size_t desired_length,
                            const unsigned char *label, size_t label_len,
                            const unsigned char *ctx, size_t ctx_len,
                            unsigned char *dst, size_t *dst_len )
{
    size_t total_label_len =
        sizeof(tls13_label_prefix) + label_len;
    size_t total_hkdf_lbl_len =
        SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN( total_label_len, ctx_len );

    unsigned char *p = dst;

    /* Add the size of the expanded key material.
     * We're hardcoding the high byte to 0 here assuming that we never use
     * TLS 1.3 HKDF key expansion to more than 255 Bytes. */
#if MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN > 255
#error "The implementation of ssl_tls13_hkdf_encode_label() is not fit for the \
        value of MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN"
#endif

    *p++ = 0;
    *p++ = MBEDTLS_BYTE_0( desired_length );

    /* Add label incl. prefix */
    *p++ = MBEDTLS_BYTE_0( total_label_len );
    memcpy( p, tls13_label_prefix, sizeof(tls13_label_prefix) );
    p += sizeof(tls13_label_prefix);
    memcpy( p, label, label_len );
    p += label_len;

    /* Add context value */
    *p++ = MBEDTLS_BYTE_0( ctx_len );
    if( ctx_len != 0 )
        memcpy( p, ctx, ctx_len );

    /* Return total length to the caller.  */
    *dst_len = total_hkdf_lbl_len;
}

int mbedtls_ssl_tls13_hkdf_expand_label(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *secret, size_t secret_len,
                     const unsigned char *label, size_t label_len,
                     const unsigned char *ctx, size_t ctx_len,
                     unsigned char *buf, size_t buf_len )
{
    const mbedtls_md_info_t *md_info;
    unsigned char hkdf_label[ SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN ];
    size_t hkdf_label_len;

    if( label_len > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN )
    {
        /* Should never happen since this is an internal
         * function, and we know statically which labels
         * are allowed. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( ctx_len > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )
    {
        /* Should not happen, as above. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( buf_len > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN )
    {
        /* Should not happen, as above. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    md_info = mbedtls_md_info_from_type( hash_alg );
    if( md_info == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    ssl_tls13_hkdf_encode_label( buf_len,
                                 label, label_len,
                                 ctx, ctx_len,
                                 hkdf_label,
                                 &hkdf_label_len );

    return( mbedtls_hkdf_expand( md_info,
                                 secret, secret_len,
                                 hkdf_label, hkdf_label_len,
                                 buf, buf_len ) );
}

/*
 * The traffic keying material is generated from the following inputs:
 *
 *  - One secret value per sender.
 *  - A purpose value indicating the specific value being generated
 *  - The desired lengths of key and IV.
 *
 * The expansion itself is based on HKDF:
 *
 *   [sender]_write_key = HKDF-Expand-Label( Secret, "key", "", key_length )
 *   [sender]_write_iv  = HKDF-Expand-Label( Secret, "iv" , "", iv_length )
 *
 * [sender] denotes the sending side and the Secret value is provided
 * by the function caller. Note that we generate server and client side
 * keys in a single function call.
 */
int mbedtls_ssl_tls13_make_traffic_keys(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *client_secret,
                     const unsigned char *server_secret, size_t secret_len,
                     size_t key_len, size_t iv_len,
                     mbedtls_ssl_key_set *keys )
{
    int ret = 0;

    ret = mbedtls_ssl_tls13_hkdf_expand_label( hash_alg,
                    client_secret, secret_len,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( key ),
                    NULL, 0,
                    keys->client_write_key, key_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls13_hkdf_expand_label( hash_alg,
                    server_secret, secret_len,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( key ),
                    NULL, 0,
                    keys->server_write_key, key_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls13_hkdf_expand_label( hash_alg,
                    client_secret, secret_len,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( iv ),
                    NULL, 0,
                    keys->client_write_iv, iv_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls13_hkdf_expand_label( hash_alg,
                    server_secret, secret_len,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( iv ),
                    NULL, 0,
                    keys->server_write_iv, iv_len );
    if( ret != 0 )
        return( ret );

    keys->key_len = key_len;
    keys->iv_len = iv_len;

    return( 0 );
}

int mbedtls_ssl_tls13_derive_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret, size_t secret_len,
                   const unsigned char *label, size_t label_len,
                   const unsigned char *ctx, size_t ctx_len,
                   int ctx_hashed,
                   unsigned char *dstbuf, size_t dstbuf_len )
{
    int ret;
    unsigned char hashed_context[ MBEDTLS_MD_MAX_SIZE ];

    const mbedtls_md_info_t *md_info;
    md_info = mbedtls_md_info_from_type( hash_alg );
    if( md_info == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    if( ctx_hashed == MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED )
    {
        ret = mbedtls_md( md_info, ctx, ctx_len, hashed_context );
        if( ret != 0 )
            return( ret );
        ctx_len = mbedtls_md_get_size( md_info );
    }
    else
    {
        if( ctx_len > sizeof(hashed_context) )
        {
            /* This should never happen since this function is internal
             * and the code sets `ctx_hashed` correctly.
             * Let's double-check nonetheless to not run at the risk
             * of getting a stack overflow. */
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        memcpy( hashed_context, ctx, ctx_len );
    }

    return( mbedtls_ssl_tls13_hkdf_expand_label( hash_alg,
                                                 secret, secret_len,
                                                 label, label_len,
                                                 hashed_context, ctx_len,
                                                 dstbuf, dstbuf_len ) );
}

int mbedtls_ssl_tls13_evolve_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret_old,
                   const unsigned char *input, size_t input_len,
                   unsigned char *secret_new )
{
    int ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    size_t hlen, ilen;
    unsigned char tmp_secret[ MBEDTLS_MD_MAX_SIZE ] = { 0 };
    unsigned char tmp_input [ MBEDTLS_ECP_MAX_BYTES ] = { 0 };

    const mbedtls_md_info_t *md_info;
    md_info = mbedtls_md_info_from_type( hash_alg );
    if( md_info == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    hlen = mbedtls_md_get_size( md_info );

    /* For non-initial runs, call Derive-Secret( ., "derived", "")
     * on the old secret. */
    if( secret_old != NULL )
    {
        ret = mbedtls_ssl_tls13_derive_secret(
                   hash_alg,
                   secret_old, hlen,
                   MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( derived ),
                   NULL, 0, /* context */
                   MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                   tmp_secret, hlen );
        if( ret != 0 )
            goto cleanup;
    }

    if( input != NULL )
    {
        memcpy( tmp_input, input, input_len );
        ilen = input_len;
    }
    else
    {
        ilen = hlen;
    }

    /* HKDF-Extract takes a salt and input key material.
     * The salt is the old secret, and the input key material
     * is the input secret (PSK / ECDHE). */
    ret = mbedtls_hkdf_extract( md_info,
                    tmp_secret, hlen,
                    tmp_input, ilen,
                    secret_new );
    if( ret != 0 )
        goto cleanup;

    ret = 0;

 cleanup:

    mbedtls_platform_zeroize( tmp_secret, sizeof(tmp_secret) );
    mbedtls_platform_zeroize( tmp_input,  sizeof(tmp_input)  );
    return( ret );
}

int mbedtls_ssl_tls13_derive_early_secrets(
          mbedtls_md_type_t md_type,
          unsigned char const *early_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls13_early_secrets *derived )
{
    int ret;
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /*
     *            0
     *            |
     *            v
     *  PSK ->  HKDF-Extract = Early Secret
     *            |
     *            +-----> Derive-Secret(., "c e traffic", ClientHello)
     *            |                     = client_early_traffic_secret
     *            |
     *            +-----> Derive-Secret(., "e exp master", ClientHello)
     *            |                     = early_exporter_master_secret
     *            v
     */

    /* Create client_early_traffic_secret */
    ret = mbedtls_ssl_tls13_derive_secret( md_type,
                         early_secret, md_size,
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_e_traffic ),
                         transcript, transcript_len,
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         derived->client_early_traffic_secret,
                         md_size );
    if( ret != 0 )
        return( ret );

    /* Create early exporter */
    ret = mbedtls_ssl_tls13_derive_secret( md_type,
                         early_secret, md_size,
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( e_exp_master ),
                         transcript, transcript_len,
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         derived->early_exporter_master_secret,
                         md_size );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_ssl_tls13_derive_handshake_secrets(
          mbedtls_md_type_t md_type,
          unsigned char const *handshake_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls13_handshake_secrets *derived )
{
    int ret;
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /*
     *
     * Handshake Secret
     * |
     * +-----> Derive-Secret( ., "c hs traffic",
     * |                     ClientHello...ServerHello )
     * |                     = client_handshake_traffic_secret
     * |
     * +-----> Derive-Secret( ., "s hs traffic",
     * |                     ClientHello...ServerHello )
     * |                     = server_handshake_traffic_secret
     *
     */

    /*
     * Compute client_handshake_traffic_secret with
     * Derive-Secret( ., "c hs traffic", ClientHello...ServerHello )
     */

    ret = mbedtls_ssl_tls13_derive_secret( md_type,
             handshake_secret, md_size,
             MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_hs_traffic ),
             transcript, transcript_len,
             MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
             derived->client_handshake_traffic_secret,
             md_size );
    if( ret != 0 )
        return( ret );

    /*
     * Compute server_handshake_traffic_secret with
     * Derive-Secret( ., "s hs traffic", ClientHello...ServerHello )
     */

    ret = mbedtls_ssl_tls13_derive_secret( md_type,
             handshake_secret, md_size,
             MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( s_hs_traffic ),
             transcript, transcript_len,
             MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
             derived->server_handshake_traffic_secret,
             md_size );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_ssl_tls13_derive_application_secrets(
          mbedtls_md_type_t md_type,
          unsigned char const *application_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls13_application_secrets *derived )
{
    int ret;
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /* Generate {client,server}_application_traffic_secret_0
     *
     * Master Secret
     * |
     * +-----> Derive-Secret( ., "c ap traffic",
     * |                      ClientHello...server Finished )
     * |                      = client_application_traffic_secret_0
     * |
     * +-----> Derive-Secret( ., "s ap traffic",
     * |                      ClientHello...Server Finished )
     * |                      = server_application_traffic_secret_0
     * |
     * +-----> Derive-Secret( ., "exp master",
     * |                      ClientHello...server Finished)
     * |                      = exporter_master_secret
     *
     */

    ret = mbedtls_ssl_tls13_derive_secret( md_type,
              application_secret, md_size,
              MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_ap_traffic ),
              transcript, transcript_len,
              MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
              derived->client_application_traffic_secret_N,
              md_size );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls13_derive_secret( md_type,
              application_secret, md_size,
              MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( s_ap_traffic ),
              transcript, transcript_len,
              MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
              derived->server_application_traffic_secret_N,
              md_size );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls13_derive_secret( md_type,
              application_secret, md_size,
              MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( exp_master ),
              transcript, transcript_len,
              MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
              derived->exporter_master_secret,
              md_size );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

/* Generate resumption_master_secret for use with the ticket exchange.
 *
 * This is not integrated with mbedtls_ssl_tls13_derive_application_secrets()
 * because it uses the transcript hash up to and including ClientFinished. */
int mbedtls_ssl_tls13_derive_resumption_master_secret(
          mbedtls_md_type_t md_type,
          unsigned char const *application_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls13_application_secrets *derived )
{
    int ret;
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    ret = mbedtls_ssl_tls13_derive_secret( md_type,
              application_secret, md_size,
              MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( res_master ),
              transcript, transcript_len,
              MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
              derived->resumption_master_secret,
              md_size );

    if( ret != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_ssl_tls13_key_schedule_stage_application( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    mbedtls_md_type_t const md_type = handshake->ciphersuite_info->mac;
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );
#endif /* MBEDTLS_DEBUG_C */

    /*
     * Compute MasterSecret
     */
    ret = mbedtls_ssl_tls13_evolve_secret( md_type,
                    handshake->tls13_master_secrets.handshake,
                    NULL, 0,
                    handshake->tls13_master_secrets.app );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_evolve_secret", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Master secret",
             handshake->tls13_master_secrets.app, md_size );

    return( 0 );
}

static int ssl_tls13_calc_finished_core( mbedtls_md_type_t md_type,
                                         unsigned char const *base_key,
                                         unsigned char const *transcript,
                                         unsigned char *dst )
{
    const mbedtls_md_info_t* const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );
    unsigned char finished_key[MBEDTLS_MD_MAX_SIZE];
    int ret;

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /* TLS 1.3 Finished message
     *
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     *
     * verify_data =
     *     HMAC( finished_key,
     *            Hash( Handshake Context +
     *                  Certificate*      +
     *                  CertificateVerify* )
     *    )
     *
     * finished_key =
     *    HKDF-Expand-Label( BaseKey, "finished", "", Hash.length )
     */

    ret = mbedtls_ssl_tls13_hkdf_expand_label(
                                 md_type, base_key, md_size,
                                 MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( finished ),
                                 NULL, 0,
                                 finished_key, md_size );
    if( ret != 0 )
        goto exit;

    ret = mbedtls_md_hmac( md_info, finished_key, md_size, transcript, md_size, dst );
    if( ret != 0 )
        goto exit;

exit:

    mbedtls_platform_zeroize( finished_key, sizeof( finished_key ) );
    return( ret );
}

int mbedtls_ssl_tls13_calculate_verify_data( mbedtls_ssl_context* ssl,
                                             unsigned char* dst,
                                             size_t dst_len,
                                             size_t *actual_len,
                                             int from )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    unsigned char transcript[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_len;

    unsigned char *base_key = NULL;
    size_t base_key_len = 0;
    mbedtls_ssl_tls13_handshake_secrets *tls13_hs_secrets =
                                            &ssl->handshake->tls13_hs_secrets;

    mbedtls_md_type_t const md_type = ssl->handshake->ciphersuite_info->mac;
    const mbedtls_md_info_t* const md_info =
                                   mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_ssl_tls13_calculate_verify_data" ) );

    if( from == MBEDTLS_SSL_IS_CLIENT )
    {
        base_key = tls13_hs_secrets->client_handshake_traffic_secret;
        base_key_len = sizeof( tls13_hs_secrets->client_handshake_traffic_secret );
    }
    else
    {
        base_key = tls13_hs_secrets->server_handshake_traffic_secret;
        base_key_len = sizeof( tls13_hs_secrets->server_handshake_traffic_secret );
    }

    if( dst_len < md_size )
    {
        ret = MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
        goto exit;
    }

    ret = mbedtls_ssl_get_handshake_transcript( ssl, md_type,
                                                transcript, sizeof( transcript ),
                                                &transcript_len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_get_handshake_transcript", ret );
        goto exit;
    }
    MBEDTLS_SSL_DEBUG_BUF( 4, "handshake hash", transcript, transcript_len );

    ret = ssl_tls13_calc_finished_core( md_type, base_key, transcript, dst );
    if( ret != 0 )
        goto exit;
    *actual_len = md_size;

    MBEDTLS_SSL_DEBUG_BUF( 3, "verify_data for finished message", dst, md_size );
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_ssl_tls13_calculate_verify_data" ) );

exit:
    /* Erase handshake secrets */
    mbedtls_platform_zeroize( base_key, base_key_len );
    mbedtls_platform_zeroize( transcript, sizeof( transcript ) );
    return( ret );
}

int mbedtls_ssl_tls13_create_psk_binder( mbedtls_ssl_context *ssl,
                               const mbedtls_md_type_t md_type,
                               unsigned char const *psk, size_t psk_len,
                               int psk_type,
                               unsigned char const *transcript,
                               unsigned char *result )
{
    int ret = 0;
    unsigned char binder_key[MBEDTLS_MD_MAX_SIZE];
    unsigned char early_secret[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_info_t const *md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

#if !defined(MBEDTLS_DEBUG_C)
    ssl = NULL; /* make sure we don't use it except for debug */
    ((void) ssl);
#endif

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /*
     *            0
     *            |
     *            v
     *  PSK ->  HKDF-Extract = Early Secret
     *            |
     *            +-----> Derive-Secret(., "ext binder" | "res binder", "")
     *            |                     = binder_key
     *            v
     */

    ret = mbedtls_ssl_tls13_evolve_secret( md_type,
                                           NULL,          /* Old secret */
                                           psk, psk_len,  /* Input      */
                                           early_secret );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_evolve_secret", ret );
        goto exit;
    }

    if( psk_type == MBEDTLS_SSL_TLS1_3_PSK_RESUMPTION )
    {
        ret = mbedtls_ssl_tls13_derive_secret( md_type,
                            early_secret, md_size,
                            MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( res_binder ),
                            NULL, 0, MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                            binder_key, md_size );
        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Derive Early Secret with 'res binder'" ) );
    }
    else
    {
        ret = mbedtls_ssl_tls13_derive_secret( md_type,
                            early_secret, md_size,
                            MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( ext_binder ),
                            NULL, 0, MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                            binder_key, md_size );
        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Derive Early Secret with 'ext binder'" ) );
    }

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_derive_secret", ret );
        goto exit;
    }

    /*
     * The binding_value is computed in the same way as the Finished message
     * but with the BaseKey being the binder_key.
     */

    ret = ssl_tls13_calc_finished_core( md_type, binder_key, transcript, result );
    if( ret != 0 )
        goto exit;

    MBEDTLS_SSL_DEBUG_BUF( 3, "psk binder", result, md_size );

exit:

    mbedtls_platform_zeroize( early_secret, sizeof( early_secret ) );
    mbedtls_platform_zeroize( binder_key,   sizeof( binder_key ) );
    return( ret );
}

int mbedtls_ssl_tls13_populate_transform( mbedtls_ssl_transform *transform,
                                          int endpoint,
                                          int ciphersuite,
                                          mbedtls_ssl_key_set const *traffic_keys,
                                          mbedtls_ssl_context *ssl /* DEBUG ONLY */ )
{
    int ret;
    mbedtls_cipher_info_t const *cipher_info;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    unsigned char const *key_enc;
    unsigned char const *iv_enc;
    unsigned char const *key_dec;
    unsigned char const *iv_dec;

#if !defined(MBEDTLS_DEBUG_C)
    ssl = NULL; /* make sure we don't use it except for those cases */
    (void) ssl;
#endif

    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( ciphersuite );
    if( ciphersuite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ciphersuite info for %d not found",
                                    ciphersuite ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    cipher_info = mbedtls_cipher_info_from_type( ciphersuite_info->cipher );
    if( cipher_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "cipher info for %u not found",
                                    ciphersuite_info->cipher ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    /*
     * Setup cipher contexts in target transform
     */

    if( ( ret = mbedtls_cipher_setup( &transform->cipher_ctx_enc,
                                      cipher_info ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setup", ret );
        return( ret );
    }

    if( ( ret = mbedtls_cipher_setup( &transform->cipher_ctx_dec,
                                      cipher_info ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setup", ret );
        return( ret );
    }

#if defined(MBEDTLS_SSL_SRV_C)
    if( endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        key_enc = traffic_keys->server_write_key;
        key_dec = traffic_keys->client_write_key;
        iv_enc = traffic_keys->server_write_iv;
        iv_dec = traffic_keys->client_write_iv;
    }
    else
#endif /* MBEDTLS_SSL_SRV_C */
#if defined(MBEDTLS_SSL_CLI_C)
    if( endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        key_enc = traffic_keys->client_write_key;
        key_dec = traffic_keys->server_write_key;
        iv_enc = traffic_keys->client_write_iv;
        iv_dec = traffic_keys->server_write_iv;
    }
    else
#endif /* MBEDTLS_SSL_CLI_C */
    {
        /* should not happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    memcpy( transform->iv_enc, iv_enc, traffic_keys->iv_len );
    memcpy( transform->iv_dec, iv_dec, traffic_keys->iv_len );

    if( ( ret = mbedtls_cipher_setkey( &transform->cipher_ctx_enc,
                                       key_enc, cipher_info->key_bitlen,
                                       MBEDTLS_ENCRYPT ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setkey", ret );
        return( ret );
    }

    if( ( ret = mbedtls_cipher_setkey( &transform->cipher_ctx_dec,
                                       key_dec, cipher_info->key_bitlen,
                                       MBEDTLS_DECRYPT ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setkey", ret );
        return( ret );
    }

    /*
     * Setup other fields in SSL transform
     */

    if( ( ciphersuite_info->flags & MBEDTLS_CIPHERSUITE_SHORT_TAG ) != 0 )
        transform->taglen  = 8;
    else
        transform->taglen  = 16;

    transform->ivlen       = traffic_keys->iv_len;
    transform->maclen      = 0;
    transform->fixed_ivlen = transform->ivlen;
    transform->minor_ver   = MBEDTLS_SSL_MINOR_VERSION_4;

    /* We add the true record content type (1 Byte) to the plaintext and
     * then pad to the configured granularity. The mimimum length of the
     * type-extended and padded plaintext is therefore the padding
     * granularity. */
    transform->minlen =
        transform->taglen + MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY;

    return( 0 );
}

int mbedtls_ssl_tls13_key_schedule_stage_early( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_md_type_t md_type;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    if( handshake->ciphersuite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "cipher suite info not found" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    md_type = handshake->ciphersuite_info->mac;

    ret = mbedtls_ssl_tls13_evolve_secret( md_type, NULL, NULL, 0,
                                           handshake->tls13_master_secrets.early );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_evolve_secret", ret );
        return( ret );
    }

    return( 0 );
}

/* mbedtls_ssl_tls13_generate_handshake_keys() generates keys necessary for
 * protecting the handshake messages, as described in Section 7 of TLS 1.3. */
int mbedtls_ssl_tls13_generate_handshake_keys( mbedtls_ssl_context *ssl,
                                               mbedtls_ssl_key_set *traffic_keys )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_md_type_t md_type;
    mbedtls_md_info_t const *md_info;
    size_t md_size;

    unsigned char transcript[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_len;

    mbedtls_cipher_info_t const *cipher_info;
    size_t key_len, iv_len;

    mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info = handshake->ciphersuite_info;
    mbedtls_ssl_tls13_handshake_secrets *tls13_hs_secrets = &handshake->tls13_hs_secrets;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_ssl_tls13_generate_handshake_keys" ) );

    cipher_info = mbedtls_cipher_info_from_type( ciphersuite_info->cipher );
    key_len = cipher_info->key_bitlen >> 3;
    iv_len = cipher_info->iv_size;

    md_type = ciphersuite_info->mac;
    md_info = mbedtls_md_info_from_type( md_type );
    md_size = mbedtls_md_get_size( md_info );

    ret = mbedtls_ssl_get_handshake_transcript( ssl, md_type,
                                                transcript,
                                                sizeof( transcript ),
                                                &transcript_len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
                               "mbedtls_ssl_get_handshake_transcript",
                               ret );
        return( ret );
    }

    ret = mbedtls_ssl_tls13_derive_handshake_secrets( md_type,
                                    handshake->tls13_master_secrets.handshake,
                                    transcript, transcript_len, tls13_hs_secrets );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_derive_handshake_secrets",
                               ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Client handshake traffic secret",
                    tls13_hs_secrets->client_handshake_traffic_secret,
                    md_size );
    MBEDTLS_SSL_DEBUG_BUF( 4, "Server handshake traffic secret",
                    tls13_hs_secrets->server_handshake_traffic_secret,
                    md_size );

    /*
     * Export client handshake traffic secret
     */
    if( ssl->f_export_keys != NULL )
    {
        ssl->f_export_keys( ssl->p_export_keys,
                MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_HANDSHAKE_TRAFFIC_SECRET,
                tls13_hs_secrets->client_handshake_traffic_secret,
                md_size,
                handshake->randbytes + 32,
                handshake->randbytes,
                MBEDTLS_SSL_TLS_PRF_NONE /* TODO: FIX! */ );

        ssl->f_export_keys( ssl->p_export_keys,
                MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_HANDSHAKE_TRAFFIC_SECRET,
                tls13_hs_secrets->server_handshake_traffic_secret,
                md_size,
                handshake->randbytes + 32,
                handshake->randbytes,
                MBEDTLS_SSL_TLS_PRF_NONE /* TODO: FIX! */ );
    }

    ret = mbedtls_ssl_tls13_make_traffic_keys( md_type,
                            tls13_hs_secrets->client_handshake_traffic_secret,
                            tls13_hs_secrets->server_handshake_traffic_secret,
                            md_size, key_len, iv_len, traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_make_traffic_keys", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "client_handshake write_key",
                           traffic_keys->client_write_key,
                           traffic_keys->key_len);

    MBEDTLS_SSL_DEBUG_BUF( 4, "server_handshake write_key",
                           traffic_keys->server_write_key,
                           traffic_keys->key_len);

    MBEDTLS_SSL_DEBUG_BUF( 4, "client_handshake write_iv",
                           traffic_keys->client_write_iv,
                           traffic_keys->iv_len);

    MBEDTLS_SSL_DEBUG_BUF( 4, "server_handshake write_iv",
                           traffic_keys->server_write_iv,
                           traffic_keys->iv_len);

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_ssl_tls13_generate_handshake_keys" ) );

exit:

    return( ret );
}

int mbedtls_ssl_tls13_key_schedule_stage_handshake( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    mbedtls_md_type_t const md_type = handshake->ciphersuite_info->mac;
    size_t ephemeral_len = 0;
    unsigned char ecdhe[MBEDTLS_ECP_MAX_BYTES];
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );
#endif /* MBEDTLS_DEBUG_C */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED)
    /*
     * Compute ECDHE secret used to compute the handshake secret from which
     * client_handshake_traffic_secret and server_handshake_traffic_secret
     * are derived in the handshake secret derivation stage.
     */
    if( mbedtls_ssl_tls13_ephemeral_enabled( ssl ) )
    {
        if( mbedtls_ssl_tls13_named_group_is_ecdhe( handshake->offered_group_id ) )
        {
#if defined(MBEDTLS_ECDH_C)
            ret = mbedtls_ecdh_calc_secret( &handshake->ecdh_ctx,
                                            &ephemeral_len, ecdhe, sizeof( ecdhe ),
                                            ssl->conf->f_rng,
                                            ssl->conf->p_rng );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_calc_secret", ret );
                return( ret );
            }
#endif /* MBEDTLS_ECDH_C */
        }
        else if( mbedtls_ssl_tls13_named_group_is_dhe( handshake->offered_group_id ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "DHE not supported." ) );
            return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
        }
    }
#else
    return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED */

    /*
     * Compute the Handshake Secret
     */
    ret = mbedtls_ssl_tls13_evolve_secret( md_type,
                                           handshake->tls13_master_secrets.early,
                                           ecdhe, ephemeral_len,
                                           handshake->tls13_master_secrets.handshake );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_evolve_secret", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Handshake secret",
                           handshake->tls13_master_secrets.handshake, md_size );

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED)
    mbedtls_platform_zeroize( ecdhe, sizeof( ecdhe ) );
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED */
    return( 0 );
}

/* Generate application traffic keys since any records following a 1-RTT Finished message
 * MUST be encrypted under the application traffic key.
 */
int mbedtls_ssl_tls13_generate_application_keys(
                                        mbedtls_ssl_context *ssl,
                                        mbedtls_ssl_key_set *traffic_keys )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    /* Address at which to store the application secrets */
    mbedtls_ssl_tls13_application_secrets * const app_secrets =
        &ssl->session_negotiate->app_secrets;

    /* Holding the transcript up to and including the ServerFinished */
    unsigned char transcript[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_len;

    /* Variables relating to the hash for the chosen ciphersuite. */
    mbedtls_md_type_t md_type;
    mbedtls_md_info_t const *md_info;
    size_t md_size;

    /* Variables relating to the cipher for the chosen ciphersuite. */
    mbedtls_cipher_info_t const *cipher_info;
    size_t key_len, iv_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> derive application traffic keys" ) );

    /* Extract basic information about hash and ciphersuite */

    cipher_info = mbedtls_cipher_info_from_type(
                                  handshake->ciphersuite_info->cipher );
    key_len = cipher_info->key_bitlen / 8;
    iv_len = cipher_info->iv_size;

    md_type = handshake->ciphersuite_info->mac;
    md_info = mbedtls_md_info_from_type( md_type );
    md_size = mbedtls_md_get_size( md_info );

    /* Compute current handshake transcript. It's the caller's responsiblity
     * to call this at the right time, that is, after the ServerFinished. */

    ret = mbedtls_ssl_get_handshake_transcript( ssl, md_type,
                                      transcript, sizeof( transcript ),
                                      &transcript_len );
    if( ret != 0 )
        goto cleanup;

    /* Compute application secrets from master secret and transcript hash. */

    ret = mbedtls_ssl_tls13_derive_application_secrets( md_type,
                                   handshake->tls13_master_secrets.app,
                                   transcript, transcript_len,
                                   app_secrets );
    /* Erase master secrets */
    mbedtls_platform_zeroize( &ssl->handshake->tls13_master_secrets,
                              sizeof( ssl->handshake->tls13_master_secrets ) );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
                     "mbedtls_ssl_tls13_derive_application_secrets", ret );
        goto cleanup;
    }

    /* Derive first epoch of IV + Key for application traffic. */

    ret = mbedtls_ssl_tls13_make_traffic_keys( md_type,
                             app_secrets->client_application_traffic_secret_N,
                             app_secrets->server_application_traffic_secret_N,
                             md_size, key_len, iv_len, traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_make_traffic_keys", ret );
        goto cleanup;
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Client application traffic secret",
                           app_secrets->client_application_traffic_secret_N,
                           md_size );

    MBEDTLS_SSL_DEBUG_BUF( 4, "Server application traffic secret",
                           app_secrets->server_application_traffic_secret_N,
                           md_size );

    /*
     * Export client/server application traffic secret 0
     */
    if( ssl->f_export_keys != NULL )
    {
        ssl->f_export_keys( ssl->p_export_keys,
                MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET,
                app_secrets->client_application_traffic_secret_N, md_size,
                handshake->randbytes + 32,
                handshake->randbytes,
                MBEDTLS_SSL_TLS_PRF_NONE /* TODO: this should be replaced by
                                            a new constant for TLS 1.3! */ );

        ssl->f_export_keys( ssl->p_export_keys,
                MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET,
                app_secrets->server_application_traffic_secret_N, md_size,
                handshake->randbytes + 32,
                handshake->randbytes,
                MBEDTLS_SSL_TLS_PRF_NONE /* TODO: this should be replaced by
                                            a new constant for TLS 1.3! */ );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "client application_write_key:",
                              traffic_keys->client_write_key, key_len );
    MBEDTLS_SSL_DEBUG_BUF( 4, "server application write key",
                              traffic_keys->server_write_key, key_len );
    MBEDTLS_SSL_DEBUG_BUF( 4, "client application write IV",
                              traffic_keys->client_write_iv, iv_len );
    MBEDTLS_SSL_DEBUG_BUF( 4, "server application write IV",
                              traffic_keys->server_write_iv, iv_len );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= derive application traffic keys" ) );

 cleanup:
    /* randbytes is not used again */
    mbedtls_platform_zeroize( ssl->handshake->randbytes,
                              sizeof( ssl->handshake->randbytes ) );
    mbedtls_platform_zeroize( transcript, sizeof( transcript ) );
    return( ret );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
