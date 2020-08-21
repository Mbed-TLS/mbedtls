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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#include "mbedtls/hkdf.h"
#include "ssl_tls13_keys.h"

#include <stdint.h>
#include <string.h>

struct mbedtls_ssl_tls1_3_labels_struct const mbedtls_ssl_tls1_3_labels =
{
    /* This seems to work in C, despite the string literal being one
     * character too long due to the 0-termination. */
    .finished     = "finished",
    .resumption   = "resumption",
    .traffic_upd  = "traffic upd",
    .export       = "exporter",
    .key          = "key",
    .iv           = "iv",
    .sn           = "sn",
    .c_hs_traffic = "c hs traffic",
    .c_ap_traffic = "c ap traffic",
    .c_e_traffic  = "c e traffic",
    .s_hs_traffic = "s hs traffic",
    .s_ap_traffic = "s ap traffic",
    .s_e_traffic  = "s e traffic",
    .exp_master   = "exp master",
    .res_master   = "res master",
    .ext_binder   = "ext binder",
    .res_binder   = "res binder",
    .derived      = "derived"
};

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
 * - (label, llen): label + label length, without "tls13 " prefix
 *                  The label length MUST be
 *                  <= MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN
 *                  It is the caller's responsiblity to ensure this.
 * - (ctx, clen): context + context length
 *                The context length MUST be
 *                <= MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN
 *                It is the caller's responsiblity to ensure this.
 * - dst: Target buffer for HkdfLabel structure,
 *        This MUST be a writable buffer of size
 *        at least SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN Bytes.
 * - dlen: Pointer at which to store the actual length of
 *         the HkdfLabel structure on success.
 */

#define SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN \
    (   2                  /* expansion length           */ \
      + 1                  /* label length               */ \
      + MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN       \
      + 1                  /* context length             */ \
      + MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )

static void ssl_tls1_3_hkdf_encode_label(
                            size_t desired_length,
                            const unsigned char *label, size_t llen,
                            const unsigned char *ctx, size_t clen,
                            unsigned char *dst, size_t *dlen )
{
    const char label_prefix[6] = { 't', 'l', 's', '1', '3', ' ' };
    size_t total_label_len = sizeof( label_prefix ) + llen;
    size_t total_hkdf_lbl_len =
          2                  /* length of expanded key material */
        + 1                  /* label length                    */
        + total_label_len    /* actual label, incl. prefix      */
        + 1                  /* context length                  */
        + clen;              /* actual context                  */

    unsigned char *p = dst;

    /* Add total length. */
    *p++ = 0;
    *p++ = (unsigned char)( ( desired_length >> 0 ) & 0xFF );

    /* Add label incl. prefix */
    *p++ = (unsigned char)( total_label_len & 0xFF );
    memcpy( p, label_prefix, sizeof(label_prefix) );
    p += sizeof(label_prefix);
    memcpy( p, label, llen );
    p += llen;

    /* Add context value */
    *p++ = (unsigned char)( clen & 0xFF );
    if( ctx != NULL )
        memcpy( p, ctx, clen );

    /* Return total length to the caller.  */
    *dlen = total_hkdf_lbl_len;
}

int mbedtls_ssl_tls1_3_hkdf_expand_label(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *secret, size_t slen,
                     const unsigned char *label, size_t llen,
                     const unsigned char *ctx, size_t clen,
                     unsigned char *buf, size_t blen )
{
    const mbedtls_md_info_t *md;
    unsigned char hkdf_label[ SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN ];
    size_t hkdf_label_len;

    if( llen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN )
    {
        /* Should never happen since this is an internal
         * function, and we know statically which labels
         * are allowed. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( clen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )
    {
        /* Should not happen, as above. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( blen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN )
    {
        /* Should not happen, as above. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    md = mbedtls_md_info_from_type( hash_alg );
    if( md == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    ssl_tls1_3_hkdf_encode_label( blen,
                                  label, llen,
                                  ctx, clen,
                                  hkdf_label,
                                  &hkdf_label_len );

    return( mbedtls_hkdf_expand( md,
                                 secret, slen,
                                 hkdf_label, hkdf_label_len,
                                 buf, blen ) );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
