/*
 *  TLS 1.3 functionality shared between client and server
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
 *
 *  This file is part of mbed TLS ( https://tls.mbed.org )
 */

#include "common.h"

#if defined(MBEDTLS_SSL_TLS_C)

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#include <string.h>
#include <mbedtls/debug.h>
#include "ssl_misc.h"

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
int mbedtls_ssl_write_signature_algorithms_ext( mbedtls_ssl_context *ssl,
                                        unsigned char* buf,
                                        unsigned char* end,
                                        size_t* olen )
{
    unsigned char *p = buf;
    size_t sig_alg_len = 0;
    const int *sig_alg;
    unsigned char *sig_alg_list = buf + 6;

    *olen = 0;

    /* Skip the extension on the client if all allowed key exchanges
     * are PSK-based. */
#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
        !mbedtls_ssl_conf_tls13_some_ecdhe_enabled( ssl ) )
    {
        return( 0 );
    }
#endif /* MBEDTLS_SSL_CLI_C */

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "adding signature_algorithms extension" ) );

    /*
     * Determine length of the signature scheme list
     */
    for ( sig_alg = ssl->conf->tls13_sig_algs;
          *sig_alg != MBEDTLS_TLS13_SIG_NONE; sig_alg++ )
    {
        sig_alg_len += 2;
    }

    if( sig_alg_len == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "No signature algorithms defined." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( end < p || (size_t)( end - p ) < sig_alg_len + 6 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    /*
     * Write signature schemes
     */

    for( sig_alg = ssl->conf->tls13_sig_algs;
         *sig_alg != MBEDTLS_TLS13_SIG_NONE; sig_alg++ )
    {
        *sig_alg_list++ = (unsigned char)( ( *sig_alg >> 8 ) & 0xFF );
        *sig_alg_list++ = (unsigned char)( ( *sig_alg ) & 0xFF );
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "signature scheme [%x]", (unsigned int) (*sig_alg) ) );
    }

    /*
     * Write extension header
     */

    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SIG_ALG >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SIG_ALG ) & 0xFF );

    *p++ = (unsigned char)( ( ( sig_alg_len + 2 ) >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ( sig_alg_len + 2 ) ) & 0xFF );

    *p++ = (unsigned char)( ( sig_alg_len >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( sig_alg_len ) & 0xFF );

    *olen = 6 + sig_alg_len;

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SIGNATURE_ALGORITHM;
    return( 0 );
}

int mbedtls_ssl_parse_signature_algorithms_ext( mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        size_t buf_len )
{
    size_t sig_alg_list_size; /* size of receive signature algorithms list */
    const unsigned char *p; /* pointer to individual signature algorithm */
    const unsigned char *end = buf + buf_len; /* end of buffer */
    const int *sig_alg; /* iterate through configured signature schemes */
    int signature_scheme; /* store received signature algorithm scheme */
    uint32_t common_idx = 0; /* iterate through received_signature_schemes_list */

    if( buf_len < 2 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad signature_algorithms extension" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    sig_alg_list_size = ( ( size_t) buf[0] << 8 ) | ( (size_t) buf[1] );
    if( sig_alg_list_size + 2 != buf_len ||
        sig_alg_list_size % 2 != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad signature_algorithms extension" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }
    memset( ssl->handshake->received_signature_schemes_list,
        0, sizeof( ssl->handshake->received_signature_schemes_list ) );

    for( p = buf + 2; p < end && common_idx + 1 < MBEDTLS_SIGNATURE_SCHEMES_SIZE; p += 2 )
    {
        signature_scheme = ( (int) p[0] << 8 ) | ( ( int ) p[1] );

        MBEDTLS_SSL_DEBUG_MSG( 4, ( "received signature algorithm: 0x%x", (unsigned int ) signature_scheme ) );

        for( sig_alg = ssl->conf->tls13_sig_algs;
             *sig_alg != MBEDTLS_TLS13_SIG_NONE; sig_alg++ )
        {
            if( *sig_alg == signature_scheme )
            {
                ssl->handshake->received_signature_schemes_list[common_idx] = signature_scheme;
                common_idx++;
                break;
            }
        }
    }

    if( common_idx == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "no signature algorithm in common" ) );
        /*
            TODO: SSL_PEND_FATAL_ALERT and relative variables are defined in tls13-prototype.
                It should be re-considered and merge in furture.
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                              MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        */
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    ssl->handshake->received_signature_schemes_list[common_idx] =
        MBEDTLS_TLS13_SIG_NONE;

    return( 0 );
}

void mbedtls_ssl_conf_signature_algorithms( mbedtls_ssl_config *conf,
                     const int* sig_algs )
{
    /* TODO: Add available algorithm check */
    conf->tls13_sig_algs = sig_algs;
}

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */


#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#endif /* MBEDTLS_SSL_CLI_C */
