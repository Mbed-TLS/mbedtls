/*
 *  TLS 1.3 client-side functions
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

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#if defined(MBEDTLS_SSL_CLI_C)

#include "ssl_misc.h"
#include <mbedtls/debug.h>

static int ssl_client_hello_process( mbedtls_ssl_context* ssl );

int mbedtls_ssl_handshake_client_step_tls1_3( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    if( ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER || ssl->handshake == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Handshake completed but ssl->handshake is NULL.\n" ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "client state: %d", ssl->state ) );

    switch( ssl->state )
    {
        case MBEDTLS_SSL_HELLO_REQUEST:
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );
            break;

        case MBEDTLS_SSL_CLIENT_HELLO:
            ret = ssl_client_hello_process( ssl );
            break;

        case MBEDTLS_SSL_SERVER_HELLO:
            // Stop here : we haven't finished whole flow
            ret=MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );
            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ret );
}

static int ssl_client_hello_process( mbedtls_ssl_context* ssl )
{
    int ret = 0;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write client hello" ) );

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_HELLO );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write client hello" ) );
    /* client_hello_process haven't finished */
    ret=MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    return ret;
}

#endif /* MBEDTLS_SSL_CLI_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
