/*
 *  TLS 1.3 server-side functions
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

#include "common.h"

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

#if defined(MBEDTLS_SSL_SRV_C)

#include "mbedtls/debug.h"

#include "ssl_misc.h"
#include "ssl_debug_helpers_generated.h"

int mbedtls_ssl_tls13_handshake_server_step( mbedtls_ssl_context *ssl )
{
    ((void) ssl);
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "tls13 server state: %s(%d)",
                                mbedtls_ssl_states_str( ssl->state ),
                                ssl->state ) );

    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}

#endif /* MBEDTLS_SSL_SRV_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
