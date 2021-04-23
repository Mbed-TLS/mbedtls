/*
 *  Test applicaiton access to private library components (struct members).
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

#include <stdio.h>
#include <stdlib.h>

#include "mbedtls/md.h"
#include "psa/crypto.h"
#include "psa/crypto_types.h"
#include "psa/crypto_struct.h"

int main( void )
{
    /* using static inline function */
    psa_key_attributes_t local_crypto_struct = psa_key_attributes_init();
    mbedtls_svc_key_id_t id =
        mbedtls_svc_key_id_make( 0, 0 );
    psa_set_key_id(&local_crypto_struct, id);

    /* accessing private member using MBEDTLS_PRIVATE() macro */
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init( &md_ctx );
    const char* t = "A";
    md_ctx.MBEDTLS_PRIVATE(md_ctx) = (void*)t;

    /* accessing private member without MBEDTLS_PRIVATE() macro - compilation wil fail */
    // md_ctx.md_ctx = t;

    exit( 0 );
}
