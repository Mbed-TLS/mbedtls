/* Ad hoc report on included headers. */
/*
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

#include <psa/crypto.h>
#include <mbedtls/platform.h>

int main(void)
{

    /* Which PSA platform header? */
#if defined(PSA_CRYPTO_PLATFORM_H)
    mbedtls_printf("PSA_CRYPTO_PLATFORM_H\n");
#endif
#if defined(PSA_CRYPTO_PLATFORM_ALT_H)
    mbedtls_printf("PSA_CRYPTO_PLATFORM_ALT_H\n");
#endif

    /* Which PSA struct header? */
#if defined(PSA_CRYPTO_STRUCT_H)
    mbedtls_printf("PSA_CRYPTO_STRUCT_H\n");
#endif
#if defined(PSA_CRYPTO_STRUCT_ALT_H)
    mbedtls_printf("PSA_CRYPTO_STRUCT_ALT_H\n");
#endif

}
