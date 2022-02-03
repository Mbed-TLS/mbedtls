/** \file psa_driver_facilities.c
 *
 * \brief Sanity checks for basic psa/crypto_driver.h functionality.
 */

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

/* Only include <psa/crypto_driver.h>. Do not include other headers, so that
 * being able to compile the file that implements the functions declared
 * here ensures that drivers can indeed include only this header without
 * depending on other Mbed TLS headers. */
#include <psa/crypto_driver.h>

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS)

int mbedtls_test_psa_crypto_driver_basics( void )

#endif  /* MBEDTLS_PSA_CRYPTO_DRIVERS */
