/*
 * Test driver for MAC driver entry points.
 */
/*  Copyright The Mbed TLS Contributors
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

#ifndef PSA_CRYPTO_TEST_DRIVERS_ENTROPY_H
#define PSA_CRYPTO_TEST_DRIVERS_ENTROPY_H

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_ENTROPY_PSA) && defined(PSA_CRYPTO_DRIVER_TEST)
#include <psa/crypto_driver_common.h>

void mbedtls_test_set_insecure_psa_crypto_entropy( size_t entropy, int calls );


#endif /* MBEDTLS_ENTROPY_PSA && PSA_CRYPTO_DRIVER_TEST */
#endif /* PSA_CRYPTO_TEST_DRIVERS_ENTROPY_H */
