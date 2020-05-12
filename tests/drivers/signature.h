/*
 * Test driver with both transparent and opaque signature functions
 */
/*  Copyright (C) 2020, ARM Limited, All Rights Reserved
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
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_PSA_CRYPTO_TEST_DRIVERS_SIGNATURE_H
#define MBEDTLS_PSA_CRYPTO_TEST_DRIVERS_SIGNATURE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <psa/crypto_driver.h>

extern void *test_driver_forced_output;
extern size_t test_driver_forced_output_length;

extern psa_status_t test_transparent_signature_sign_hash_status;
extern unsigned long test_transparent_signature_sign_hash_hit;

#endif /* MBEDTLS_PSA_CRYPTO_TEST_DRIVERS_SIGNATURE_H */
