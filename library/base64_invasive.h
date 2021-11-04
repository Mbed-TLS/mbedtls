/**
 * \file base_invasive.h
 *
 * \brief Base64 module: interfaces for invasive testing only.
 *
 * The interfaces in this file are intended for testing purposes only.
 * They SHOULD NOT be made available in library integrations except when
 * building the library for testing.
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
#ifndef MBEDTLS_BASE64_INVASIVE_H
#define MBEDTLS_BASE64_INVASIVE_H

#include "common.h"

#if defined(MBEDTLS_TEST_HOOKS)
/* Return 0xff if low <= c <= high, 0 otherwise.
 *
 * Constant flow with respect to c.
 */
unsigned char mbedtls_base64_mask_of_range( unsigned char low,
                                            unsigned char high,
                                            unsigned char c );

/* Given a value in the range 0..63, return the corresponding Base64 digit.
 *
 * Operates in constant time (no branches or memory access depending on val).
 */
unsigned char mbedtls_base64_enc_char( unsigned char val );

/* Given a Base64 digit, return its value.
 * If c is not a Base64 digit ('A'..'Z', 'a'..'z', '0'..'9', '+' or '/'),
 * return -1.
 *
 * Operates in constant time (no branches or memory access depending on c).
 */
signed char mbedtls_base64_dec_value( unsigned char c );
#endif /* MBEDTLS_TEST_HOOKS */

#endif /* MBEDTLS_BASE64_INVASIVE_H */
