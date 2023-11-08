/**
 * \file base64_internal.h
 *
 * \brief RFC 1521 base64 encoding/decoding: interfaces for invasive testing
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

#ifndef MBEDTLS_BASE64_INTERNAL
#define MBEDTLS_BASE64_INTERNAL

#include "common.h"

#if defined(MBEDTLS_TEST_HOOKS)

/** Given a value in the range 0..63, return the corresponding Base64 digit.
 *
 * The implementation assumes that letters are consecutive (e.g. ASCII
 * but not EBCDIC).
 *
 * \param value     A value in the range 0..63.
 *
 * \return          A base64 digit converted from \p value.
 */
unsigned char mbedtls_ct_base64_enc_char(unsigned char value);

/** Given a Base64 digit, return its value.
 *
 * If c is not a Base64 digit ('A'..'Z', 'a'..'z', '0'..'9', '+' or '/'),
 * return -1.
 *
 * The implementation assumes that letters are consecutive (e.g. ASCII
 * but not EBCDIC).
 *
 * \param c     A base64 digit.
 *
 * \return      The value of the base64 digit \p c.
 */
signed char mbedtls_ct_base64_dec_value(unsigned char c);

#endif /* MBEDTLS_TEST_HOOKS */

#endif /* MBEDTLS_BASE64_INTERNAL */
