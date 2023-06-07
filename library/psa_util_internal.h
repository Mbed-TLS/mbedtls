/**
 * \file psa_util_internal.h
 *
 * \brief Internal utility functions for use of PSA Crypto.
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

#ifndef MBEDTLS_PSA_UTIL_INTERNAL_H
#define MBEDTLS_PSA_UTIL_INTERNAL_H

/* Include the public header so that users only need one include. */
#include "mbedtls/psa_util.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

/*************************************************************************
 * FFDH
 ************************************************************************/

#define MBEDTLS_PSA_MAX_FFDH_PUBKEY_LENGTH \
    PSA_KEY_EXPORT_FFDH_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_FFDH_MAX_KEY_BITS)

/*************************************************************************
 * ECC
 ************************************************************************/

#define MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH \
    PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)

#define MBEDTLS_PSA_MAX_EC_KEY_PAIR_LENGTH \
    PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)

#endif /* MBEDTLS_PSA_CRYPTO_C */
#endif /* MBEDTLS_PSA_UTIL_INTERNAL_H */
