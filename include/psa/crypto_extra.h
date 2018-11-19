/**
 * \file psa/crypto_extra.h
 *
 * \brief PSA cryptography module: Mbed TLS vendor extensions
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file is reserved for vendor-specific definitions.
 */
/*
 *  Copyright (C) 2018, ARM Limited, All Rights Reserved
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

#ifndef PSA_CRYPTO_EXTRA_H
#define PSA_CRYPTO_EXTRA_H

#ifdef __cplusplus
extern "C" {
#endif

/* UID for secure storage seed */
#define MBED_RANDOM_SEED_ITS_UID 0xFFFFFF52

/**
 * \brief Library deinitialization.
 *
 * This function clears all data associated with the PSA layer,
 * including the whole key store.
 *
 * This is an Mbed TLS extension.
 */
void mbedtls_psa_crypto_free( void );


#if ( defined(MBEDTLS_ENTROPY_NV_SEED) && defined(MBEDTLS_PSA_HAS_ITS_IO) )
/**
 * \brief Inject initial entropy seed into persistent storage for random capabilities.
 *
 * \warning This function **can** fail! Callers MUST check the return status.
 *
 * \note    To use this function both mbedtls_nv_seed_read and mbedtls_nv_seed_write
 *          must be defined.
 *
 * \param seed[in]            Buffer storing the seed value to inject.
 * \param seed_size[in]       Size of the \p seed buffer. The minimum size of the seed is MBEDTLS_ENTROPY_MIN_PLATFORM
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 * \retval #PSA_ERROR_STORAGE_FAILURE
 * \retval #PSA_ERROR_NOT_PERMITTED
 * \retval #PSA_ERROR_BAD_STATE
 */
psa_status_t mbedtls_psa_inject_entropy(const unsigned char *seed,
                                        size_t seed_size);

#endif

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_EXTRA_H */
