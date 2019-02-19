/**
 * \file psa_crypto_storage_backend.h
 *
 * \brief PSA cryptography module: Mbed TLS key storage backend
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

#ifndef PSA_CRYPTO_STORAGE_BACKEND_H
#define PSA_CRYPTO_STORAGE_BACKEND_H

#ifdef __cplusplus
extern "C" {
#endif

/* Include the Mbed TLS configuration file, the way Mbed TLS does it
 * in each of its header files. */
#if defined(MBEDTLS_CONFIG_FILE)
#include MBEDTLS_CONFIG_FILE
#else
#include "mbedtls/config.h"
#endif

#include "psa/crypto.h"
#include "psa_crypto_storage.h"
#include <stdint.h>

/**
 * \brief Load persistent data for the given key slot number.
 *
 * This function reads data from a storage backend and returns the data in a
 * buffer.
 *
 * \param key               Persistent identifier of the key to be loaded. This
 *                          should be an occupied storage location.
 * \param[out] data         Buffer where the data is to be written.
 * \param data_size         Size of the \c data buffer in bytes.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_STORAGE_FAILURE
 * \retval PSA_ERROR_DOES_NOT_EXIST
 */
psa_status_t psa_crypto_storage_load( const psa_key_file_id_t key, uint8_t *data,
                                      size_t data_size );

/**
 * \brief Store persistent data for the given key slot number.
 *
 * This function stores the given data buffer to a persistent storage.
 *
 * \param key           Persistent identifier of the key to be stored. This
 *                      should be an unoccupied storage location.
 * \param[in] data      Buffer containing the data to be stored.
 * \param data_length   The number of bytes
 *                      that make up the data.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_INSUFFICIENT_STORAGE
 * \retval PSA_ERROR_STORAGE_FAILURE
 * \retval PSA_ERROR_ALREADY_EXISTS
 */
psa_status_t psa_crypto_storage_store( const psa_key_file_id_t key,
                                       const uint8_t *data,
                                       size_t data_length );

/**
 * \brief Checks if persistent data is stored for the given key slot number
 *
 * This function checks if any key data or metadata exists for the key slot in
 * the persistent storage.
 *
 * \param key           Persistent identifier to check.
 *
 * \retval 0
 *         No persistent data present for slot number
 * \retval 1
 *         Persistent data present for slot number
 */
int psa_is_key_present_in_storage( const psa_key_file_id_t key );

/**
 * \brief Get data length for given key slot number.
 *
 * \param key               Persistent identifier whose stored data length
 *                          is to be obtained.
 * \param[out] data_length  The number of bytes that make up the data.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_STORAGE_FAILURE
 */
psa_status_t psa_crypto_storage_get_data_length( const psa_key_file_id_t key,
                                                 size_t *data_length );


#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_STORAGE_H */
