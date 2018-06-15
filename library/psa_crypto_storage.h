/**
 * \file psa_crypto_storage.h
 *
 * \brief PSA cryptography module: Mbed TLS key storage
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

#ifndef PSA_CRYPTO_STORAGE_H
#define PSA_CRYPTO_STORAGE_H

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
#include <stdint.h>

/* Limit the maximum key size to 30kB (just in case someone tries to
 * inadvertently store an obscene amount of data) */
#define PSA_CRYPTO_MAX_STORAGE_SIZE ( 30 * 1024 )

/**
 * \brief Format key data and metadata and save to a location for given key
 *        slot.
 *
 * This function formats the key data and metadata and saves it to a
 * persistent storage backend. The storage location corresponding to the
 * key slot must be empty, otherwise this function will fail. This function
 * should be called after psa_import_key_into_slot() to ensure the
 * persistent key is not saved into a storage location corresponding to an
 * already occupied non-persistent key, as well as validating the key data.
 *
 *
 * \param key           Slot number of the key to be stored. This must be a
 *                      valid slot for a key of the chosen type. This should be
 *                      an occupied key slot with an unoccupied corresponding
 *                      storage location.
 * \param type          Key type (a \c PSA_KEY_TYPE_XXX value).
 * \param[in] policy    The key policy to save.
 * \param[in] data      Buffer containing the key data.
 * \param data_length   The number of bytes that make up the key data.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_INSUFFICIENT_STORAGE
 * \retval PSA_ERROR_STORAGE_FAILURE
 */
psa_status_t psa_save_persistent_key( const psa_key_slot_t key,
                                      const psa_key_type_t type,
                                      const psa_key_policy_t *policy,
                                      const uint8_t *data,
                                      const size_t data_length );

/**
 * \brief Parses key data and metadata and load persistent key for given
 * key slot number.
 *
 * This function reads from a storage backend, parses the key data and
 * metadata and writes them to the appropriate output parameters.
 *
 * Note: This function allocates a buffer and returns a pointer to it through
 * the data parameter. psa_free_persistent_key_data() must be called after
 * this function to zeroize and free this buffer, regardless of whether this
 * function succeeds or fails.
 *
 * \param key               Slot number whose content is to be loaded. This
 *                          must be an unoccupied key slot with an occupied
 *                          corresponding storage location. The key slot
 *                          lifetime must be set to persistent.
 * \param[out] type         On success, the key type (a \c PSA_KEY_TYPE_XXX
 *                          value).
 * \param[out] policy       On success, the key's policy.
 * \param[out] data         Pointer to an allocated key data buffer on return.
 * \param[out] data_length  The number of bytes that make up the key data.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_STORAGE_FAILURE
 */
psa_status_t psa_load_persistent_key( psa_key_slot_t key,
                                      psa_key_type_t *type,
                                      psa_key_policy_t *policy,
                                      uint8_t **data,
                                      size_t *data_length );

/**
 * \brief Remove persistent data for the given key slot number.
 *
 * \param key           Slot number whose content is to be removed
 *                      from persistent storage.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_STORAGE_FAILURE
 */
psa_status_t psa_destroy_persistent_key( const psa_key_slot_t key );

/**
 * \brief Zeroizes and frees the given buffer.
 *
 * This function must be called at some point after psa_load_persistent_key()
 * to zeroize and free the memory allocated to the buffer in that function.
 *
 * \param key_data        Buffer for the key data.
 * \param key_data_length Size of the key data buffer.
 *
 */
void psa_free_persistent_key_data( uint8_t *key_data, size_t key_data_length );

/**
 * \brief Formats key data and metadata for persistent storage
 *
 * \param[in] data          Buffer for the key data.
 * \param data_length       Length of the key data buffer.
 * \param type              Key type (a \c PSA_KEY_TYPE_XXX value).
 * \param policy            The key policy.
 * \param[out] storage_data Output buffer for the formatted data.
 *
 */
void psa_format_key_data_for_storage( const uint8_t *data,
                                      const size_t data_length,
                                      const psa_key_type_t type,
                                      const psa_key_policy_t *policy,
                                      uint8_t *storage_data );

/**
 * \brief Parses persistent storage data into key data and metadata
 *
 * \param[in] storage_data     Buffer for the storage data.
 * \param storage_data_length  Length of the storage data buffer
 * \param[out] key_data        On output, pointer to a newly allocated buffer
 *                             containing the key data. This must be freed
 *                             using psa_free_persistent_key_data()
 * \param[out] key_data_length Length of the key data buffer
 * \param[out] type            Key type (a \c PSA_KEY_TYPE_XXX value).
 * \param[out] policy          The key policy.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_INSUFFICIENT_STORAGE
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_STORAGE_FAILURE
 */
psa_status_t psa_parse_key_data_from_storage( const uint8_t *storage_data,
                                              size_t storage_data_length,
                                              uint8_t **key_data,
                                              size_t *key_data_length,
                                              psa_key_type_t *type,
                                              psa_key_policy_t *policy );

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_STORAGE_H */
