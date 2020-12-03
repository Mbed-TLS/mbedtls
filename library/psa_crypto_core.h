/*
 *  PSA crypto core internal interfaces
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

#ifndef PSA_CRYPTO_CORE_H
#define PSA_CRYPTO_CORE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"

/** The data structure representing a key slot, containing key material
 * and metadata for one key.
 */
typedef struct
{
    psa_core_key_attributes_t attr;

    /*
     * Number of locks on the key slot held by the library.
     *
     * This counter is incremented by one each time a library function
     * retrieves through one of the dedicated internal API a pointer to the
     * key slot.
     *
     * This counter is decremented by one each time a library function stops
     * accessing the key slot and states it by calling the
     * psa_unlock_key_slot() API.
     *
     * This counter is used to prevent resetting the key slot while the library
     * may access it. For example, such control is needed in the following
     * scenarios:
     * . In case of key slot starvation, all key slots contain the description
     *   of a key, and the library asks for the description of a persistent
     *   key not present in the key slots, the key slots currently accessed by
     *   the library cannot be reclaimed to free a key slot to load the
     *   persistent key.
     * . In case of a multi-threaded application where one thread asks to close
     *   or purge or destroy a key while it is in used by the library through
     *   another thread.
     */
    size_t lock_count;

    union
    {
        /* Dynamically allocated key data buffer.
         * Format as specified in psa_export_key(). */
        struct key_data
        {
            uint8_t *data;
            size_t bytes;
        } key;
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
        /* Any key type in a secure element */
        struct se
        {
            psa_key_slot_number_t slot_number;
        } se;
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
    } data;
} psa_key_slot_t;

/* A mask of key attribute flags used only internally.
 * Currently there aren't any. */
#define PSA_KA_MASK_INTERNAL_ONLY (     \
        0 )

/** Test whether a key slot is occupied.
 *
 * A key slot is occupied iff the key type is nonzero. This works because
 * no valid key can have 0 as its key type.
 *
 * \param[in] slot      The key slot to test.
 *
 * \return 1 if the slot is occupied, 0 otherwise.
 */
static inline int psa_is_key_slot_occupied( const psa_key_slot_t *slot )
{
    return( slot->attr.type != 0 );
}

/** Test whether a key slot is locked.
 *
 * A key slot is locked iff its lock counter is strictly greater than 0.
 *
 * \param[in] slot  The key slot to test.
 *
 * \return 1 if the slot is locked, 0 otherwise.
 */
static inline int psa_is_key_slot_locked( const psa_key_slot_t *slot )
{
    return( slot->lock_count > 0 );
}

/** Retrieve flags from psa_key_slot_t::attr::core::flags.
 *
 * \param[in] slot      The key slot to query.
 * \param mask          The mask of bits to extract.
 *
 * \return The key attribute flags in the given slot,
 *         bitwise-anded with \p mask.
 */
static inline uint16_t psa_key_slot_get_flags( const psa_key_slot_t *slot,
                                               uint16_t mask )
{
    return( slot->attr.flags & mask );
}

/** Set flags in psa_key_slot_t::attr::core::flags.
 *
 * \param[in,out] slot  The key slot to modify.
 * \param mask          The mask of bits to modify.
 * \param value         The new value of the selected bits.
 */
static inline void psa_key_slot_set_flags( psa_key_slot_t *slot,
                                           uint16_t mask,
                                           uint16_t value )
{
    slot->attr.flags = ( ( ~mask & slot->attr.flags ) |
                              ( mask & value ) );
}

/** Turn on flags in psa_key_slot_t::attr::core::flags.
 *
 * \param[in,out] slot  The key slot to modify.
 * \param mask          The mask of bits to set.
 */
static inline void psa_key_slot_set_bits_in_flags( psa_key_slot_t *slot,
                                                   uint16_t mask )
{
    slot->attr.flags |= mask;
}

/** Turn off flags in psa_key_slot_t::attr::core::flags.
 *
 * \param[in,out] slot  The key slot to modify.
 * \param mask          The mask of bits to clear.
 */
static inline void psa_key_slot_clear_bits( psa_key_slot_t *slot,
                                            uint16_t mask )
{
    slot->attr.flags &= ~mask;
}

/** Completely wipe a slot in memory, including its policy.
 *
 * Persistent storage is not affected.
 *
 * \param[in,out] slot  The key slot to wipe.
 *
 * \retval #PSA_SUCCESS
 *         Success. This includes the case of a key slot that was
 *         already fully wiped.
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 */
psa_status_t psa_wipe_key_slot( psa_key_slot_t *slot );

/** Copy key data (in export format) into an empty key slot.
 *
 * This function assumes that the slot does not contain
 * any key material yet. On failure, the slot content is unchanged.
 *
 * \param[in,out] slot          Key slot to copy the key into.
 * \param[in] data              Buffer containing the key material.
 * \param data_length           Size of the key buffer.
 *
 * \retval #PSA_SUCCESS
 *         The key has been copied successfully.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *         Not enough memory was available for allocation of the
 *         copy buffer.
 * \retval #PSA_ERROR_ALREADY_EXISTS
 *         There was other key material already present in the slot.
 */
psa_status_t psa_copy_key_material_into_slot( psa_key_slot_t *slot,
                                              const uint8_t *data,
                                              size_t data_length );

/** Convert an mbed TLS error code to a PSA error code
 *
 * \note This function is provided solely for the convenience of
 *       Mbed TLS and may be removed at any time without notice.
 *
 * \param ret           An mbed TLS-thrown error code
 *
 * \return              The corresponding PSA error code
 */
psa_status_t mbedtls_to_psa_error( int ret );

#endif /* PSA_CRYPTO_CORE_H */
