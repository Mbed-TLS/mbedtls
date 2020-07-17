/*
 *  Functions to delegate cryptographic operations to an available
 *  and appropriate accelerator.
 *  Warning: auto-generated file.
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

#include "psa_crypto_core.h"
#include "psa_crypto_driver_wrappers.h"

/* Include test driver definition when running tests */
#if defined(MBEDTLS_TEST_HOOKS)
#undef MBEDTLS_PSA_CRYPTO_DRIVER_PRESENT
#define MBEDTLS_PSA_CRYPTO_DRIVER_PRESENT
#undef MBEDTLS_PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#define MBEDTLS_PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#include "drivers/test_driver.h"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
#undef MBEDTLS_PSA_CRYPTO_DRIVER_PRESENT
#define MBEDTLS_PSA_CRYPTO_DRIVER_PRESENT
#include "psa_crypto_se.h"
#endif

/* Include driver definition file for each registered driver */

/* Start delegation functions */
psa_status_t psa_driver_wrapper_sign_hash( psa_key_slot_t *slot,
                                           psa_algorithm_t alg,
                                           const uint8_t *hash,
                                           size_t hash_length,
                                           uint8_t *signature,
                                           size_t signature_size,
                                           size_t *signature_length )
{
#if defined(MBEDTLS_PSA_CRYPTO_DRIVER_PRESENT)
    /* Try dynamically-registered SE interface first */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if( psa_get_se_driver( slot->attr.lifetime, &drv, &drv_context ) )
    {
        if( drv->asymmetric == NULL ||
            drv->asymmetric->p_sign == NULL )
        {
            /* Key is defined in SE, but we have no way to exercise it */
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        return( drv->asymmetric->p_sign( drv_context,
                                         slot->data.se.slot_number,
                                         alg,
                                         hash, hash_length,
                                         signature, signature_size,
                                         signature_length ) );
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    /* Then try accelerator API */
#if defined(MBEDTLS_PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime);
    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */
#if defined(MBEDTLS_TEST_HOOKS)
            status = test_transparent_signature_sign_hash( &attributes,
                                                           slot->data.key.data,
                                                           slot->data.key.bytes,
                                                           alg,
                                                           hash,
                                                           hash_length,
                                                           signature,
                                                           signature_size,
                                                           signature_length );
            /* Declared with fallback == true */
            if( status != PSA_ERROR_NOT_SUPPORTED )
                return status;
#endif /* MBEDTLS_TEST_HOOKS */
            /* Fell through, meaning no accelerator supports this operation */
            return PSA_ERROR_NOT_SUPPORTED;
        /* Add cases for opaque driver here */
#if defined(MBEDTLS_TEST_HOOKS)
        case MBEDTLS_PSA_CRYPTO_TEST_DRIVER_LIFETIME:
            return( test_opaque_signature_sign_hash( &attributes,
                                                     slot->data.key.data,
                                                     slot->data.key.bytes,
                                                     alg,
                                                     hash,
                                                     hash_length,
                                                     signature,
                                                     signature_size,
                                                     signature_length ) );
#endif /* MBEDTLS_TEST_HOOKS */
        default:
            /* Key is declared with a lifetime not known to us */
            return status;
    }
#else /* MBEDTLS_PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
    return PSA_ERROR_NOT_SUPPORTED;
#endif /* MBEDTLS_PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
#else /* MBEDTLS_PSA_CRYPTO_DRIVER_PRESENT */
    (void)slot;
    (void)alg;
    (void)hash;
    (void)hash_length;
    (void)signature;
    (void)signature_size;
    (void)signature_length;

    return PSA_ERROR_NOT_SUPPORTED;
#endif /* MBEDTLS_PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_verify_hash( psa_key_slot_t *slot,
                                             psa_algorithm_t alg,
                                             const uint8_t *hash,
                                             size_t hash_length,
                                             const uint8_t *signature,
                                             size_t signature_length )
{
#if defined(MBEDTLS_PSA_CRYPTO_DRIVER_PRESENT)
    /* Try dynamically-registered SE interface first */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if( psa_get_se_driver( slot->attr.lifetime, &drv, &drv_context ) )
    {
        if( drv->asymmetric == NULL ||
            drv->asymmetric->p_verify == NULL )
        {
            /* Key is defined in SE, but we have no way to exercise it */
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        return( drv->asymmetric->p_verify( drv_context,
                                           slot->data.se.slot_number,
                                           alg,
                                           hash, hash_length,
                                           signature, signature_length ) );
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    /* Then try accelerator API */
#if defined(MBEDTLS_PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime);
    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */
#if defined(MBEDTLS_TEST_HOOKS)
            status = test_transparent_signature_verify_hash( &attributes,
                                                             slot->data.key.data,
                                                             slot->data.key.bytes,
                                                             alg,
                                                             hash,
                                                             hash_length,
                                                             signature,
                                                             signature_length );
            /* Declared with fallback == true */
            if( status != PSA_ERROR_NOT_SUPPORTED )
                return status;
#endif /* MBEDTLS_TEST_HOOKS */
            /* Fell through, meaning no accelerator supports this operation */
            return PSA_ERROR_NOT_SUPPORTED;
        /* Add cases for opaque driver here */
#if defined(MBEDTLS_TEST_HOOKS)
        case MBEDTLS_PSA_CRYPTO_TEST_DRIVER_LIFETIME:
            return( test_opaque_signature_verify_hash( &attributes,
                                                       slot->data.key.data,
                                                       slot->data.key.bytes,
                                                       alg,
                                                       hash,
                                                       hash_length,
                                                       signature,
                                                       signature_length ) );
#endif /* MBEDTLS_TEST_HOOKS */
        default:
            /* Key is declared with a lifetime not known to us */
            return status;
    }
#else /* MBEDTLS_PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
    return PSA_ERROR_NOT_SUPPORTED;
#endif /* MBEDTLS_PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
#else /* MBEDTLS_PSA_CRYPTO_DRIVER_PRESENT */
    (void)slot;
    (void)alg;
    (void)hash;
    (void)hash_length;
    (void)signature;
    (void)signature_length;

    return PSA_ERROR_NOT_SUPPORTED;
#endif /* MBEDTLS_PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_generate_key( const psa_key_attributes_t *attributes,
                                              psa_key_slot_t *slot )
{
    (void) attributes;
    (void) slot;

    return PSA_ERROR_NOT_SUPPORTED;
}

/* End of automatically generated file. */
