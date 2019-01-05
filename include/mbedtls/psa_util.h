/**
 * \file psa_util.h
 *
 * \brief Utility functions for the use of the PSA Crypto library.
 *
 * \warning This function is not part of the public API and may
 *          change at any time.
 */
/*
 *  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
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

#ifndef MBEDTLS_PSA_UTIL_H
#define MBEDTLS_PSA_UTIL_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)

#include "psa/crypto.h"

#include "ecp.h"
#include "md.h"
#include "pk.h"

/* Slot allocation */

static inline psa_status_t mbedtls_psa_get_free_key_slot( psa_key_slot_t *key )
{
    for( psa_key_slot_t slot = 1; slot <= 32; slot++ )
    {
        if( psa_get_key_information( slot, NULL, NULL ) == PSA_ERROR_EMPTY_SLOT )
        {
            *key = slot;
            return( PSA_SUCCESS );
        }
    }
    return( PSA_ERROR_INSUFFICIENT_MEMORY );
}

/* Translations for symmetric crypto. */

static inline psa_key_type_t mbedtls_psa_translate_cipher_type(
    mbedtls_cipher_type_t cipher )
{
    switch( cipher )
    {
        case MBEDTLS_CIPHER_AES_128_CCM:
        case MBEDTLS_CIPHER_AES_192_CCM:
        case MBEDTLS_CIPHER_AES_256_CCM:
        case MBEDTLS_CIPHER_AES_128_GCM:
        case MBEDTLS_CIPHER_AES_192_GCM:
        case MBEDTLS_CIPHER_AES_256_GCM:
        case MBEDTLS_CIPHER_AES_128_CBC:
        case MBEDTLS_CIPHER_AES_192_CBC:
        case MBEDTLS_CIPHER_AES_256_CBC:
            return( PSA_KEY_TYPE_AES );

        /* ARIA not yet supported in PSA. */
        /* case MBEDTLS_CIPHER_ARIA_128_CCM:
           case MBEDTLS_CIPHER_ARIA_192_CCM:
           case MBEDTLS_CIPHER_ARIA_256_CCM:
           case MBEDTLS_CIPHER_ARIA_128_GCM:
           case MBEDTLS_CIPHER_ARIA_192_GCM:
           case MBEDTLS_CIPHER_ARIA_256_GCM:
           case MBEDTLS_CIPHER_ARIA_128_CBC:
           case MBEDTLS_CIPHER_ARIA_192_CBC:
           case MBEDTLS_CIPHER_ARIA_256_CBC:
               return( PSA_KEY_TYPE_ARIA ); */

        default:
            return( 0 );
    }
}

static inline psa_algorithm_t mbedtls_psa_translate_cipher_mode(
    mbedtls_cipher_mode_t mode, size_t taglen )
{
    switch( mode )
    {
        case MBEDTLS_MODE_GCM:
            return( PSA_ALG_AEAD_WITH_TAG_LENGTH( PSA_ALG_GCM, taglen ) );
        case MBEDTLS_MODE_CCM:
            return( PSA_ALG_AEAD_WITH_TAG_LENGTH( PSA_ALG_CCM, taglen ) );
        case MBEDTLS_MODE_CBC:
            if( taglen == 0 )
                return( PSA_ALG_CBC_NO_PADDING );
            /* Intentional fallthrough for taglen != 0 */
        default:
            return( 0 );
    }
}

static inline psa_key_usage_t mbedtls_psa_translate_cipher_operation(
    mbedtls_operation_t op )
{
    switch( op )
    {
        case MBEDTLS_ENCRYPT:
            return( PSA_KEY_USAGE_ENCRYPT );
        case MBEDTLS_DECRYPT:
            return( PSA_KEY_USAGE_DECRYPT );
        default:
            return( 0 );
    }
}

/* Translations for hashing. */

static inline psa_algorithm_t mbedtls_psa_translate_md( mbedtls_md_type_t md_alg )
{
    switch( md_alg )
    {
#if defined(MBEDTLS_MD2_C)
    case MBEDTLS_MD_MD2:
        return( PSA_ALG_MD2 );
#endif
#if defined(MBEDTLS_MD4_C)
    case MBEDTLS_MD_MD4:
        return( PSA_ALG_MD4 );
#endif
#if defined(MBEDTLS_MD5_C)
    case MBEDTLS_MD_MD5:
        return( PSA_ALG_MD5 );
#endif
#if defined(MBEDTLS_SHA1_C)
    case MBEDTLS_MD_SHA1:
        return( PSA_ALG_SHA_1 );
#endif
#if defined(MBEDTLS_SHA256_C)
    case MBEDTLS_MD_SHA224:
        return( PSA_ALG_SHA_224 );
    case MBEDTLS_MD_SHA256:
        return( PSA_ALG_SHA_256 );
#endif
#if defined(MBEDTLS_SHA512_C)
    case MBEDTLS_MD_SHA384:
        return( PSA_ALG_SHA_384 );
    case MBEDTLS_MD_SHA512:
        return( PSA_ALG_SHA_512 );
#endif
#if defined(MBEDTLS_RIPEMD160_C)
    case MBEDTLS_MD_RIPEMD160:
        return( PSA_ALG_RIPEMD160 );
#endif
    case MBEDTLS_MD_NONE:  /* Intentional fallthrough */
    default:
        return( 0 );
    }
}

/* Translations for ECC. */

static inline psa_ecc_curve_t mbedtls_psa_translate_ecc_group( mbedtls_ecp_group_id grpid )
{
    switch( grpid )
    {
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP192R1:
            return( PSA_ECC_CURVE_SECP192R1 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP224R1:
            return( PSA_ECC_CURVE_SECP224R1 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP256R1:
            return( PSA_ECC_CURVE_SECP256R1 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP384R1:
            return( PSA_ECC_CURVE_SECP384R1 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP521R1:
            return( PSA_ECC_CURVE_SECP521R1 );
#endif
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
        case MBEDTLS_ECP_DP_BP256R1:
            return( PSA_ECC_CURVE_BRAINPOOL_P256R1 );
#endif
#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
        case MBEDTLS_ECP_DP_BP384R1:
            return( PSA_ECC_CURVE_BRAINPOOL_P384R1 );
#endif
#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
        case MBEDTLS_ECP_DP_BP512R1:
            return( PSA_ECC_CURVE_BRAINPOOL_P512R1 );
#endif
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
        case MBEDTLS_ECP_DP_CURVE25519:
            return( PSA_ECC_CURVE_CURVE25519 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
        case MBEDTLS_ECP_DP_SECP192K1:
            return( PSA_ECC_CURVE_SECP192K1 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
        case MBEDTLS_ECP_DP_SECP224K1:
            return( PSA_ECC_CURVE_SECP224K1 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
        case MBEDTLS_ECP_DP_SECP256K1:
            return( PSA_ECC_CURVE_SECP256K1 );
#endif
#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
        case MBEDTLS_ECP_DP_CURVE448:
            return( PSA_ECC_CURVE_CURVE448 );
#endif
        default:
            return( 0 );
    }
}

/* Translations for PK layer */

static inline int mbedtls_psa_err_translate_pk( psa_status_t status )
{
    switch( status )
    {
        case PSA_SUCCESS:
            return( 0 );
        case PSA_ERROR_NOT_SUPPORTED:
            return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );
        case PSA_ERROR_INSUFFICIENT_MEMORY:
            return( MBEDTLS_ERR_PK_ALLOC_FAILED );
        case PSA_ERROR_INSUFFICIENT_ENTROPY:
            return( MBEDTLS_ERR_ECP_RANDOM_FAILED );
        case PSA_ERROR_BAD_STATE:
            return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
        /* All other failures */
        case PSA_ERROR_COMMUNICATION_FAILURE:
        case PSA_ERROR_HARDWARE_FAILURE:
        case PSA_ERROR_TAMPERING_DETECTED:
            return( MBEDTLS_ERR_PK_HW_ACCEL_FAILED );
        default: /* We return the same as for the 'other failures',
                  * but list them separately nonetheless to indicate
                  * which failure conditions we have considered. */
            return( MBEDTLS_ERR_PK_HW_ACCEL_FAILED );
    }
}

#endif /* MBEDTLS_USE_PSA_CRYPTO */

#endif /* MBEDTLS_PSA_UTIL_H */
