/*
 *  PSA ECP layer on top of Mbed TLS crypto
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

#include "common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include <psa/crypto.h>
#include "psa_crypto_core.h"
#include "psa_crypto_ecp.h"
#include "psa_crypto_random_impl.h"

#include <stdlib.h>
#include <string.h>
#include "mbedtls/platform.h"
#if !defined(MBEDTLS_PLATFORM_C)
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

#include <mbedtls/ecp.h>
#include <mbedtls/error.h>

#if ( defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) ||  \
      ( defined(PSA_CRYPTO_DRIVER_TEST) &&                   \
        defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) ) )
#define BUILTIN_KEY_TYPE_ECC_KEY_PAIR    1
#endif

#if ( defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) ||  \
      ( defined(PSA_CRYPTO_DRIVER_TEST) &&                   \
        defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY) ) )
#define BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY  1
#endif

#if defined(BUILTIN_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_ECDH) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
psa_status_t mbedtls_psa_ecp_load_representation(
    psa_key_type_t type, const uint8_t *data, size_t data_length,
    mbedtls_ecp_keypair **p_ecp )
{
    mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_NONE;
    psa_status_t status;
    mbedtls_ecp_keypair *ecp = NULL;
    size_t curve_size = data_length;

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) &&
        PSA_KEY_TYPE_ECC_GET_FAMILY( type ) != PSA_ECC_FAMILY_MONTGOMERY )
    {
        /* A Weierstrass public key is represented as:
         * - The byte 0x04;
         * - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
         * - `y_P` as a `ceiling(m/8)`-byte string, big-endian.
         * So its data length is 2m+1 where m is the curve size in bits.
         */
        if( ( data_length & 1 ) == 0 )
            return( PSA_ERROR_INVALID_ARGUMENT );
        curve_size = data_length / 2;

        /* Montgomery public keys are represented in compressed format, meaning
         * their curve_size is equal to the amount of input. */

        /* Private keys are represented in uncompressed private random integer
         * format, meaning their curve_size is equal to the amount of input. */
    }

    /* Allocate and initialize a key representation. */
    ecp = mbedtls_calloc( 1, sizeof( mbedtls_ecp_keypair ) );
    if( ecp == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    mbedtls_ecp_keypair_init( ecp );

    /* Load the group. */
    grp_id = mbedtls_ecc_group_of_psa( PSA_KEY_TYPE_ECC_GET_FAMILY( type ),
                                       curve_size );
    if( grp_id == MBEDTLS_ECP_DP_NONE )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = mbedtls_to_psa_error(
                mbedtls_ecp_group_load( &ecp->grp, grp_id ) );
    if( status != PSA_SUCCESS )
        goto exit;

    /* Load the key material. */
    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) )
    {
        /* Load the public value. */
        status = mbedtls_to_psa_error(
            mbedtls_ecp_point_read_binary( &ecp->grp, &ecp->Q,
                                           data,
                                           data_length ) );
        if( status != PSA_SUCCESS )
            goto exit;

        /* Check that the point is on the curve. */
        status = mbedtls_to_psa_error(
            mbedtls_ecp_check_pubkey( &ecp->grp, &ecp->Q ) );
        if( status != PSA_SUCCESS )
            goto exit;
    }
    else
    {
        /* Load and validate the secret value. */
        status = mbedtls_to_psa_error(
            mbedtls_ecp_read_key( ecp->grp.id,
                                  ecp,
                                  data,
                                  data_length ) );
        if( status != PSA_SUCCESS )
            goto exit;
    }

    *p_ecp = ecp;
exit:
    if( status != PSA_SUCCESS )
    {
        mbedtls_ecp_keypair_free( ecp );
        mbedtls_free( ecp );
    }

    return( status );
}
#endif /* defined(BUILTIN_KEY_TYPE_ECC_KEY_PAIR) ||
        * defined(BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_ECDH) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) */

#if defined(BUILTIN_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY)

static psa_status_t ecp_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits )
{
    psa_status_t status;
    mbedtls_ecp_keypair *ecp = NULL;

    /* Parse input */
    status = mbedtls_psa_ecp_load_representation( attributes->core.type,
                                                  data,
                                                  data_length,
                                                  &ecp );
    if( status != PSA_SUCCESS )
        goto exit;

    if( PSA_KEY_TYPE_ECC_GET_FAMILY( attributes->core.type ) ==
        PSA_ECC_FAMILY_MONTGOMERY )
        *bits = ecp->grp.nbits + 1;
    else
        *bits = ecp->grp.nbits;

    /* Re-export the data to PSA export format. There is currently no support
     * for other input formats then the export format, so this is a 1-1
     * copy operation. */
    status = mbedtls_psa_ecp_export_key( attributes->core.type,
                                         ecp,
                                         key_buffer,
                                         key_buffer_size,
                                         key_buffer_length );
exit:
    /* Always free the PK object (will also free contained ECP context) */
    mbedtls_ecp_keypair_free( ecp );
    mbedtls_free( ecp );

    return( status );
}

psa_status_t mbedtls_psa_ecp_export_key( psa_key_type_t type,
                                         mbedtls_ecp_keypair *ecp,
                                         uint8_t *data,
                                         size_t data_size,
                                         size_t *data_length )
{
    psa_status_t status;

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) )
    {
        /* Check whether the public part is loaded */
        if( mbedtls_ecp_is_zero( &ecp->Q ) )
        {
            /* Calculate the public key */
            status = mbedtls_to_psa_error(
                mbedtls_ecp_mul( &ecp->grp, &ecp->Q, &ecp->d, &ecp->grp.G,
                                 mbedtls_psa_get_random,
                                 MBEDTLS_PSA_RANDOM_STATE ) );
            if( status != PSA_SUCCESS )
                return( status );
        }

        status = mbedtls_to_psa_error(
                    mbedtls_ecp_point_write_binary( &ecp->grp, &ecp->Q,
                                                    MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                    data_length,
                                                    data,
                                                    data_size ) );
        if( status != PSA_SUCCESS )
            memset( data, 0, data_size );

        return( status );
    }
    else
    {
        if( data_size < PSA_BITS_TO_BYTES( ecp->grp.nbits ) )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        status = mbedtls_to_psa_error(
                    mbedtls_ecp_write_key( ecp,
                                           data,
                                           PSA_BITS_TO_BYTES( ecp->grp.nbits ) ) );
        if( status == PSA_SUCCESS )
            *data_length = PSA_BITS_TO_BYTES( ecp->grp.nbits );
        else
            memset( data, 0, data_size );

        return( status );
    }
}

static psa_status_t ecp_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_keypair *ecp = NULL;

    status = mbedtls_psa_ecp_load_representation(
                 attributes->core.type, key_buffer, key_buffer_size, &ecp );
    if( status != PSA_SUCCESS )
        return( status );

    status = mbedtls_psa_ecp_export_key(
                 PSA_KEY_TYPE_ECC_PUBLIC_KEY(
                     PSA_KEY_TYPE_ECC_GET_FAMILY( attributes->core.type ) ),
                 ecp, data, data_size, data_length );

    mbedtls_ecp_keypair_free( ecp );
    mbedtls_free( ecp );

    return( status );
}
#endif /* defined(BUILTIN_KEY_TYPE_ECC_KEY_PAIR) ||
        * defined(BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY)

psa_status_t mbedtls_psa_ecp_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits )
{
    return( ecp_import_key( attributes, data, data_length,
                            key_buffer, key_buffer_size,
                            key_buffer_length, bits ) );
}

psa_status_t mbedtls_psa_ecp_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    return( ecp_export_public_key( attributes, key_buffer, key_buffer_size,
                                   data, data_size, data_length ) );
}

#endif /* defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) */

/*
 * BEYOND THIS POINT, TEST DRIVER ENTRY POINTS ONLY.
 */

#if defined(PSA_CRYPTO_DRIVER_TEST)

#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)

psa_status_t mbedtls_transparent_test_driver_ecp_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits )
{
    return( ecp_import_key( attributes, data, data_length,
                            key_buffer, key_buffer_size,
                            key_buffer_length, bits ) );
}

psa_status_t mbedtls_transparent_test_driver_ecp_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    return( ecp_export_public_key( attributes, key_buffer, key_buffer_size,
                                   data, data_size, data_length ) );
}

#endif /* defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) ||
          defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY) */

#endif /* PSA_CRYPTO_DRIVER_TEST */

#endif /* MBEDTLS_PSA_CRYPTO_C */
