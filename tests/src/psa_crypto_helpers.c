/** \file psa_crypto_helpers.c
 *
 * \brief Helper functions to test PSA crypto functionality.
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

#include <test/helpers.h>
#include <test/macros.h>
#include <psa_crypto_slot_management.h>
#include <test/psa_crypto_helpers.h>

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include <psa/crypto.h>

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)

#include <psa_crypto_storage.h>

static mbedtls_svc_key_id_t key_ids_used_in_test[9];
static size_t num_key_ids_used;

int mbedtls_test_uses_key_id( mbedtls_svc_key_id_t key_id )
{
    size_t i;
    if( MBEDTLS_SVC_KEY_ID_GET_KEY_ID( key_id ) >
        PSA_MAX_PERSISTENT_KEY_IDENTIFIER )
    {
        /* Don't touch key id values that designate non-key files. */
        return( 1 );
    }
    for( i = 0; i < num_key_ids_used ; i++ )
    {
        if( mbedtls_svc_key_id_equal( key_id, key_ids_used_in_test[i] ) )
            return( 1 );
    }
    if( num_key_ids_used == ARRAY_LENGTH( key_ids_used_in_test ) )
        return( 0 );
    key_ids_used_in_test[num_key_ids_used] = key_id;
    ++num_key_ids_used;
    return( 1 );
}

void mbedtls_test_psa_purge_key_storage( void )
{
    size_t i;
    for( i = 0; i < num_key_ids_used; i++ )
        psa_destroy_persistent_key( key_ids_used_in_test[i] );
    num_key_ids_used = 0;
}

void mbedtls_test_psa_purge_key_cache( void )
{
    size_t i;
    for( i = 0; i < num_key_ids_used; i++ )
        psa_purge_key( key_ids_used_in_test[i] );
}

#endif /* MBEDTLS_PSA_CRYPTO_STORAGE_C */

const char *mbedtls_test_helper_is_psa_leaking( void )
{
    mbedtls_psa_stats_t stats;

    mbedtls_psa_get_stats( &stats );

    if( stats.volatile_slots != 0 )
        return( "A volatile slot has not been closed properly." );
    if( stats.persistent_slots != 0 )
        return( "A persistent slot has not been closed properly." );
    if( stats.external_slots != 0 )
        return( "An external slot has not been closed properly." );
     if( stats.half_filled_slots != 0 )
        return( "A half-filled slot has not been cleared properly." );
    if( stats.locked_slots != 0 )
        return( "Some slots are still marked as locked." );

    return( NULL );
}

int mbedtls_test_psa_create_key( mbedtls_test_psa_create_key_method_t method,
                                 const psa_key_attributes_t *attributes,
                                 const uint8_t *key_material,
                                 size_t key_material_size,
                                 mbedtls_svc_key_id_t *key )
{
    int ok = 0;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    mbedtls_svc_key_id_t base_key = MBEDTLS_SVC_KEY_ID_INIT;

    switch( method )
    {
        case IMPORT_KEY:
            /* Import the key */
            PSA_ASSERT( psa_import_key( attributes,
                                        key_material, key_material_size,
                                        key ) );
            break;

        case GENERATE_KEY:
            /* Generate a key */
            PSA_ASSERT( psa_generate_key( attributes, key ) );
            break;

        case DERIVE_KEY:
#if defined(PSA_WANT_ALG_HKDF) && defined(PSA_WANT_ALG_SHA_256)
            {
                /* Create base key */
                psa_algorithm_t derive_alg = PSA_ALG_HKDF( PSA_ALG_SHA_256 );
                psa_key_attributes_t base_attributes = PSA_KEY_ATTRIBUTES_INIT;
                psa_set_key_usage_flags( &base_attributes,
                                         PSA_KEY_USAGE_DERIVE );
                psa_set_key_algorithm( &base_attributes, derive_alg );
                psa_set_key_type( &base_attributes, PSA_KEY_TYPE_DERIVE );
                PSA_ASSERT( psa_import_key( &base_attributes,
                                            key_material, key_material_size,
                                            &base_key ) );
                /* Derive a key. */
                PSA_ASSERT( psa_key_derivation_setup( &operation, derive_alg ) );
                PSA_ASSERT( psa_key_derivation_input_key(
                                &operation,
                                PSA_KEY_DERIVATION_INPUT_SECRET, base_key ) );
                PSA_ASSERT( psa_key_derivation_input_bytes(
                                &operation, PSA_KEY_DERIVATION_INPUT_INFO,
                                NULL, 0 ) );
                PSA_ASSERT( psa_key_derivation_output_key( attributes,
                                                           &operation,
                                                           key ) );
                PSA_ASSERT( psa_key_derivation_abort( &operation ) );
                PSA_ASSERT( psa_destroy_key( base_key ) );
                base_key = MBEDTLS_SVC_KEY_ID_INIT;
            }
#else
            TEST_ASSUME( ! "KDF not supported in this configuration" );
#endif
            break;

        default:
            TEST_ASSERT( ! "generation_method not implemented in test" );
            break;
    }

    ok = 1;

exit:
    psa_destroy_key( base_key );
    psa_key_derivation_abort( &operation );
    return( ok );
}

#if defined(RECORD_PSA_STATUS_COVERAGE_LOG)
/** Name of the file where return statuses are logged by #RECORD_STATUS. */
#define STATUS_LOG_FILE_NAME "statuses.log"

psa_status_t mbedtls_test_record_status( psa_status_t status,
                                         const char *func,
                                         const char *file, int line,
                                         const char *expr )
{
    /* We open the log file on first use.
     * We never close the log file, so the record_status feature is not
     * compatible with resource leak detectors such as Asan.
     */
    static FILE *log;
    if( log == NULL )
        log = fopen( STATUS_LOG_FILE_NAME, "a" );
    fprintf( log, "%d:%s:%s:%d:%s\n", (int) status, func, file, line, expr );
    return( status );
}
#endif /* defined(RECORD_PSA_STATUS_COVERAGE_LOG) */

psa_key_usage_t mbedtls_test_update_key_usage_flags( psa_key_usage_t usage_flags )
{
    psa_key_usage_t updated_usage = usage_flags;

    if( usage_flags & PSA_KEY_USAGE_SIGN_HASH )
        updated_usage |= PSA_KEY_USAGE_SIGN_MESSAGE;

    if( usage_flags & PSA_KEY_USAGE_VERIFY_HASH )
        updated_usage |= PSA_KEY_USAGE_VERIFY_MESSAGE;

    return( updated_usage );
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
