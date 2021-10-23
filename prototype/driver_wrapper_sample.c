/*
 *  Functions to delegate cryptographic operations to an available
 *  and appropriate accelerator.
 *  Warning: This file is partially auto-generated from a base template.
 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
/* BEGIN-common headers */
#include "common.h"
#include "psa_crypto_aead.h"
#include "psa_crypto_cipher.h"
#include "psa_crypto_core.h"
#include "psa_crypto_driver_wrappers.h"
#include "psa_crypto_hash.h"
#include "psa_crypto_mac.h"
#include "mbedtls/platform.h"
/* END-common headers */

/* BEGIN-driver headers */
/* Headers for sli_se transparent driver */
#include "sli_se_transparent_types.h"
#include "sli_se_transparent_functions.h"

/* Headers for sli_se opaque driver */
#include "sli_se_opaque_types.h"
#include "sli_se_opaque_functions.h"


/* END-driver headers */

/* BEGIN-driver id definition */
#define PSA_CRYPTO_MBED_TLS_DRIVER_ID 1
#define SLI_SE_TRANSPARENT_DRIVER_ID 2
#define SLI_SE_OPAQUE_DRIVER_ID 3

/* END-driver id */

/* BEGIN-driver dispatch */

/*
 * Hashing functions
 */
psa_status_t psa_driver_wrapper_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length)
{
/* BEGIN-function body */

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
/* BEGIN-Templating *************************************/

#if defined((CONFIG_THIS) && (CONFIG_THAT) )
    status = sli_se_transparent_hash_compute(alg, 
                        input, 
                        input_length,
                        hash, 
                        hash_size, 
                        hash_length 
    );
                                                  
    if( status != PSA_ERROR_NOT_SUPPORTED )
        return( status );
#endif

/* END-Templating ************************************** */
/* If software fallback is compiled in, try fallback */
#if defined(MBEDTLS_PSA_BUILTIN_HASH)
    status = mbedtls_psa_hash_compute( alg, input, input_length,
                                       hash, hash_size, hash_length );
    if( status != PSA_ERROR_NOT_SUPPORTED )
        return( status );
#endif
    (void) status;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) hash;
    (void) hash_size;
    (void) hash_length;

    return( PSA_ERROR_NOT_SUPPORTED );
/* END-function body */
}

psa_status_t psa_driver_wrapper_hash_setup(
    psa_hash_operation_t *operation,
    psa_algorithm_t alg )
{



    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    /* Try setup on accelerators first */
    /* BEGIN-Templating ************************************ */

#if defined((CONFIG_THIS) && (CONFIG_THAT) )

    status = sli_se_transparent_hash_setup( 
                        &operation->ctx.sli_se_transparent_ctx,
                        alg
     );
                                                  
    if( status == PSA_SUCCESS )
        operation->id = SLI_SE_TRANSPARENT_DRIVER_ID;

    if( status != PSA_ERROR_NOT_SUPPORTED )
        return( status );

#endif


/* END-Templating ************************************** */

    /* If software fallback is compiled in, try fallback */
#if defined(MBEDTLS_PSA_BUILTIN_HASH)
    status = mbedtls_psa_hash_setup( &operation->ctx.mbedtls_ctx, alg );
    if( status == PSA_SUCCESS )
        operation->id = PSA_CRYPTO_MBED_TLS_DRIVER_ID;

    if( status != PSA_ERROR_NOT_SUPPORTED )
        return( status );
#endif
    /* Nothing left to try if we fall through here */
    (void) status;
    (void) operation;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}


psa_status_t psa_driver_wrapper_hash_clone(
    const psa_hash_operation_t *source_operation,
    psa_hash_operation_t *target_operation )
{

    switch( source_operation->id )
    {
#if defined(MBEDTLS_PSA_BUILTIN_HASH)
        case PSA_CRYPTO_MBED_TLS_DRIVER_ID:
            target_operation->id = PSA_CRYPTO_MBED_TLS_DRIVER_ID;
            return( mbedtls_psa_hash_clone( &source_operation->ctx.mbedtls_ctx,
                                            &target_operation->ctx.mbedtls_ctx ) );
#endif
/* BEGIN-Templating ************************************ */

#if defined((CONFIG_THIS) && (CONFIG_THAT) )

        case SLI_SE_TRANSPARENT_DRIVER_ID:
            target_operation->id = SLI_SE_TRANSPARENT_ID;
          
            return(sli_se_transparent_hash_clone(&source_operation->ctx.sli_se_transparent_ctx,
                            &target_operation->ctx.sli_se_transparent_ctx
        ));

#endif


/* END-Templating ************************************** */
        default:
            (void) target_operation;
            return( PSA_ERROR_BAD_STATE );
    }
}

psa_status_t psa_driver_wrapper_hash_update(
    psa_hash_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{


 
    switch( operation->id )
    {
#if defined(MBEDTLS_PSA_BUILTIN_HASH)
        case PSA_CRYPTO_MBED_TLS_DRIVER_ID:
            return( mbedtls_psa_hash_update( &operation->ctx.mbedtls_ctx,
                                             input, input_length ) );
#endif
/* BEGIN-Templating ************************************ */

#if defined((CONFIG_THIS) && (CONFIG_THAT) )

        case SLI_SE_TRANSPARENT_DRIVER_ID:
              
            return(sli_se_transparent_hash_update(&operation->ctx.sli_se_transparent_ctx,
                            input,
                            input_length
        ));

#endif


/* END-Templating ************************************** */
        default:
            (void) input;
            (void) input_length;
            return( PSA_ERROR_BAD_STATE );
    }
}

psa_status_t psa_driver_wrapper_hash_finish(
    psa_hash_operation_t *operation,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length )
{

    switch( operation->id )
    {
#if defined(MBEDTLS_PSA_BUILTIN_HASH)
        case PSA_CRYPTO_MBED_TLS_DRIVER_ID:
            return( mbedtls_psa_hash_finish( &operation->ctx.mbedtls_ctx,
                                             hash, hash_size, hash_length ) );
#endif
/* BEGIN-Templating ************************************ */

#if defined((CONFIG_THIS) && (CONFIG_THAT) )

        case SLI_SE_TRANSPARENT_DRIVER_ID:
              
            return(sli_se_transparent_hash_finish(&operation->ctx.sli_se_transparent_ctx,
                            hash,
                            hash_size,
                            hash_length
        ));

#endif


/* END-Templating ************************************** */
        default:
            (void) hash;
            (void) hash_size;
            (void) hash_length;
            return( PSA_ERROR_BAD_STATE );
    }
}

psa_status_t psa_driver_wrapper_hash_abort(
    psa_hash_operation_t *operation )
{

    switch( operation->id )
    {
#if defined(MBEDTLS_PSA_BUILTIN_HASH)
        case PSA_CRYPTO_MBED_TLS_DRIVER_ID:
            return( mbedtls_psa_hash_abort( &operation->ctx.mbedtls_ctx ) );
#endif
/* BEGIN-Templating ************************************ */

#if defined((CONFIG_THIS) && (CONFIG_THAT) )

        case SLI_SE_TRANSPARENT_DRIVER_ID:
              
            return(sli_se_transparent_hash_abort(&operation->ctx.sli_se_transparent_ctx,
        ));

#endif


/* END-Templating ************************************** */
        default:
            return( PSA_ERROR_BAD_STATE );
    }
}

psa_status_t psa_driver_wrapper_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length,
    size_t *bits )
{
/* BEGIN-function body */

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(
                                      psa_get_key_lifetime( attributes ) );

    /* Try dynamically-registered SE interface first */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if( psa_get_se_driver( attributes->core.lifetime, &drv, &drv_context ) )
    {
        if( drv->key_management == NULL ||
            drv->key_management->p_import == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );

        /* The driver should set the number of key bits, however in
         * case it doesn't, we initialize bits to an invalid value. */
        *bits = PSA_MAX_KEY_BITS + 1;
        status = drv->key_management->p_import(
            drv_context,
            *( (psa_key_slot_number_t *)key_buffer ),
            attributes, data, data_length, bits );

        if( status != PSA_SUCCESS )
            return( status );

        if( (*bits) > PSA_MAX_KEY_BITS )
            return( PSA_ERROR_NOT_SUPPORTED );

        return( PSA_SUCCESS );
    }
#endif /* PSA_CRYPTO_SE_C */

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:                                  
           /* Key is stored in the slot in export representation, so
            * cycle through all known transparent accelerators */
/* BEGIN-Templating ************************************ */

#if defined((CONFIG_THIS) && (CONFIG_THAT) )
            status = sli_se_transparent_import_key(attributes, 
                                data, 
                                data_length, 
                                key_buffer, 
                                key_buffer_size, 
                                key_buffer_length, 
                                bits
            );
                                                          
            if( status != PSA_ERROR_NOT_SUPPORTED )
                return( status );
#endif

/* END-Templating ************************************** */

#if defined(MBEDTLS_PSA_BUILTIN_IMPORT)
            /* Fell through, meaning no accelerator supports this operation */
            return( psa_import_key_into_slot( attributes,
                                              data, data_length,
                                              key_buffer, key_buffer_size,
                                              key_buffer_length, bits ) );
#else
            return( status );
#endif
        /* Add cases for opaque driver here */
/* BEGIN-Templating ************************************ */

#if defined((CONFIG_OPAQUE_THIS) && (CONFIG_OPAQUE_THAT) )
        case 1:
            return(sli_se_opaque_import_key(attributes, 
                            data, 
                            data_length, 
                            key_buffer, 
                            key_buffer_size, 
                            key_buffer_length, 
                            bits
        ));
#endif

/* END-Templating ************************************** */
        default:
            (void)status;
            return( PSA_ERROR_INVALID_ARGUMENT );
    }

/* END-function body */
}
psa_status_t psa_driver_wrapper_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )

{

    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(
                                      psa_get_key_lifetime( attributes ) );

    /* Try dynamically-registered SE interface first */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if( psa_get_se_driver( attributes->core.lifetime, &drv, &drv_context ) )
    {
        if( ( drv->key_management == NULL ) ||
            ( drv->key_management->p_export_public == NULL ) )
        {
            return( PSA_ERROR_NOT_SUPPORTED );
        }

        return( drv->key_management->p_export_public(
                    drv_context,
                    *( (psa_key_slot_number_t *)key_buffer ),
                    data, data_size, data_length ) );
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */
/* BEGIN-Templating ************************************ */

#if defined((CONFIG_THIS) && (CONFIG_THAT) )
            status = sli_se_transparent_export_public_key(attributes,
                                key_buffer,
                                key_buffer_size,
                                data,
                                data_size,
                                data_length
            );
                                                          
            if( status != PSA_ERROR_NOT_SUPPORTED )
                return( status );
#endif

/* END-Templating ************************************** */
           
#if defined(MBEDTLS_PSA_BUILTIN_EXPORT_PUBLIC_KEY)
            /* Fell through, meaning no accelerator supports this operation */
            return( psa_export_public_key_internal( attributes,
                                                    key_buffer,
                                                    key_buffer_size,
                                                    data,
                                                    data_size,
                                                    data_length ) );
#else
            return( status );
#endif
        /* Add cases for opaque driver here */
/* BEGIN-Templating ************************************ */

#if defined((CONFIG_OPAQUE_THIS) && (CONFIG_OPAQUE_THAT) )
        case 1:
            return(sli_se_opaque_export_public_key(attributes,
                            key_buffer,
                            key_buffer_size,
                            data,
                            data_size,
                            data_length
        ));
#endif

/* END-Templating ************************************** */
        default:
            /* Key is declared with a lifetime not known to us */
            return( status );
    }
}

psa_status_t psa_driver_wrapper_get_builtin_key(
    psa_drv_slot_number_t slot_number,
    psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length )
{

    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION( attributes->core.lifetime );
    switch( location )
    {
/* BEGIN-Templating ************************************ */

#if defined((CONFIG_OPAQUE_THIS) && (CONFIG_OPAQUE_THAT) )
        case 1:
            return(sli_se_opaque_get_builtin_key(slot_number,
                            attributes,
                            key_buffer,
                            key_buffer_size,
                            key_buffer_length
        ));
#endif

/* END-Templating ************************************** */
        default:
            (void) slot_number;
            (void) key_buffer;
            (void) key_buffer_size;
            (void) key_buffer_length;
            return( PSA_ERROR_DOES_NOT_EXIST );
    }
}
/* END-driver dispatch */
#endif /* MBEDTLS_PSA_CRYPTO_C */
