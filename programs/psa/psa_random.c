#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <psa/crypto.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "mbedtls/entropy.h"
#include "mbedtls/entropy_poll.h"

#define BUFFER_SIZE 100

#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
#include <mbedtls/psa_util.h>
#include <psa/crypto_platform.h>

typedef mbedtls_psa_external_random_context_t mbedtls_psa_random_context_t;


typedef struct
{
    mbedtls_psa_random_context_t rng;
    unsigned initialized : 1;
    unsigned rng_state : 2;
} psa_global_data_t;

static psa_global_data_t global_data;

psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context,
    uint8_t *output, size_t output_size, size_t *output_length )
{
    (void) context;
    size_t i;

    /* This implementation is for test purposes only! */
    for( i = 0; i < output_size; ++i )
        output[i] = '\0';

    *output_length = output_size;
    return( PSA_SUCCESS );
}
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

#if !defined(MBEDTLS_PSA_CRYPTO_C)
int main( void )
{
    printf( "MBEDTLS_PSA_CRYPTO_C not defined.\r\n" );
    return( 0 );
}
#else
int main( void )
{
    psa_status_t status;
    uint8_t output[BUFFER_SIZE] = {0};

    status = psa_crypto_init( );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_crypto_init failed\n" );
        return( EXIT_FAILURE );
    }
#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
     size_t output_length = 0;
    psa_status_t status = mbedtls_psa_external_get_random( &global_data.rng,
                                                           output, output_size,
                                                           &output_length );

    status = mbedtls_psa_external_get_random ( output, BUFFER_SIZE );
    if( status != PSA_SUCCESS )
    {
        printf( "mbedtls_psa_external_get_random failed\n" );
        return( EXIT_FAILURE );
    }

#else
    status = psa_generate_random( output, BUFFER_SIZE );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_generate_random failed\n" );
        return( EXIT_FAILURE );
    }
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

    printf( "Random bytes generated:\n" );

    for( size_t j = 0; j < BUFFER_SIZE; j++ )
    {
        if( j % 8 == 0 ) printf( "\n    " );
        printf( "%02x ", output[j] );
    }

    printf( "\n" );

    mbedtls_psa_crypto_free( );
    return( 0 );
}
#endif /* MBEDTLS_PSA_CRYPTO_C */
