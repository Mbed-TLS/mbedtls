/**
 * PSA API key derivation demonstration
 *
 * This program calculates a key ladder: a chain of secret material, each
 * derived from the previous one in a deterministic way based on a label.
 * Two keys are identical if and only if they are derived from the same key
 * using the same label.
 *
 * The initial key is called the master key. The master key is normally
 * randomly generated, but it could itself be derived from another key.
 *
 * This program derives a series of keys called intermediate keys.
 * The first intermediate key is derived from the master key using the
 * first label passed on the command line. Each subsequent intermediate
 * key is derived from the previous one using the next label passed
 * on the command line.
 *
 * This program has four modes of operation:
 *
 * - "generate": generate a random master key.
 * - "wrap": derive a wrapping key from the last intermediate key,
 *           and use that key to encrypt-and-authenticate some data.
 * - "unwrap": derive a wrapping key from the last intermediate key,
 *             and use that key to decrypt-and-authenticate some
 *             ciphertext created by wrap mode.
 * - "save": save the last intermediate key so that it can be reused as
 *           the master key in another run of the program.
 *
 * See the usage() output for the command line usage. See the file
 * `key_ladder_demo.sh` for an example run.
 */

/*  Copyright (C) 2018, ARM Limited, All Rights Reserved
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

/* First include Mbed TLS headers to get the Mbed TLS configuration and
 * platform definitions that we'll use in this program. Also include
 * standard C headers for functions we'll use here. */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/platform_util.h" // for mbedtls_platform_zeroize

/* If the build options we need are not enabled, compile a placeholder. */
#if !defined(MBEDTLS_SHA256_C) || !defined(MBEDTLS_MD_C) ||     \
    !defined(MBEDTLS_AES_C) || !defined(MBEDTLS_CCM_C) ||       \
    !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(MBEDTLS_FS_IO)
int main( void )
{
    printf("MBEDTLS_SHA256_C and/or MBEDTLS_MD_C and/or "
           "MBEDTLS_AES_C and/or MBEDTLS_CCM_C and/or "
           "MBEDTLS_PSA_CRYPTO_C and/or MBEDTLS_FS_IO not defined.\n");
    return( 0 );
}
#else

/* The real program starts here. */



#include <psa/crypto.h>

/* Run a system function and bail out if it fails. */
#define SYS_CHECK( expr )                                       \
    do                                                          \
    {                                                           \
        if( ! ( expr ) )                                        \
        {                                                       \
            perror( #expr );                                    \
            status = DEMO_ERROR;                                \
            goto exit;                                          \
        }                                                       \
    }                                                           \
    while( 0 )

/* Run a PSA function and bail out if it fails. */
#define PSA_CHECK( expr )                                       \
    do                                                          \
    {                                                           \
        status = ( expr );                                      \
        if( status != PSA_SUCCESS )                             \
        {                                                       \
            printf( "Error %d at line %u: %s\n",                \
                    (int) status,                               \
                    __LINE__,                                   \
                    #expr );                                    \
            goto exit;                                          \
        }                                                       \
    }                                                           \
    while( 0 )

/* To report operational errors in this program, use an error code that is
 * different from every PSA error code. */
#define DEMO_ERROR 120

/* The maximum supported key ladder depth. */
#define MAX_LADDER_DEPTH 10

/* Salt to use when deriving an intermediate key. */
#define DERIVE_KEY_SALT ( (uint8_t *) "key_ladder_demo.derive" )
#define DERIVE_KEY_SALT_LENGTH ( strlen( (const char*) DERIVE_KEY_SALT ) )

/* Salt to use when deriving a wrapping key. */
#define WRAPPING_KEY_SALT ( (uint8_t *) "key_ladder_demo.wrap" )
#define WRAPPING_KEY_SALT_LENGTH ( strlen( (const char*) WRAPPING_KEY_SALT ) )

/* Size of the key derivation keys (applies both to the master key and
 * to intermediate keys). */
#define KEY_SIZE_BYTES 40

/* Algorithm for key derivation. */
#define KDF_ALG PSA_ALG_HKDF( PSA_ALG_SHA_256 )

/* Type and size of the key used to wrap data. */
#define WRAPPING_KEY_TYPE PSA_KEY_TYPE_AES
#define WRAPPING_KEY_BITS 128

/* Cipher mode used to wrap data. */
#define WRAPPING_ALG PSA_ALG_CCM

/* Nonce size used to wrap data. */
#define WRAPPING_IV_SIZE 13

/* Header used in files containing wrapped data. We'll save this header
 * directly without worrying about data representation issues such as
 * integer sizes and endianness, because the data is meant to be read
 * back by the same program on the same machine. */
#define WRAPPED_DATA_MAGIC "key_ladder_demo" // including trailing null byte
#define WRAPPED_DATA_MAGIC_LENGTH ( sizeof( WRAPPED_DATA_MAGIC ) )
typedef struct
{
    char magic[WRAPPED_DATA_MAGIC_LENGTH];
    size_t ad_size; /* Size of the additional data, which is this header. */
    size_t payload_size; /* Size of the encrypted data. */
    /* Store the IV inside the additional data. It's convenient. */
    uint8_t iv[WRAPPING_IV_SIZE];
} wrapped_data_header_t;

/* The modes that this program can operate in (see usage). */
enum program_mode
{
    MODE_GENERATE,
    MODE_SAVE,
    MODE_UNWRAP,
    MODE_WRAP
};

/* Save a key to a file. In the real world, you may want to export a derived
 * key sometimes, to share it with another party. */
static psa_status_t save_key( psa_key_handle_t key_handle,
                              const char *output_file_name )
{
    psa_status_t status = PSA_SUCCESS;
    uint8_t key_data[KEY_SIZE_BYTES];
    size_t key_size;
    FILE *key_file = NULL;

    PSA_CHECK( psa_export_key( key_handle,
                               key_data, sizeof( key_data ),
                               &key_size ) );
    SYS_CHECK( ( key_file = fopen( output_file_name, "wb" ) ) != NULL );
    SYS_CHECK( fwrite( key_data, 1, key_size, key_file ) == key_size );
    SYS_CHECK( fclose( key_file ) == 0 );
    key_file = NULL;

exit:
    if( key_file != NULL)
        fclose( key_file );
    return( status );
}

/* Generate a master key for use in this demo.
 *
 * Normally a master key would be non-exportable. For the purpose of this
 * demo, we want to save it to a file, to avoid relying on the keystore
 * capability of the PSA crypto library. */
static psa_status_t generate( const char *key_file_name )
{
    psa_status_t status = PSA_SUCCESS;
    psa_key_handle_t key_handle = 0;
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;

    PSA_CHECK( psa_allocate_key( &key_handle ) );
    psa_key_policy_set_usage( &policy,
                              PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT,
                              KDF_ALG );
    PSA_CHECK( psa_set_key_policy( key_handle, &policy ) );

    PSA_CHECK( psa_generate_key( key_handle,
                                 PSA_KEY_TYPE_DERIVE,
                                 PSA_BYTES_TO_BITS( KEY_SIZE_BYTES ),
                                 NULL, 0 ) );

    PSA_CHECK( save_key( key_handle, key_file_name ) );

exit:
    (void) psa_destroy_key( key_handle );
    return( status );
}

/* Load the master key from a file.
 *
 * In the real world, this master key would be stored in an internal memory
 * and the storage would be managed by the keystore capability of the PSA
 * crypto library. */
static psa_status_t import_key_from_file( psa_key_usage_t usage,
                                          psa_algorithm_t alg,
                                          const char *key_file_name,
                                          psa_key_handle_t *master_key_handle )
{
    psa_status_t status = PSA_SUCCESS;
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;
    uint8_t key_data[KEY_SIZE_BYTES];
    size_t key_size;
    FILE *key_file = NULL;
    unsigned char extra_byte;

    *master_key_handle = 0;

    SYS_CHECK( ( key_file = fopen( key_file_name, "rb" ) ) != NULL );
    SYS_CHECK( ( key_size = fread( key_data, 1, sizeof( key_data ),
                                   key_file ) ) != 0 );
    if( fread( &extra_byte, 1, 1, key_file ) != 0 )
    {
        printf( "Key file too large (max: %u).\n",
                (unsigned) sizeof( key_data ) );
        status = DEMO_ERROR;
        goto exit;
    }
    SYS_CHECK( fclose( key_file ) == 0 );
    key_file = NULL;

    PSA_CHECK( psa_allocate_key( master_key_handle ) );
    psa_key_policy_set_usage( &policy, usage, alg );
    PSA_CHECK( psa_set_key_policy( *master_key_handle, &policy ) );
    PSA_CHECK( psa_import_key( *master_key_handle,
                               PSA_KEY_TYPE_DERIVE,
                               key_data, key_size ) );
exit:
    if( key_file != NULL )
        fclose( key_file );
    mbedtls_platform_zeroize( key_data, sizeof( key_data ) );
    if( status != PSA_SUCCESS )
    {
        /* If psa_allocate_key hasn't been called yet or has failed,
         * *master_key_handle is 0. psa_destroy_key(0) is guaranteed to do
         * nothing and return PSA_ERROR_INVALID_HANDLE. */
        (void) psa_destroy_key( *master_key_handle );
        *master_key_handle = 0;
    }
    return( status );
}

/* Derive the intermediate keys, using the list of labels provided on
 * the command line. On input, *key_handle is a handle to the master key.
 * This function closes the master key. On successful output, *key_handle
 * is a handle to the final derived key. */
static psa_status_t derive_key_ladder( const char *ladder[],
                                       size_t ladder_depth,
                                       psa_key_handle_t *key_handle )
{
    psa_status_t status = PSA_SUCCESS;
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;
    psa_crypto_generator_t generator = PSA_CRYPTO_GENERATOR_INIT;
    size_t i;
    psa_key_policy_set_usage( &policy,
                              PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT,
                              KDF_ALG );

    /* For each label in turn, ... */
    for( i = 0; i < ladder_depth; i++ )
    {
        /* Start deriving material from the master key (if i=0) or from
         * the current intermediate key (if i>0). */
        PSA_CHECK( psa_key_derivation(
                       &generator,
                       *key_handle,
                       KDF_ALG,
                       DERIVE_KEY_SALT, DERIVE_KEY_SALT_LENGTH,
                       (uint8_t*) ladder[i], strlen( ladder[i] ),
                       KEY_SIZE_BYTES ) );
        /* When the parent key is not the master key, destroy it,
         * since it is no longer needed. */
        PSA_CHECK( psa_close_key( *key_handle ) );
        *key_handle = 0;
        PSA_CHECK( psa_allocate_key( key_handle ) );
        PSA_CHECK( psa_set_key_policy( *key_handle, &policy ) );
        /* Use the generator obtained from the parent key to create
         * the next intermediate key. */
        PSA_CHECK( psa_generator_import_key(
                       *key_handle,
                       PSA_KEY_TYPE_DERIVE,
                       PSA_BYTES_TO_BITS( KEY_SIZE_BYTES ),
                       &generator ) );
        PSA_CHECK( psa_generator_abort( &generator ) );
    }

exit:
    psa_generator_abort( &generator );
    if( status != PSA_SUCCESS )
    {
        psa_close_key( *key_handle );
        *key_handle = 0;
    }
    return( status );
}

/* Derive a wrapping key from the last intermediate key. */
static psa_status_t derive_wrapping_key( psa_key_usage_t usage,
                                         psa_key_handle_t derived_key_handle,
                                         psa_key_handle_t *wrapping_key_handle )
{
    psa_status_t status = PSA_SUCCESS;
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;
    psa_crypto_generator_t generator = PSA_CRYPTO_GENERATOR_INIT;

    *wrapping_key_handle = 0;
    PSA_CHECK( psa_allocate_key( wrapping_key_handle ) );
    psa_key_policy_set_usage( &policy, usage, WRAPPING_ALG );
    PSA_CHECK( psa_set_key_policy( *wrapping_key_handle, &policy ) );

    PSA_CHECK( psa_key_derivation(
                   &generator,
                   derived_key_handle,
                   KDF_ALG,
                   WRAPPING_KEY_SALT, WRAPPING_KEY_SALT_LENGTH,
                   NULL, 0,
                   PSA_BITS_TO_BYTES( WRAPPING_KEY_BITS ) ) );
    PSA_CHECK( psa_generator_import_key(
                   *wrapping_key_handle,
                   PSA_KEY_TYPE_AES,
                   WRAPPING_KEY_BITS,
                   &generator ) );

exit:
    psa_generator_abort( &generator );
    if( status != PSA_SUCCESS )
    {
        psa_close_key( *wrapping_key_handle );
        *wrapping_key_handle = 0;
    }
    return( status );
}

static psa_status_t wrap_data( const char *input_file_name,
                               const char *output_file_name,
                               psa_key_handle_t wrapping_key_handle )
{
    psa_status_t status;
    FILE *input_file = NULL;
    FILE *output_file = NULL;
    long input_position;
    size_t input_size;
    size_t buffer_size = 0;
    unsigned char *buffer = NULL;
    size_t ciphertext_size;
    wrapped_data_header_t header;

    /* Find the size of the data to wrap. */
    SYS_CHECK( ( input_file = fopen( input_file_name, "rb" ) ) != NULL );
    SYS_CHECK( fseek( input_file, 0, SEEK_END ) == 0 );
    SYS_CHECK( ( input_position = ftell( input_file ) ) != -1 );
#if LONG_MAX > SIZE_MAX
    if( input_position > SIZE_MAX )
    {
        printf( "Input file too large.\n" );
        status = DEMO_ERROR;
        goto exit;
    }
#endif
    input_size = input_position;
    buffer_size = PSA_AEAD_ENCRYPT_OUTPUT_SIZE( WRAPPING_ALG, input_size );
    /* Check for integer overflow. */
    if( buffer_size < input_size )
    {
        printf( "Input file too large.\n" );
        status = DEMO_ERROR;
        goto exit;
    }

    /* Load the data to wrap. */
    SYS_CHECK( fseek( input_file, 0, SEEK_SET ) == 0 );
    SYS_CHECK( ( buffer = calloc( 1, buffer_size ) ) != NULL );
    SYS_CHECK( fread( buffer, 1, input_size, input_file ) == input_size );
    SYS_CHECK( fclose( input_file ) == 0 );
    input_file = NULL;

    /* Construct a header. */
    memcpy( &header.magic, WRAPPED_DATA_MAGIC, WRAPPED_DATA_MAGIC_LENGTH );
    header.ad_size = sizeof( header );
    header.payload_size = input_size;

    /* Wrap the data. */
    PSA_CHECK( psa_generate_random( header.iv, WRAPPING_IV_SIZE ) );
    PSA_CHECK( psa_aead_encrypt( wrapping_key_handle, WRAPPING_ALG,
                                 header.iv, WRAPPING_IV_SIZE,
                                 (uint8_t *) &header, sizeof( header ),
                                 buffer, input_size,
                                 buffer, buffer_size,
                                 &ciphertext_size ) );

    /* Write the output. */
    SYS_CHECK( ( output_file = fopen( output_file_name, "wb" ) ) != NULL );
    SYS_CHECK( fwrite( &header, 1, sizeof( header ),
                       output_file ) == sizeof( header ) );
    SYS_CHECK( fwrite( buffer, 1, ciphertext_size,
                       output_file ) == ciphertext_size );
    SYS_CHECK( fclose( output_file ) == 0 );
    output_file = NULL;

exit:
    if( input_file != NULL )
        fclose( input_file );
    if( output_file != NULL )
        fclose( output_file );
    if( buffer != NULL )
        mbedtls_platform_zeroize( buffer, buffer_size );
    free( buffer );
    return( status );
}

static psa_status_t unwrap_data( const char *input_file_name,
                                 const char *output_file_name,
                                 psa_key_handle_t wrapping_key_handle )
{
    psa_status_t status;
    FILE *input_file = NULL;
    FILE *output_file = NULL;
    unsigned char *buffer = NULL;
    size_t ciphertext_size = 0;
    size_t plaintext_size;
    wrapped_data_header_t header;
    unsigned char extra_byte;

    /* Load and validate the header. */
    SYS_CHECK( ( input_file = fopen( input_file_name, "rb" ) ) != NULL );
    SYS_CHECK( fread( &header, 1, sizeof( header ),
                      input_file ) == sizeof( header ) );
    if( memcmp( &header.magic, WRAPPED_DATA_MAGIC,
                WRAPPED_DATA_MAGIC_LENGTH ) != 0 )
    {
        printf( "The input does not start with a valid magic header.\n" );
        status = DEMO_ERROR;
        goto exit;
    }
    if( header.ad_size != sizeof( header ) )
    {
        printf( "The header size is not correct.\n" );
        status = DEMO_ERROR;
        goto exit;
    }
    ciphertext_size =
        PSA_AEAD_ENCRYPT_OUTPUT_SIZE( WRAPPING_ALG, header.payload_size );
    /* Check for integer overflow. */
    if( ciphertext_size < header.payload_size )
    {
        printf( "Input file too large.\n" );
        status = DEMO_ERROR;
        goto exit;
    }

    /* Load the payload data. */
    SYS_CHECK( ( buffer = calloc( 1, ciphertext_size ) ) != NULL );
    SYS_CHECK( fread( buffer, 1, ciphertext_size,
                      input_file ) == ciphertext_size );
    if( fread( &extra_byte, 1, 1, input_file ) != 0 )
    {
        printf( "Extra garbage after ciphertext\n" );
        status = DEMO_ERROR;
        goto exit;
    }
    SYS_CHECK( fclose( input_file ) == 0 );
    input_file = NULL;

    /* Unwrap the data. */
    PSA_CHECK( psa_aead_decrypt( wrapping_key_handle, WRAPPING_ALG,
                                 header.iv, WRAPPING_IV_SIZE,
                                 (uint8_t *) &header, sizeof( header ),
                                 buffer, ciphertext_size,
                                 buffer, ciphertext_size,
                                 &plaintext_size ) );
    if( plaintext_size != header.payload_size )
    {
        printf( "Incorrect payload size in the header.\n" );
        status = DEMO_ERROR;
        goto exit;
    }

    /* Write the output. */
    SYS_CHECK( ( output_file = fopen( output_file_name, "wb" ) ) != NULL );
    SYS_CHECK( fwrite( buffer, 1, plaintext_size,
                       output_file ) == plaintext_size );
    SYS_CHECK( fclose( output_file ) == 0 );
    output_file = NULL;

exit:
    if( input_file != NULL )
        fclose( input_file );
    if( output_file != NULL )
        fclose( output_file );
    if( buffer != NULL )
        mbedtls_platform_zeroize( buffer, ciphertext_size );
    free( buffer );
    return( status );
}

static psa_status_t run( enum program_mode mode,
                         const char *key_file_name,
                         const char *ladder[], size_t ladder_depth,
                         const char *input_file_name,
                         const char *output_file_name )
{
    psa_status_t status = PSA_SUCCESS;
    psa_key_handle_t derivation_key_handle = 0;
    psa_key_handle_t wrapping_key_handle = 0;

    /* Initialize the PSA crypto library. */
    PSA_CHECK( psa_crypto_init( ) );

    /* Generate mode is unlike the others. Generate the master key and exit. */
    if( mode == MODE_GENERATE )
        return( generate( key_file_name ) );

    /* Read the master key. */
    PSA_CHECK( import_key_from_file( PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT,
                                     KDF_ALG,
                                     key_file_name,
                                     &derivation_key_handle ) );

    /* Calculate the derived key for this session. */
    PSA_CHECK( derive_key_ladder( ladder, ladder_depth,
                                  &derivation_key_handle ) );

    switch( mode )
    {
        case MODE_SAVE:
            PSA_CHECK( save_key( derivation_key_handle, output_file_name ) );
            break;
        case MODE_UNWRAP:
            PSA_CHECK( derive_wrapping_key( PSA_KEY_USAGE_DECRYPT,
                                            derivation_key_handle,
                                            &wrapping_key_handle ) );
            PSA_CHECK( unwrap_data( input_file_name, output_file_name,
                                    wrapping_key_handle ) );
            break;
        case MODE_WRAP:
            PSA_CHECK( derive_wrapping_key( PSA_KEY_USAGE_ENCRYPT,
                                            derivation_key_handle,
                                            &wrapping_key_handle ) );
            PSA_CHECK( wrap_data( input_file_name, output_file_name,
                                  wrapping_key_handle ) );
            break;
        default:
            /* Unreachable but some compilers don't realize it. */
            break;
    }

exit:
    /* Close any remaining key. Deinitializing the crypto library would do
     * this anyway, but explicitly closing handles makes the code easier
     * to reuse. */
    (void) psa_close_key( derivation_key_handle );
    (void) psa_close_key( wrapping_key_handle );
    /* Deinitialize the PSA crypto library. */
    mbedtls_psa_crypto_free( );
    return( status );
}

static void usage( void )
{
    printf( "Usage: key_ladder_demo MODE [OPTION=VALUE]...\n" );
    printf( "Demonstrate the usage of a key derivation ladder.\n" );
    printf( "\n" );
    printf( "Modes:\n" );
    printf( "  generate  Generate the master key\n" );
    printf( "  save      Save the derived key\n" );
    printf( "  unwrap    Unwrap (decrypt) input with the derived key\n" );
    printf( "  wrap      Wrap (encrypt) input with the derived key\n" );
    printf( "\n" );
    printf( "Options:\n" );
    printf( "  input=FILENAME    Input file (required for wrap/unwrap)\n" );
    printf( "  master=FILENAME   File containing the master key (default: master.key)\n" );
    printf( "  output=FILENAME   Output file (required for save/wrap/unwrap)\n" );
    printf( "  label=TEXT        Label for the key derivation.\n" );
    printf( "                    This may be repeated multiple times.\n" );
    printf( "                    To get the same key, you must use the same master key\n" );
    printf( "                    and the same sequence of labels.\n" );
}

#if defined(MBEDTLS_CHECK_PARAMS)
#include "mbedtls/platform_util.h"
void mbedtls_param_failed( const char *failure_condition,
                           const char *file,
                           int line )
{
    printf( "%s:%i: Input param failed - %s\n",
                    file, line, failure_condition );
    exit( EXIT_FAILURE );
}
#endif

int main( int argc, char *argv[] )
{
    const char *key_file_name = "master.key";
    const char *input_file_name = NULL;
    const char *output_file_name = NULL;
    const char *ladder[MAX_LADDER_DEPTH];
    size_t ladder_depth = 0;
    int i;
    enum program_mode mode;
    psa_status_t status;

    if( argc <= 1 ||
        strcmp( argv[1], "help" ) == 0 ||
        strcmp( argv[1], "-help" ) == 0 ||
        strcmp( argv[1], "--help" ) == 0 )
    {
        usage( );
        return( EXIT_SUCCESS );
    }

    for( i = 2; i < argc; i++ )
    {
        char *q = strchr( argv[i], '=' );
        if( q == NULL )
        {
            printf( "Missing argument to option %s\n", argv[i] );
            goto usage_failure;
        }
        *q = 0;
        ++q;
        if( strcmp( argv[i], "input" ) == 0 )
            input_file_name = q;
        else if( strcmp( argv[i], "label" ) == 0 )
        {
            if( ladder_depth == MAX_LADDER_DEPTH )
            {
                printf( "Maximum ladder depth %u exceeded.\n",
                                (unsigned) MAX_LADDER_DEPTH );
                return( EXIT_FAILURE );
            }
            ladder[ladder_depth] = q;
            ++ladder_depth;
        }
        else if( strcmp( argv[i], "master" ) == 0 )
            key_file_name = q;
        else if( strcmp( argv[i], "output" ) == 0 )
            output_file_name = q;
        else
        {
            printf( "Unknown option: %s\n", argv[i] );
            goto usage_failure;
        }
    }

    if( strcmp( argv[1], "generate" ) == 0 )
        mode = MODE_GENERATE;
    else if( strcmp( argv[1], "save" ) == 0 )
        mode = MODE_SAVE;
    else if( strcmp( argv[1], "unwrap" ) == 0 )
        mode = MODE_UNWRAP;
    else if( strcmp( argv[1], "wrap" ) == 0 )
        mode = MODE_WRAP;
    else
    {
        printf( "Unknown action: %s\n", argv[1] );
        goto usage_failure;
    }

    if( input_file_name == NULL &&
        ( mode == MODE_WRAP || mode == MODE_UNWRAP ) )
    {
        printf( "Required argument missing: input\n" );
        return( DEMO_ERROR );
    }
    if( output_file_name == NULL &&
        ( mode == MODE_SAVE || mode == MODE_WRAP || mode == MODE_UNWRAP ) )
    {
        printf( "Required argument missing: output\n" );
        return( DEMO_ERROR );
    }

    status = run( mode, key_file_name,
                  ladder, ladder_depth,
                  input_file_name, output_file_name );
    return( status == PSA_SUCCESS ?
            EXIT_SUCCESS :
            EXIT_FAILURE );

usage_failure:
    usage( );
    return( EXIT_FAILURE );
}
#endif /* MBEDTLS_SHA256_C && MBEDTLS_MD_C && MBEDTLS_AES_C && MBEDTLS_CCM_C && MBEDTLS_PSA_CRYPTO_C && MBEDTLS_FS_IO */
