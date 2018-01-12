/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script: /home/clm/PATCH_mbed/mbedtls/tests/scripts/generate_code.pl
 *
 * Test file      : test_suite_cipher.padding.c
 *
 * The following files were used to create this file.
 *
 *      Main code file  : /home/clm/PATCH_mbed/mbedtls/tests/suites/main_test.function
 *      Helper file     : /home/clm/PATCH_mbed/mbedtls/tests/suites/helpers.function
 *      Test suite file : /home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function
 *      Test suite data : /home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.padding.data
 *
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif


/*----------------------------------------------------------------------------*/
/* Common helper code */

#line 1 "helpers.function"
/*----------------------------------------------------------------------------*/
/* Headers */

#include <stdlib.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#define mbedtls_exit       exit
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT32 uint32_t;
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#else
#include <stdint.h>
#endif

#include <string.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#endif

/*----------------------------------------------------------------------------*/
/* Constants */

#define DEPENDENCY_SUPPORTED        0
#define DEPENDENCY_NOT_SUPPORTED    1

#define KEY_VALUE_MAPPING_FOUND     0
#define KEY_VALUE_MAPPING_NOT_FOUND -1

#define DISPATCH_TEST_SUCCESS       0
#define DISPATCH_TEST_FN_NOT_FOUND  1
#define DISPATCH_INVALID_TEST_DATA  2
#define DISPATCH_UNSUPPORTED_SUITE  3


/*----------------------------------------------------------------------------*/
/* Macros */

#define TEST_ASSERT( TEST )                         \
    do {                                            \
        if( ! (TEST) )                              \
        {                                           \
            test_fail( #TEST, __LINE__, __FILE__ ); \
            goto exit;                              \
        }                                           \
    } while( 0 )

#define assert(a) if( !( a ) )                                      \
{                                                                   \
    mbedtls_fprintf( stderr, "Assertion Failed at %s:%d - %s\n",   \
                             __FILE__, __LINE__, #a );              \
    mbedtls_exit( 1 );                                             \
}

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif


/*----------------------------------------------------------------------------*/
/* Global variables */

static int test_errors = 0;


/*----------------------------------------------------------------------------*/
/* Helper Functions */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
static int redirect_output( FILE** out_stream, const char* path )
{
    int stdout_fd = dup( fileno( *out_stream ) );

    if( stdout_fd == -1 )
    {
        return -1;
    }

    fflush( *out_stream );
    fclose( *out_stream );
    *out_stream = fopen( path, "w" );

    if( *out_stream == NULL )
    {
        return -1;
    }

    return stdout_fd;
}

static int restore_output( FILE** out_stream, int old_fd )
{
    fflush( *out_stream );
    fclose( *out_stream );

    *out_stream = fdopen( old_fd, "w" );
    if( *out_stream == NULL )
    {
        return -1;
    }

    return 0;
}

static void close_output( FILE* out_stream )
{
    fclose( out_stream );
}
#endif /* __unix__ || __APPLE__ __MACH__ */

static int unhexify( unsigned char *obuf, const char *ibuf )
{
    unsigned char c, c2;
    int len = strlen( ibuf ) / 2;
    assert( strlen( ibuf ) % 2 == 0 ); /* must be even number of bytes */

    while( *ibuf != 0 )
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

static void hexify( unsigned char *obuf, const unsigned char *ibuf, int len )
{
    unsigned char l, h;

    while( len != 0 )
    {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

/**
 * Allocate and zeroize a buffer.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
static unsigned char *zero_alloc( size_t len )
{
    void *p;
    size_t actual_len = ( len != 0 ) ? len : 1;

    p = mbedtls_calloc( 1, actual_len );
    assert( p != NULL );

    memset( p, 0x00, actual_len );

    return( p );
}

/**
 * Allocate and fill a buffer from hex data.
 *
 * The buffer is sized exactly as needed. This allows to detect buffer
 * overruns (including overreads) when running the test suite under valgrind.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
static unsigned char *unhexify_alloc( const char *ibuf, size_t *olen )
{
    unsigned char *obuf;

    *olen = strlen( ibuf ) / 2;

    if( *olen == 0 )
        return( zero_alloc( *olen ) );

    obuf = mbedtls_calloc( 1, *olen );
    assert( obuf != NULL );

    (void) unhexify( obuf, ibuf );

    return( obuf );
}

/**
 * This function just returns data from rand().
 * Although predictable and often similar on multiple
 * runs, this does not result in identical random on
 * each run. So do not use this if the results of a
 * test depend on the random data that is generated.
 *
 * rng_state shall be NULL.
 */
static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}

/**
 * This function only returns zeros
 *
 * rng_state shall be NULL.
 */
static int rnd_zero_rand( void *rng_state, unsigned char *output, size_t len )
{
    if( rng_state != NULL )
        rng_state  = NULL;

    memset( output, 0, len );

    return( 0 );
}

typedef struct
{
    unsigned char *buf;
    size_t length;
} rnd_buf_info;

/**
 * This function returns random based on a buffer it receives.
 *
 * rng_state shall be a pointer to a rnd_buf_info structure.
 *
 * The number of bytes released from the buffer on each call to
 * the random function is specified by per_call. (Can be between
 * 1 and 4)
 *
 * After the buffer is empty it will return rand();
 */
static int rnd_buffer_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_buf_info *info = (rnd_buf_info *) rng_state;
    size_t use_len;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    use_len = len;
    if( len > info->length )
        use_len = info->length;

    if( use_len )
    {
        memcpy( output, info->buf, use_len );
        info->buf += use_len;
        info->length -= use_len;
    }

    if( len - use_len > 0 )
        return( rnd_std_rand( NULL, output + use_len, len - use_len ) );

    return( 0 );
}

/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

/**
 * This function returns random based on a pseudo random function.
 * This means the results should be identical on all systems.
 * Pseudo random is based on the XTEA encryption algorithm to
 * generate pseudorandom.
 *
 * rng_state shall be a pointer to a rnd_pseudo_info structure.
 */
static int rnd_pseudo_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_pseudo_info *info = (rnd_pseudo_info *) rng_state;
    uint32_t i, *k, sum, delta=0x9E3779B9;
    unsigned char result[4], *out = output;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    k = info->key;

    while( len > 0 )
    {
        size_t use_len = ( len > 4 ) ? 4 : len;
        sum = 0;

        for( i = 0; i < 32; i++ )
        {
            info->v0 += ( ( ( info->v1 << 4 ) ^ ( info->v1 >> 5 ) )
                            + info->v1 ) ^ ( sum + k[sum & 3] );
            sum += delta;
            info->v1 += ( ( ( info->v0 << 4 ) ^ ( info->v0 >> 5 ) )
                            + info->v0 ) ^ ( sum + k[( sum>>11 ) & 3] );
        }

        PUT_UINT32_BE( info->v0, result, 0 );
        memcpy( out, result, use_len );
        len -= use_len;
        out += 4;
    }

    return( 0 );
}

static void test_fail( const char *test, int line_no, const char* filename )
{
    test_errors++;
    if( test_errors == 1 )
        mbedtls_fprintf( stdout, "FAILED\n" );
    mbedtls_fprintf( stdout, "  %s\n  at line %d, %s\n", test, line_no,
                        filename );
}




/*----------------------------------------------------------------------------*/
/* Test Suite Code */

#if defined(MBEDTLS_CIPHER_C)

#include "mbedtls/cipher.h"

#if defined(MBEDTLS_GCM_C)
#include "mbedtls/gcm.h"
#endif

#endif /* defined(MBEDTLS_CIPHER_C) */


#line 1 "main_test.function"
#if defined(MBEDTLS_CIPHER_C)

#define TEST_SUITE_ACTIVE

int verify_string( char **str )
{
    if( (*str)[0] != '"' ||
        (*str)[strlen( *str ) - 1] != '"' )
    {
        mbedtls_fprintf( stderr,
            "Expected string (with \"\") for parameter and got: %s\n", *str );
        return( -1 );
    }

    (*str)++;
    (*str)[strlen( *str ) - 1] = '\0';

    return( 0 );
}

int verify_int( char *str, int *value )
{
    size_t i;
    int minus = 0;
    int digits = 1;
    int hex = 0;

    for( i = 0; i < strlen( str ); i++ )
    {
        if( i == 0 && str[i] == '-' )
        {
            minus = 1;
            continue;
        }

        if( ( ( minus && i == 2 ) || ( !minus && i == 1 ) ) &&
            str[i - 1] == '0' && str[i] == 'x' )
        {
            hex = 1;
            continue;
        }

        if( ! ( ( str[i] >= '0' && str[i] <= '9' ) ||
                ( hex && ( ( str[i] >= 'a' && str[i] <= 'f' ) ||
                           ( str[i] >= 'A' && str[i] <= 'F' ) ) ) ) )
        {
            digits = 0;
            break;
        }
    }

    if( digits )
    {
        if( hex )
            *value = strtol( str, NULL, 16 );
        else
            *value = strtol( str, NULL, 10 );

        return( 0 );
    }

#ifdef MBEDTLS_CIPHER_MODE_CBC
    if( strcmp( str, "MBEDTLS_PADDING_ONE_AND_ZEROS" ) == 0 )
    {
        *value = ( MBEDTLS_PADDING_ONE_AND_ZEROS );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_CBC
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_CIPHER_AES_128_CTR" ) == 0 )
    {
        *value = ( MBEDTLS_CIPHER_AES_128_CTR );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_CBC
    if( strcmp( str, "MBEDTLS_ERR_CIPHER_INVALID_PADDING" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_CIPHER_INVALID_PADDING );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_CBC
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_CBC
    if( strcmp( str, "MBEDTLS_PADDING_NONE" ) == 0 )
    {
        *value = ( MBEDTLS_PADDING_NONE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_CBC
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_CIPHER_NULL" ) == 0 )
    {
        *value = ( MBEDTLS_CIPHER_NULL );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_CBC
    if( strcmp( str, "MBEDTLS_PADDING_PKCS7" ) == 0 )
    {
        *value = ( MBEDTLS_PADDING_PKCS7 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_CBC
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_PADDING_PKCS7" ) == 0 )
    {
        *value = ( MBEDTLS_PADDING_PKCS7 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_CBC
    if( strcmp( str, "MBEDTLS_PADDING_ZEROS" ) == 0 )
    {
        *value = ( MBEDTLS_PADDING_ZEROS );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_CBC
#ifdef MBEDTLS_CIPHER_MODE_CBC
    if( strcmp( str, "MBEDTLS_PADDING_ZEROS_AND_LEN" ) == 0 )
    {
        *value = ( MBEDTLS_PADDING_ZEROS_AND_LEN );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_CBC
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_CIPHER_BLOWFISH_CTR" ) == 0 )
    {
        *value = ( MBEDTLS_CIPHER_BLOWFISH_CTR );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_CIPHER_DES_CBC" ) == 0 )
    {
        *value = ( MBEDTLS_CIPHER_DES_CBC );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_CIPHER_AES_128_CBC" ) == 0 )
    {
        *value = ( MBEDTLS_CIPHER_AES_128_CBC );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_CIPHER_AES_128_CFB128" ) == 0 )
    {
        *value = ( MBEDTLS_CIPHER_AES_128_CFB128 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_CIPHER_CAMELLIA_128_CTR" ) == 0 )
    {
        *value = ( MBEDTLS_CIPHER_CAMELLIA_128_CTR );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_CIPHER_BLOWFISH_CBC" ) == 0 )
    {
        *value = ( MBEDTLS_CIPHER_BLOWFISH_CBC );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "-1" ) == 0 )
    {
        *value = ( -1 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_CIPHER_BLOWFISH_CFB64" ) == 0 )
    {
        *value = ( MBEDTLS_CIPHER_BLOWFISH_CFB64 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_CIPHER_CAMELLIA_128_CFB128" ) == 0 )
    {
        *value = ( MBEDTLS_CIPHER_CAMELLIA_128_CFB128 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING
#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
    if( strcmp( str, "MBEDTLS_CIPHER_CAMELLIA_128_CBC" ) == 0 )
    {
        *value = ( MBEDTLS_CIPHER_CAMELLIA_128_CBC );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CIPHER_MODE_WITH_PADDING


    mbedtls_fprintf( stderr,
                    "Expected integer for parameter and got: %s\n", str );
    return( KEY_VALUE_MAPPING_NOT_FOUND );
}


/*----------------------------------------------------------------------------*/
/* Test Case code */

#line 15 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function"
void test_suite_mbedtls_cipher_list( )
{
    const int *cipher_type;

    for( cipher_type = mbedtls_cipher_list(); *cipher_type != 0; cipher_type++ )
        TEST_ASSERT( mbedtls_cipher_info_from_type( *cipher_type ) != NULL );

exit:
    return;
}

#line 25 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function"
void test_suite_cipher_null_args( )
{
    mbedtls_cipher_context_t ctx;
    const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type( *( mbedtls_cipher_list() ) );
    unsigned char buf[1] = { 0 };
    size_t olen;

    mbedtls_cipher_init( &ctx );

    TEST_ASSERT( mbedtls_cipher_get_block_size( NULL ) == 0 );
    TEST_ASSERT( mbedtls_cipher_get_block_size( &ctx ) == 0 );

    TEST_ASSERT( mbedtls_cipher_get_cipher_mode( NULL ) == MBEDTLS_MODE_NONE );
    TEST_ASSERT( mbedtls_cipher_get_cipher_mode( &ctx ) == MBEDTLS_MODE_NONE );

    TEST_ASSERT( mbedtls_cipher_get_iv_size( NULL ) == 0 );
    TEST_ASSERT( mbedtls_cipher_get_iv_size( &ctx ) == 0 );

    TEST_ASSERT( mbedtls_cipher_info_from_string( NULL ) == NULL );

    TEST_ASSERT( mbedtls_cipher_setup( &ctx, NULL )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    TEST_ASSERT( mbedtls_cipher_setup( NULL, info )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    TEST_ASSERT( mbedtls_cipher_setkey( NULL, buf, 0, MBEDTLS_ENCRYPT )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    TEST_ASSERT( mbedtls_cipher_setkey( &ctx, buf, 0, MBEDTLS_ENCRYPT )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    TEST_ASSERT( mbedtls_cipher_set_iv( NULL, buf, 0 )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    TEST_ASSERT( mbedtls_cipher_set_iv( &ctx, buf, 0 )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    TEST_ASSERT( mbedtls_cipher_reset( NULL ) == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    TEST_ASSERT( mbedtls_cipher_reset( &ctx ) == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

#if defined(MBEDTLS_GCM_C)
    TEST_ASSERT( mbedtls_cipher_update_ad( NULL, buf, 0 )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    TEST_ASSERT( mbedtls_cipher_update_ad( &ctx, buf, 0 )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
#endif

    TEST_ASSERT( mbedtls_cipher_update( NULL, buf, 0, buf, &olen )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    TEST_ASSERT( mbedtls_cipher_update( &ctx, buf, 0, buf, &olen )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    TEST_ASSERT( mbedtls_cipher_finish( NULL, buf, &olen )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    TEST_ASSERT( mbedtls_cipher_finish( &ctx, buf, &olen )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

#if defined(MBEDTLS_GCM_C)
    TEST_ASSERT( mbedtls_cipher_write_tag( NULL, buf, olen )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    TEST_ASSERT( mbedtls_cipher_write_tag( &ctx, buf, olen )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    TEST_ASSERT( mbedtls_cipher_check_tag( NULL, buf, olen )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    TEST_ASSERT( mbedtls_cipher_check_tag( &ctx, buf, olen )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
#endif

exit:
    return;
}

#ifdef MBEDTLS_AES_C
#line 95 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function"
void test_suite_cipher_special_behaviours( )
{
    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_context_t ctx;
    unsigned char input[32];
    unsigned char output[32];
    unsigned char iv[32];
    size_t olen = 0;

    mbedtls_cipher_init( &ctx );
    memset( input, 0, sizeof( input ) );
    memset( output, 0, sizeof( output ) );
    memset( iv, 0, sizeof( iv ) );

    /* Check and get info structures */
    cipher_info = mbedtls_cipher_info_from_type( MBEDTLS_CIPHER_AES_128_ECB );
    TEST_ASSERT( NULL != cipher_info );

    TEST_ASSERT( 0 == mbedtls_cipher_setup( &ctx, cipher_info ) );

    /* IV too big */
    TEST_ASSERT( mbedtls_cipher_set_iv( &ctx, iv, MBEDTLS_MAX_IV_LENGTH + 1 )
                 == MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE );

    /* IV too small */
    TEST_ASSERT( mbedtls_cipher_set_iv( &ctx, iv, 0 )
                 == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    /* Update ECB with partial block */
    TEST_ASSERT( mbedtls_cipher_update( &ctx, input, 1, output, &olen )
                 == MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED );

exit:
    mbedtls_cipher_free( &ctx );
}
#endif /* MBEDTLS_AES_C */

#line 133 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function"
void test_suite_enc_dec_buf( int cipher_id, char *cipher_string, int key_len,
                  int length_val, int pad_mode )
{
    size_t length = length_val, outlen, total_len, i, block_size;
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char ad[13];
    unsigned char tag[16];
    unsigned char inbuf[64];
    unsigned char encbuf[64];
    unsigned char decbuf[64];

    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_context_t ctx_dec;
    mbedtls_cipher_context_t ctx_enc;

    /*
     * Prepare contexts
     */
    mbedtls_cipher_init( &ctx_dec );
    mbedtls_cipher_init( &ctx_enc );

    memset( key, 0x2a, sizeof( key ) );

    /* Check and get info structures */
    cipher_info = mbedtls_cipher_info_from_type( cipher_id );
    TEST_ASSERT( NULL != cipher_info );
    TEST_ASSERT( mbedtls_cipher_info_from_string( cipher_string ) == cipher_info );

    /* Initialise enc and dec contexts */
    TEST_ASSERT( 0 == mbedtls_cipher_setup( &ctx_dec, cipher_info ) );
    TEST_ASSERT( 0 == mbedtls_cipher_setup( &ctx_enc, cipher_info ) );

    TEST_ASSERT( 0 == mbedtls_cipher_setkey( &ctx_dec, key, key_len, MBEDTLS_DECRYPT ) );
    TEST_ASSERT( 0 == mbedtls_cipher_setkey( &ctx_enc, key, key_len, MBEDTLS_ENCRYPT ) );

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    if( -1 != pad_mode )
    {
        TEST_ASSERT( 0 == mbedtls_cipher_set_padding_mode( &ctx_dec, pad_mode ) );
        TEST_ASSERT( 0 == mbedtls_cipher_set_padding_mode( &ctx_enc, pad_mode ) );
    }
#else
    (void) pad_mode;
#endif /* MBEDTLS_CIPHER_MODE_WITH_PADDING */

    /*
     * Do a few encode/decode cycles
     */
    for( i = 0; i < 3; i++ )
    {
    memset( iv , 0x00 + i, sizeof( iv ) );
    memset( ad, 0x10 + i, sizeof( ad ) );
    memset( inbuf, 0x20 + i, sizeof( inbuf ) );

    memset( encbuf, 0, sizeof( encbuf ) );
    memset( decbuf, 0, sizeof( decbuf ) );
    memset( tag, 0, sizeof( tag ) );

    TEST_ASSERT( 0 == mbedtls_cipher_set_iv( &ctx_dec, iv, sizeof( iv ) ) );
    TEST_ASSERT( 0 == mbedtls_cipher_set_iv( &ctx_enc, iv, sizeof( iv ) ) );

    TEST_ASSERT( 0 == mbedtls_cipher_reset( &ctx_dec ) );
    TEST_ASSERT( 0 == mbedtls_cipher_reset( &ctx_enc ) );

#if defined(MBEDTLS_GCM_C)
    TEST_ASSERT( 0 == mbedtls_cipher_update_ad( &ctx_dec, ad, sizeof( ad ) - i ) );
    TEST_ASSERT( 0 == mbedtls_cipher_update_ad( &ctx_enc, ad, sizeof( ad ) - i ) );
#endif

    block_size = mbedtls_cipher_get_block_size( &ctx_enc );
    TEST_ASSERT( block_size != 0 );

    /* encode length number of bytes from inbuf */
    TEST_ASSERT( 0 == mbedtls_cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
    total_len = outlen;

    TEST_ASSERT( total_len == length ||
                 ( total_len % block_size == 0 &&
                   total_len < length &&
                   total_len + block_size > length ) );

    TEST_ASSERT( 0 == mbedtls_cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
    total_len += outlen;

#if defined(MBEDTLS_GCM_C)
    TEST_ASSERT( 0 == mbedtls_cipher_write_tag( &ctx_enc, tag, sizeof( tag ) ) );
#endif

    TEST_ASSERT( total_len == length ||
                 ( total_len % block_size == 0 &&
                   total_len > length &&
                   total_len <= length + block_size ) );

    /* decode the previously encoded string */
    TEST_ASSERT( 0 == mbedtls_cipher_update( &ctx_dec, encbuf, total_len, decbuf, &outlen ) );
    total_len = outlen;

    TEST_ASSERT( total_len == length ||
                 ( total_len % block_size == 0 &&
                   total_len < length &&
                   total_len + block_size >= length ) );

    TEST_ASSERT( 0 == mbedtls_cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
    total_len += outlen;

#if defined(MBEDTLS_GCM_C)
    TEST_ASSERT( 0 == mbedtls_cipher_check_tag( &ctx_dec, tag, sizeof( tag ) ) );
#endif

    /* check result */
    TEST_ASSERT( total_len == length );
    TEST_ASSERT( 0 == memcmp(inbuf, decbuf, length) );
    }

    /*
     * Done
     */
exit:
    mbedtls_cipher_free( &ctx_dec );
    mbedtls_cipher_free( &ctx_enc );
}

#line 258 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function"
void test_suite_enc_fail( int cipher_id, int pad_mode, int key_len,
               int length_val, int ret )
{
    size_t length = length_val;
    unsigned char key[32];
    unsigned char iv[16];

    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_context_t ctx;

    unsigned char inbuf[64];
    unsigned char encbuf[64];

    size_t outlen = 0;

    memset( key, 0, 32 );
    memset( iv , 0, 16 );

    mbedtls_cipher_init( &ctx );

    memset( inbuf, 5, 64 );
    memset( encbuf, 0, 64 );

    /* Check and get info structures */
    cipher_info = mbedtls_cipher_info_from_type( cipher_id );
    TEST_ASSERT( NULL != cipher_info );

    /* Initialise context */
    TEST_ASSERT( 0 == mbedtls_cipher_setup( &ctx, cipher_info ) );
    TEST_ASSERT( 0 == mbedtls_cipher_setkey( &ctx, key, key_len, MBEDTLS_ENCRYPT ) );
#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    TEST_ASSERT( 0 == mbedtls_cipher_set_padding_mode( &ctx, pad_mode ) );
#else
    (void) pad_mode;
#endif /* MBEDTLS_CIPHER_MODE_WITH_PADDING */
    TEST_ASSERT( 0 == mbedtls_cipher_set_iv( &ctx, iv, 16 ) );
    TEST_ASSERT( 0 == mbedtls_cipher_reset( &ctx ) );
#if defined(MBEDTLS_GCM_C)
    TEST_ASSERT( 0 == mbedtls_cipher_update_ad( &ctx, NULL, 0 ) );
#endif

    /* encode length number of bytes from inbuf */
    TEST_ASSERT( 0 == mbedtls_cipher_update( &ctx, inbuf, length, encbuf, &outlen ) );
    TEST_ASSERT( ret == mbedtls_cipher_finish( &ctx, encbuf + outlen, &outlen ) );

    /* done */
exit:
    mbedtls_cipher_free( &ctx );
}

#line 310 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function"
void test_suite_dec_empty_buf()
{
    unsigned char key[32];
    unsigned char iv[16];

    mbedtls_cipher_context_t ctx_dec;
    const mbedtls_cipher_info_t *cipher_info;

    unsigned char encbuf[64];
    unsigned char decbuf[64];

    size_t outlen = 0;

    memset( key, 0, 32 );
    memset( iv , 0, 16 );

    mbedtls_cipher_init( &ctx_dec );

    memset( encbuf, 0, 64 );
    memset( decbuf, 0, 64 );

    /* Initialise context */
    cipher_info = mbedtls_cipher_info_from_type( MBEDTLS_CIPHER_AES_128_CBC );
    TEST_ASSERT( NULL != cipher_info);

    TEST_ASSERT( 0 == mbedtls_cipher_setup( &ctx_dec, cipher_info ) );

    TEST_ASSERT( 0 == mbedtls_cipher_setkey( &ctx_dec, key, 128, MBEDTLS_DECRYPT ) );

    TEST_ASSERT( 0 == mbedtls_cipher_set_iv( &ctx_dec, iv, 16 ) );

    TEST_ASSERT( 0 == mbedtls_cipher_reset( &ctx_dec ) );

#if defined(MBEDTLS_GCM_C)
    TEST_ASSERT( 0 == mbedtls_cipher_update_ad( &ctx_dec, NULL, 0 ) );
#endif

    /* decode 0-byte string */
    TEST_ASSERT( 0 == mbedtls_cipher_update( &ctx_dec, encbuf, 0, decbuf, &outlen ) );
    TEST_ASSERT( 0 == outlen );
    TEST_ASSERT( MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED == mbedtls_cipher_finish(
                 &ctx_dec, decbuf + outlen, &outlen ) );
    TEST_ASSERT( 0 == outlen );

exit:
    mbedtls_cipher_free( &ctx_dec );
}

#line 360 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function"
void test_suite_enc_dec_buf_multipart( int cipher_id, int key_len, int first_length_val,
                            int second_length_val )
{
    size_t first_length = first_length_val;
    size_t second_length = second_length_val;
    size_t length = first_length + second_length;
    size_t block_size;
    unsigned char key[32];
    unsigned char iv[16];

    mbedtls_cipher_context_t ctx_dec;
    mbedtls_cipher_context_t ctx_enc;
    const mbedtls_cipher_info_t *cipher_info;

    unsigned char inbuf[64];
    unsigned char encbuf[64];
    unsigned char decbuf[64];

    size_t outlen = 0;
    size_t totaloutlen = 0;

    memset( key, 0, 32 );
    memset( iv , 0, 16 );

    mbedtls_cipher_init( &ctx_dec );
    mbedtls_cipher_init( &ctx_enc );

    memset( inbuf, 5, 64 );
    memset( encbuf, 0, 64 );
    memset( decbuf, 0, 64 );

    /* Initialise enc and dec contexts */
    cipher_info = mbedtls_cipher_info_from_type( cipher_id );
    TEST_ASSERT( NULL != cipher_info);

    TEST_ASSERT( 0 == mbedtls_cipher_setup( &ctx_dec, cipher_info ) );
    TEST_ASSERT( 0 == mbedtls_cipher_setup( &ctx_enc, cipher_info ) );

    TEST_ASSERT( 0 == mbedtls_cipher_setkey( &ctx_dec, key, key_len, MBEDTLS_DECRYPT ) );
    TEST_ASSERT( 0 == mbedtls_cipher_setkey( &ctx_enc, key, key_len, MBEDTLS_ENCRYPT ) );

    TEST_ASSERT( 0 == mbedtls_cipher_set_iv( &ctx_dec, iv, 16 ) );
    TEST_ASSERT( 0 == mbedtls_cipher_set_iv( &ctx_enc, iv, 16 ) );

    TEST_ASSERT( 0 == mbedtls_cipher_reset( &ctx_dec ) );
    TEST_ASSERT( 0 == mbedtls_cipher_reset( &ctx_enc ) );

#if defined(MBEDTLS_GCM_C)
    TEST_ASSERT( 0 == mbedtls_cipher_update_ad( &ctx_dec, NULL, 0 ) );
    TEST_ASSERT( 0 == mbedtls_cipher_update_ad( &ctx_enc, NULL, 0 ) );
#endif

    block_size = mbedtls_cipher_get_block_size( &ctx_enc );
    TEST_ASSERT( block_size != 0 );

    /* encode length number of bytes from inbuf */
    TEST_ASSERT( 0 == mbedtls_cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
    totaloutlen = outlen;
    TEST_ASSERT( 0 == mbedtls_cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
    totaloutlen += outlen;
    TEST_ASSERT( totaloutlen == length ||
                 ( totaloutlen % block_size == 0 &&
                   totaloutlen < length &&
                   totaloutlen + block_size > length ) );

    TEST_ASSERT( 0 == mbedtls_cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
    totaloutlen += outlen;
    TEST_ASSERT( totaloutlen == length ||
                 ( totaloutlen % block_size == 0 &&
                   totaloutlen > length &&
                   totaloutlen <= length + block_size ) );

    /* decode the previously encoded string */
    TEST_ASSERT( 0 == mbedtls_cipher_update( &ctx_dec, encbuf, totaloutlen, decbuf, &outlen ) );
    totaloutlen = outlen;

    TEST_ASSERT( totaloutlen == length ||
                 ( totaloutlen % block_size == 0 &&
                   totaloutlen < length &&
                   totaloutlen + block_size >= length ) );

    TEST_ASSERT( 0 == mbedtls_cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
    totaloutlen += outlen;

    TEST_ASSERT( totaloutlen == length );

    TEST_ASSERT( 0 == memcmp(inbuf, decbuf, length) );

exit:
    mbedtls_cipher_free( &ctx_dec );
    mbedtls_cipher_free( &ctx_enc );
}

#line 455 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function"
void test_suite_decrypt_test_vec( int cipher_id, int pad_mode,
                       char *hex_key, char *hex_iv,
                       char *hex_cipher, char *hex_clear,
                       char *hex_ad, char *hex_tag,
                       int finish_result, int tag_result )
{
    unsigned char key[50];
    unsigned char iv[50];
    unsigned char cipher[200];
    unsigned char clear[200];
    unsigned char ad[200];
    unsigned char tag[20];
    size_t key_len, iv_len, cipher_len, clear_len;
#if defined(MBEDTLS_GCM_C)
    size_t ad_len, tag_len;
#endif
    mbedtls_cipher_context_t ctx;
    unsigned char output[200];
    size_t outlen, total_len;

    mbedtls_cipher_init( &ctx );

    memset( key, 0x00, sizeof( key ) );
    memset( iv, 0x00, sizeof( iv ) );
    memset( cipher, 0x00, sizeof( cipher ) );
    memset( clear, 0x00, sizeof( clear ) );
    memset( ad, 0x00, sizeof( ad ) );
    memset( tag, 0x00, sizeof( tag ) );
    memset( output, 0x00, sizeof( output ) );

    key_len = unhexify( key, hex_key );
    iv_len = unhexify( iv, hex_iv );
    cipher_len = unhexify( cipher, hex_cipher );
    clear_len = unhexify( clear, hex_clear );
#if defined(MBEDTLS_GCM_C)
    ad_len = unhexify( ad, hex_ad );
    tag_len = unhexify( tag, hex_tag );
#else
    ((void) hex_ad);
    ((void) hex_tag);
#endif

    /* Prepare context */
    TEST_ASSERT( 0 == mbedtls_cipher_setup( &ctx,
                                       mbedtls_cipher_info_from_type( cipher_id ) ) );
    TEST_ASSERT( 0 == mbedtls_cipher_setkey( &ctx, key, 8 * key_len, MBEDTLS_DECRYPT ) );
#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    if( pad_mode != -1 )
        TEST_ASSERT( 0 == mbedtls_cipher_set_padding_mode( &ctx, pad_mode ) );
#else
    (void) pad_mode;
#endif /* MBEDTLS_CIPHER_MODE_WITH_PADDING */
    TEST_ASSERT( 0 == mbedtls_cipher_set_iv( &ctx, iv, iv_len ) );
    TEST_ASSERT( 0 == mbedtls_cipher_reset( &ctx ) );
#if defined(MBEDTLS_GCM_C)
    TEST_ASSERT( 0 == mbedtls_cipher_update_ad( &ctx, ad, ad_len ) );
#endif

    /* decode buffer and check tag */
    total_len = 0;
    TEST_ASSERT( 0 == mbedtls_cipher_update( &ctx, cipher, cipher_len, output, &outlen ) );
    total_len += outlen;
    TEST_ASSERT( finish_result == mbedtls_cipher_finish( &ctx, output + outlen,
                                                 &outlen ) );
    total_len += outlen;
#if defined(MBEDTLS_GCM_C)
    TEST_ASSERT( tag_result == mbedtls_cipher_check_tag( &ctx, tag, tag_len ) );
#endif

    /* check plaintext only if everything went fine */
    if( 0 == finish_result && 0 == tag_result )
    {
        TEST_ASSERT( total_len == clear_len );
        TEST_ASSERT( 0 == memcmp( output, clear, clear_len ) );
    }

exit:
    mbedtls_cipher_free( &ctx );
}

#ifdef MBEDTLS_CIPHER_MODE_AEAD
#line 537 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function"
void test_suite_auth_crypt_tv( int cipher_id, char *hex_key, char *hex_iv,
                    char *hex_ad, char *hex_cipher,
                    char *hex_tag, char *hex_clear )
{
    int ret;
    unsigned char key[50];
    unsigned char iv[50];
    unsigned char cipher[200];
    unsigned char clear[200];
    unsigned char ad[200];
    unsigned char tag[20];
    unsigned char my_tag[20];
    size_t key_len, iv_len, cipher_len, clear_len, ad_len, tag_len;
    mbedtls_cipher_context_t ctx;
    unsigned char output[200];
    size_t outlen;

    mbedtls_cipher_init( &ctx );

    memset( key,    0x00, sizeof( key    ) );
    memset( iv,     0x00, sizeof( iv     ) );
    memset( cipher, 0x00, sizeof( cipher ) );
    memset( clear,  0x00, sizeof( clear  ) );
    memset( ad,     0x00, sizeof( ad     ) );
    memset( tag,    0x00, sizeof( tag    ) );
    memset( my_tag, 0xFF, sizeof( my_tag ) );
    memset( output, 0xFF, sizeof( output ) );

    key_len     = unhexify( key,    hex_key     );
    iv_len      = unhexify( iv,     hex_iv      );
    cipher_len  = unhexify( cipher, hex_cipher  );
    ad_len      = unhexify( ad,     hex_ad      );
    tag_len     = unhexify( tag,    hex_tag     );

    /* Prepare context */
    TEST_ASSERT( 0 == mbedtls_cipher_setup( &ctx,
                                       mbedtls_cipher_info_from_type( cipher_id ) ) );
    TEST_ASSERT( 0 == mbedtls_cipher_setkey( &ctx, key, 8 * key_len, MBEDTLS_DECRYPT ) );

    /* decode buffer and check tag */
    ret = mbedtls_cipher_auth_decrypt( &ctx, iv, iv_len, ad, ad_len,
                               cipher, cipher_len, output, &outlen,
                               tag, tag_len );

    /* make sure we didn't overwrite */
    TEST_ASSERT( output[outlen + 0] == 0xFF );
    TEST_ASSERT( output[outlen + 1] == 0xFF );

    /* make sure the message is rejected if it should be */
    if( strcmp( hex_clear, "FAIL" ) == 0 )
    {
        TEST_ASSERT( ret == MBEDTLS_ERR_CIPHER_AUTH_FAILED );
        goto exit;
    }

    /* otherwise, make sure it was decrypted properly */
    TEST_ASSERT( ret == 0 );

    clear_len = unhexify( clear,  hex_clear   );
    TEST_ASSERT( outlen == clear_len );
    TEST_ASSERT( memcmp( output, clear, clear_len ) == 0 );

    /* then encrypt the clear and make sure we get the same ciphertext and tag */
    memset( output, 0xFF, sizeof( output ) );
    outlen = 0;

    ret = mbedtls_cipher_auth_encrypt( &ctx, iv, iv_len, ad, ad_len,
                               clear, clear_len, output, &outlen,
                               my_tag, tag_len );
    TEST_ASSERT( ret == 0 );

    TEST_ASSERT( outlen == clear_len );
    TEST_ASSERT( memcmp( output, cipher, clear_len ) == 0 );
    TEST_ASSERT( memcmp( my_tag, tag, tag_len ) == 0 );

    /* make sure we didn't overwrite */
    TEST_ASSERT( output[outlen + 0] == 0xFF );
    TEST_ASSERT( output[outlen + 1] == 0xFF );
    TEST_ASSERT( my_tag[tag_len + 0] == 0xFF );
    TEST_ASSERT( my_tag[tag_len + 1] == 0xFF );


exit:
    mbedtls_cipher_free( &ctx );
}
#endif /* MBEDTLS_CIPHER_MODE_AEAD */

#line 625 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function"
void test_suite_test_vec_ecb( int cipher_id, int operation, char *hex_key,
                   char *hex_input, char *hex_result,
                   int finish_result )
{
    unsigned char key[50];
    unsigned char input[16];
    unsigned char result[16];
    size_t key_len;
    mbedtls_cipher_context_t ctx;
    unsigned char output[32];
    size_t outlen;

    mbedtls_cipher_init( &ctx );

    memset( key, 0x00, sizeof( key ) );
    memset( input, 0x00, sizeof( input ) );
    memset( result, 0x00, sizeof( result ) );
    memset( output, 0x00, sizeof( output ) );

    /* Prepare context */
    TEST_ASSERT( 0 == mbedtls_cipher_setup( &ctx,
                                       mbedtls_cipher_info_from_type( cipher_id ) ) );

    key_len = unhexify( key, hex_key );
    TEST_ASSERT( unhexify( input, hex_input ) ==
                 (int) mbedtls_cipher_get_block_size( &ctx ) );
    TEST_ASSERT( unhexify( result, hex_result ) ==
                 (int) mbedtls_cipher_get_block_size( &ctx ) );

    TEST_ASSERT( 0 == mbedtls_cipher_setkey( &ctx, key, 8 * key_len, operation ) );

    TEST_ASSERT( 0 == mbedtls_cipher_update( &ctx, input,
                                     mbedtls_cipher_get_block_size( &ctx ),
                                     output, &outlen ) );
    TEST_ASSERT( outlen == mbedtls_cipher_get_block_size( &ctx ) );
    TEST_ASSERT( finish_result == mbedtls_cipher_finish( &ctx, output + outlen,
                                                 &outlen ) );
    TEST_ASSERT( 0 == outlen );

    /* check plaintext only if everything went fine */
    if( 0 == finish_result )
        TEST_ASSERT( 0 == memcmp( output, result,
                                  mbedtls_cipher_get_block_size( &ctx ) ) );

exit:
    mbedtls_cipher_free( &ctx );
}

#ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING
#line 675 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function"
void test_suite_set_padding( int cipher_id, int pad_mode, int ret )
{
    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_context_t ctx;

    mbedtls_cipher_init( &ctx );

    cipher_info = mbedtls_cipher_info_from_type( cipher_id );
    TEST_ASSERT( NULL != cipher_info );
    TEST_ASSERT( 0 == mbedtls_cipher_setup( &ctx, cipher_info ) );

    TEST_ASSERT( ret == mbedtls_cipher_set_padding_mode( &ctx, pad_mode ) );

exit:
    mbedtls_cipher_free( &ctx );
}
#endif /* MBEDTLS_CIPHER_MODE_WITH_PADDING */

#ifdef MBEDTLS_CIPHER_MODE_CBC
#line 694 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function"
void test_suite_check_padding( int pad_mode, char *input_str, int ret, int dlen_check )
{
    mbedtls_cipher_info_t cipher_info;
    mbedtls_cipher_context_t ctx;
    unsigned char input[16];
    size_t ilen, dlen;

    /* build a fake context just for getting access to get_padding */
    mbedtls_cipher_init( &ctx );
    cipher_info.mode = MBEDTLS_MODE_CBC;
    ctx.cipher_info = &cipher_info;

    TEST_ASSERT( 0 == mbedtls_cipher_set_padding_mode( &ctx, pad_mode ) );

    ilen = unhexify( input, input_str );

    TEST_ASSERT( ret == ctx.get_padding( input, ilen, &dlen ) );
    if( 0 == ret )
        TEST_ASSERT( dlen == (size_t) dlen_check );

exit:
    return;
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#ifdef MBEDTLS_CIPHER_MODE_GCM
#line 717 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.function"
void test_suite_check_gcm_multiple_encryption( int cipher_id, char *hex_key, char *hex_iv )
{
    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_context_t ctx;
    unsigned char key[128];
    unsigned char iv[96];
    unsigned char buffer0[1024];
    unsigned char buffer1[1040];
    unsigned char *current, *end;
    size_t key_len, iv_len, buffer1_len, buffer0_len, len;    
    
    mbedtls_cipher_init( &ctx );
    
    cipher_info = mbedtls_cipher_info_from_type( cipher_id );
    TEST_ASSERT( NULL != cipher_info );
    
    memset( key, 0x00, sizeof( key ) );
    memset( iv, 0x00, sizeof( iv ) );
    memset( buffer1, 0x10, sizeof( buffer1 ) );
    memset( buffer0, 0x10, sizeof( buffer0 ) );
    
    key_len = unhexify( key, hex_key );
    iv_len = unhexify( iv, hex_iv );

    
    /* Set encryption key for the context */
    TEST_ASSERT( 0 == mbedtls_cipher_setup( &ctx, cipher_info ) );
    TEST_ASSERT( 0 == mbedtls_cipher_setkey( &ctx, key, key_len * 8, MBEDTLS_ENCRYPT ) );
    
    /* Prepare context for full encryption */
    TEST_ASSERT( 0 == mbedtls_cipher_set_iv( &ctx, iv, iv_len ) );
    TEST_ASSERT( 0 == mbedtls_cipher_update_ad( &ctx, NULL, 0 ) );
    
    TEST_ASSERT( 0 == mbedtls_cipher_update( &ctx, buffer0, 1024, buffer0, &buffer0_len ) );
    

    /* Reprepare context for full encryption */
    TEST_ASSERT( 0 == mbedtls_cipher_set_iv( &ctx, iv, 12 ) );
    TEST_ASSERT( 0 == mbedtls_cipher_update_ad( &ctx, NULL, 0 ) );
        
    /* now loop over short lengths until input is encrypted */
    current = buffer1;
    end = buffer1 + 1024;
    buffer1_len = 0;
    while ( current < end ) { 
        /* choose a short length */
        len = rand() & 0x01f;
        /* make sure that len doesn't cause us to overreach the buffer */
        if ( current + len > end )
	        len = end - current;

        TEST_ASSERT( 0 == mbedtls_cipher_update( &ctx, current, len, current, &len ) );

        /* advance pointer into input and output2 to reflect encryption */
        current += len;
        buffer1_len += len;
      
        /* if buffer1 is all encrypted, break out of loop */
        if ( current == end )
	        break;
    }
    
    TEST_ASSERT( buffer0_len == buffer1_len );
    TEST_ASSERT( 0 == memcmp( buffer0, buffer1, buffer1_len ) );
    
exit:
    mbedtls_cipher_free( &ctx );
}
#endif /* MBEDTLS_CIPHER_MODE_GCM */


#endif /* defined(MBEDTLS_CIPHER_C) */


#line 77 "main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */

int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS" ) == 0 )
    {
#if defined(MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_CIPHER_MODE_CBC" ) == 0 )
    {
#if defined(MBEDTLS_CIPHER_MODE_CBC)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_CAMELLIA_C" ) == 0 )
    {
#if defined(MBEDTLS_CAMELLIA_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_CIPHER_MODE_CTR" ) == 0 )
    {
#if defined(MBEDTLS_CIPHER_MODE_CTR)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_BLOWFISH_C" ) == 0 )
    {
#if defined(MBEDTLS_BLOWFISH_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_DES_C" ) == 0 )
    {
#if defined(MBEDTLS_DES_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN" ) == 0 )
    {
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_CIPHER_MODE_CFB" ) == 0 )
    {
#if defined(MBEDTLS_CIPHER_MODE_CFB)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_AES_C" ) == 0 )
    {
#if defined(MBEDTLS_AES_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_CIPHER_PADDING_ZEROS" ) == 0 )
    {
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_CIPHER_NULL_CIPHER" ) == 0 )
    {
#if defined(MBEDTLS_CIPHER_NULL_CIPHER)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_CIPHER_PADDING_PKCS7" ) == 0 )
    {
#if defined(MBEDTLS_CIPHER_PADDING_PKCS7)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }

#line 89 "main_test.function"

    return( DEPENDENCY_NOT_SUPPORTED );
}

int dispatch_test(int cnt, char *params[50])
{
    int ret;
    ((void) cnt);
    ((void) params);

#if defined(TEST_SUITE_ACTIVE)
    ret = DISPATCH_TEST_SUCCESS;

    // Cast to void to avoid compiler warnings
    (void)ret;

    if( strcmp( params[0], "mbedtls_cipher_list" ) == 0 )
    {


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_mbedtls_cipher_list(  );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "cipher_null_args" ) == 0 )
    {


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_cipher_null_args(  );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "cipher_special_behaviours" ) == 0 )
    {
    #ifdef MBEDTLS_AES_C


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_cipher_special_behaviours(  );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_AES_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "enc_dec_buf" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        int param5;

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_enc_dec_buf( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "enc_fail" ) == 0 )
    {

        int param1;
        int param2;
        int param3;
        int param4;
        int param5;

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_enc_fail( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "dec_empty_buf" ) == 0 )
    {


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_dec_empty_buf(  );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "enc_dec_buf_multipart" ) == 0 )
    {

        int param1;
        int param2;
        int param3;
        int param4;

        if( cnt != 5 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_enc_dec_buf_multipart( param1, param2, param3, param4 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "decrypt_test_vec" ) == 0 )
    {

        int param1;
        int param2;
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        char *param6 = params[6];
        char *param7 = params[7];
        char *param8 = params[8];
        int param9;
        int param10;

        if( cnt != 11 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 11 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[10], &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_decrypt_test_vec( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "auth_crypt_tv" ) == 0 )
    {
    #ifdef MBEDTLS_CIPHER_MODE_AEAD

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        char *param6 = params[6];
        char *param7 = params[7];

        if( cnt != 8 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_auth_crypt_tv( param1, param2, param3, param4, param5, param6, param7 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_CIPHER_MODE_AEAD */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "test_vec_ecb" ) == 0 )
    {

        int param1;
        int param2;
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        int param6;

        if( cnt != 7 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_test_vec_ecb( param1, param2, param3, param4, param5, param6 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "set_padding" ) == 0 )
    {
    #ifdef MBEDTLS_CIPHER_MODE_WITH_PADDING

        int param1;
        int param2;
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_set_padding( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_CIPHER_MODE_WITH_PADDING */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "check_padding" ) == 0 )
    {
    #ifdef MBEDTLS_CIPHER_MODE_CBC

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;

        if( cnt != 5 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_check_padding( param1, param2, param3, param4 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_CIPHER_MODE_CBC */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "check_gcm_multiple_encryption" ) == 0 )
    {
    #ifdef MBEDTLS_CIPHER_MODE_GCM

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_check_gcm_multiple_encryption( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_CIPHER_MODE_GCM */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else

    {
#line 108 "main_test.function"
        mbedtls_fprintf( stdout,
                         "FAILED\nSkipping unknown test function '%s'\n",
                         params[0] );
        fflush( stdout );
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }
#else
    ret = DISPATCH_UNSUPPORTED_SUITE;
#endif
    return( ret );
}


/*----------------------------------------------------------------------------*/
/* Main Test code */

#line 125 "main_test.function"

#define USAGE \
    "Usage: %s [OPTIONS] files...\n\n" \
    "   Command line arguments:\n" \
    "     files...          One or more test data file. If no file is specified\n" \
    "                       the followimg default test case is used:\n" \
    "                           %s\n\n" \
    "   Options:\n" \
    "     -v | --verbose    Display full information about each test\n" \
    "     -h | --help       Display this information\n\n", \
    argv[0], \
    "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.padding.data"


int get_line( FILE *f, char *buf, size_t len )
{
    char *ret;

    ret = fgets( buf, len, f );
    if( ret == NULL )
        return( -1 );

    if( strlen( buf ) && buf[strlen(buf) - 1] == '\n' )
        buf[strlen(buf) - 1] = '\0';
    if( strlen( buf ) && buf[strlen(buf) - 1] == '\r' )
        buf[strlen(buf) - 1] = '\0';

    return( 0 );
}

int parse_arguments( char *buf, size_t len, char *params[50] )
{
    int cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while( *p != '\0' && p < buf + len )
    {
        if( *p == '\\' )
        {
            p++;
            p++;
            continue;
        }
        if( *p == ':' )
        {
            if( p + 1 < buf + len )
            {
                cur = p + 1;
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    /* Replace newlines, question marks and colons in strings */
    for( i = 0; i < cnt; i++ )
    {
        p = params[i];
        q = params[i];

        while( *p != '\0' )
        {
            if( *p == '\\' && *(p + 1) == 'n' )
            {
                p += 2;
                *(q++) = '\n';
            }
            else if( *p == '\\' && *(p + 1) == ':' )
            {
                p += 2;
                *(q++) = ':';
            }
            else if( *p == '\\' && *(p + 1) == '?' )
            {
                p += 2;
                *(q++) = '?';
            }
            else
                *(q++) = *(p++);
        }
        *q = '\0';
    }

    return( cnt );
}

static int test_snprintf( size_t n, const char ref_buf[10], int ref_ret )
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    ret = mbedtls_snprintf( buf, n, "%s", "123" );
    if( ret < 0 || (size_t) ret >= n )
        ret = -1;

    if( strncmp( ref_buf, buf, sizeof( buf ) ) != 0 ||
        ref_ret != ret ||
        memcmp( buf + n, ref + n, sizeof( buf ) - n ) != 0 )
    {
        return( 1 );
    }

    return( 0 );
}

static int run_test_snprintf( void )
{
    return( test_snprintf( 0, "xxxxxxxxx",  -1 ) != 0 ||
            test_snprintf( 1, "",           -1 ) != 0 ||
            test_snprintf( 2, "1",          -1 ) != 0 ||
            test_snprintf( 3, "12",         -1 ) != 0 ||
            test_snprintf( 4, "123",         3 ) != 0 ||
            test_snprintf( 5, "123",         3 ) != 0 );
}

int main(int argc, const char *argv[])
{
    /* Local Configurations and options */
    const char *default_filename = "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_cipher.padding.data";
    const char *test_filename = NULL;
    const char **test_files = NULL;
    int testfile_count = 0;
    int option_verbose = 0;

    /* Other Local variables */
    int arg_index = 1;
    const char *next_arg;
    int testfile_index, ret, i, cnt;
    int total_errors = 0, total_tests = 0, total_skipped = 0;
    FILE *file;
    char buf[5000];
    char *params[50];
    void *pointer;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    int stdout_fd = -1;
#endif /* __unix__ || __APPLE__ __MACH__ */

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
    unsigned char alloc_buf[1000000];
    mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset( &pointer, 0, sizeof( void * ) );
    if( pointer != NULL )
    {
        mbedtls_fprintf( stderr, "all-bits-zero is not a NULL pointer\n" );
        return( 1 );
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
    if( run_test_snprintf() != 0 )
    {
        mbedtls_fprintf( stderr, "the snprintf implementation is broken\n" );
        return( 0 );
    }

    while( arg_index < argc)
    {
        next_arg = argv[ arg_index ];

        if( strcmp(next_arg, "--verbose" ) == 0 ||
                 strcmp(next_arg, "-v" ) == 0 )
        {
            option_verbose = 1;
        }
        else if( strcmp(next_arg, "--help" ) == 0 ||
                 strcmp(next_arg, "-h" ) == 0 )
        {
            mbedtls_fprintf( stdout, USAGE );
            mbedtls_exit( EXIT_SUCCESS );
        }
        else
        {
            /* Not an option, therefore treat all further arguments as the file
             * list.
             */
            test_files = &argv[ arg_index ];
            testfile_count = argc - arg_index;
        }

        arg_index++;
    }

    /* If no files were specified, assume a default */
    if ( test_files == NULL || testfile_count == 0 )
    {
        test_files = &default_filename;
        testfile_count = 1;
    }

    /* Now begin to execute the tests in the testfiles */
    for ( testfile_index = 0;
          testfile_index < testfile_count;
          testfile_index++ )
    {
        int unmet_dep_count = 0;
        char *unmet_dependencies[20];

        test_filename = test_files[ testfile_index ];

        file = fopen( test_filename, "r" );
        if( file == NULL )
        {
            mbedtls_fprintf( stderr, "Failed to open test file: %s\n",
                             test_filename );
            return( 1 );
        }

        while( !feof( file ) )
        {
            if( unmet_dep_count > 0 )
            {
                mbedtls_fprintf( stderr,
                    "FATAL: Dep count larger than zero at start of loop\n" );
                mbedtls_exit( MBEDTLS_EXIT_FAILURE );
            }
            unmet_dep_count = 0;

            if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                break;
            mbedtls_fprintf( stdout, "%s%.66s", test_errors ? "\n" : "", buf );
            mbedtls_fprintf( stdout, " " );
            for( i = strlen( buf ) + 1; i < 67; i++ )
                mbedtls_fprintf( stdout, "." );
            mbedtls_fprintf( stdout, " " );
            fflush( stdout );

            total_tests++;

            if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                break;
            cnt = parse_arguments( buf, strlen(buf), params );

            if( strcmp( params[0], "depends_on" ) == 0 )
            {
                for( i = 1; i < cnt; i++ )
                {
                    if( dep_check( params[i] ) != DEPENDENCY_SUPPORTED )
                    {
                        if( 0 == option_verbose )
                        {
                            /* Only one count is needed if not verbose */
                            unmet_dep_count++;
                            break;
                        }

                        unmet_dependencies[ unmet_dep_count ] = strdup(params[i]);
                        if(  unmet_dependencies[ unmet_dep_count ] == NULL )
                        {
                            mbedtls_fprintf( stderr, "FATAL: Out of memory\n" );
                            mbedtls_exit( MBEDTLS_EXIT_FAILURE );
                        }
                        unmet_dep_count++;
                    }
                }

                if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                    break;
                cnt = parse_arguments( buf, strlen(buf), params );
            }
 
            // If there are no unmet dependencies execute the test
            if( unmet_dep_count == 0 )
            {
                test_errors = 0;

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                /* Suppress all output from the library unless we're verbose
                 * mode
                 */
                if( !option_verbose )
                {
                    stdout_fd = redirect_output( &stdout, "/dev/null" );
                    if( stdout_fd == -1 )
                    {
                        /* Redirection has failed with no stdout so exit */
                        exit( 1 );
                    }
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

                ret = dispatch_test( cnt, params );

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                if( !option_verbose && restore_output( &stdout, stdout_fd ) )
                {
                        /* Redirection has failed with no stdout so exit */
                        exit( 1 );
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

            }

            if( unmet_dep_count > 0 || ret == DISPATCH_UNSUPPORTED_SUITE )
            {
                total_skipped++;
                mbedtls_fprintf( stdout, "----\n" );

                if( 1 == option_verbose && ret == DISPATCH_UNSUPPORTED_SUITE )
                {
                    mbedtls_fprintf( stdout, "   Test Suite not enabled" );
                }

                if( 1 == option_verbose && unmet_dep_count > 0 )
                {
                    mbedtls_fprintf( stdout, "   Unmet dependencies: " );
                    for( i = 0; i < unmet_dep_count; i++ )
                    {
                        mbedtls_fprintf(stdout, "%s  ",
                                        unmet_dependencies[i]);
                        free(unmet_dependencies[i]);
                    }
                    mbedtls_fprintf( stdout, "\n" );
                }
                fflush( stdout );

                unmet_dep_count = 0;
            }
            else if( ret == DISPATCH_TEST_SUCCESS && test_errors == 0 )
            {
                mbedtls_fprintf( stdout, "PASS\n" );
                fflush( stdout );
            }
            else if( ret == DISPATCH_INVALID_TEST_DATA )
            {
                mbedtls_fprintf( stderr, "FAILED: FATAL PARSE ERROR\n" );
                fclose(file);
                mbedtls_exit( 2 );
            }
            else
                total_errors++;

            if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                break;
            if( strlen(buf) != 0 )
            {
                mbedtls_fprintf( stderr, "Should be empty %d\n",
                                 (int) strlen(buf) );
                return( 1 );
            }
        }
        fclose(file);

        /* In case we encounter early end of file */
        for( i = 0; i < unmet_dep_count; i++ )
            free( unmet_dependencies[i] );
    }

    mbedtls_fprintf( stdout, "\n----------------------------------------------------------------------------\n\n");
    if( total_errors == 0 )
        mbedtls_fprintf( stdout, "PASSED" );
    else
        mbedtls_fprintf( stdout, "FAILED" );

    mbedtls_fprintf( stdout, " (%d / %d tests (%d skipped))\n",
             total_tests - total_errors, total_tests, total_skipped );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#if defined(MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_status();
#endif
    mbedtls_memory_buffer_alloc_free();
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    if( stdout_fd != -1 )
        close_output( stdout );
#endif /* __unix__ || __APPLE__ __MACH__ */

    return( total_errors != 0 );
}


