/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script: /Users/alessandrobudroni/Dev/milagro-mbedtls/tests/scripts/generate_code.pl
 *
 * Test file      : test_suite_pk.c
 *
 * The following files were used to create this file.
 *
 *      Main code file  : /Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/main_test.function
 *      Helper file     : /Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/helpers.function
 *      Test suite file : /Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.function
 *      Test suite data : /Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.data
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

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#define mbedtls_exit       exit
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
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
        mbedtls_printf( "FAILED\n" );
    mbedtls_printf( "  %s\n  at line %d, %s\n", test, line_no, filename );
}




/*----------------------------------------------------------------------------*/
/* Test Suite Code */

#if defined(MBEDTLS_PK_C)

#include "mbedtls/pk.h"

/* For error codes */
#include "mbedtls/ecp.h"
#include "mbedtls/rsa.h"

static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len );

#define RSA_KEY_SIZE 512
#define RSA_KEY_LEN   64

static int pk_genkey( mbedtls_pk_context *pk )
{
    ((void) pk);

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if( mbedtls_pk_get_type( pk ) == MBEDTLS_PK_RSA )
        return mbedtls_rsa_gen_key( mbedtls_pk_rsa( *pk ), rnd_std_rand, NULL, RSA_KEY_SIZE, 3 );
#endif
#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( pk ) == MBEDTLS_PK_ECKEY ||
        mbedtls_pk_get_type( pk ) == MBEDTLS_PK_ECKEY_DH ||
        mbedtls_pk_get_type( pk ) == MBEDTLS_PK_ECDSA )
    {
        int ret;
        if( ( ret = mbedtls_ecp_group_load( &mbedtls_pk_ec( *pk )->grp,
                                      MBEDTLS_ECP_DP_SECP192R1 ) ) != 0 )
            return( ret );

        return mbedtls_ecp_gen_keypair( &mbedtls_pk_ec( *pk )->grp, &mbedtls_pk_ec( *pk )->d,
                                &mbedtls_pk_ec( *pk )->Q, rnd_std_rand, NULL );
    }
#endif
    return( -1 );
}

#if defined(MBEDTLS_RSA_C)
int mbedtls_rsa_decrypt_func( void *ctx, int mode, size_t *olen,
                       const unsigned char *input, unsigned char *output,
                       size_t output_max_len )
{
    return( mbedtls_rsa_pkcs1_decrypt( (mbedtls_rsa_context *) ctx, NULL, NULL, mode, olen,
                               input, output, output_max_len ) );
}
int mbedtls_rsa_sign_func( void *ctx,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                   int mode, mbedtls_md_type_t md_alg, unsigned int hashlen,
                   const unsigned char *hash, unsigned char *sig )
{
    return( mbedtls_rsa_pkcs1_sign( (mbedtls_rsa_context *) ctx, f_rng, p_rng, mode,
                            md_alg, hashlen, hash, sig ) );
}
size_t mbedtls_rsa_key_len_func( void *ctx )
{
    return( ((const mbedtls_rsa_context *) ctx)->len );
}
#endif /* MBEDTLS_RSA_C */

#endif /* defined(MBEDTLS_PK_C) */


#line 1 "main_test.function"
#if defined(MBEDTLS_PK_C)

#define TEST_SUITE_ACTIVE

int verify_string( char **str )
{
    if( (*str)[0] != '"' ||
        (*str)[strlen( *str ) - 1] != '"' )
    {
        mbedtls_printf( "Expected string (with \"\") for parameter and got: %s\n", *str );
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

#ifdef MBEDTLS_RSA_C
    if( strcmp( str, "MBEDTLS_ERR_RSA_VERIFY_FAILED" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_VERIFY_FAILED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_RSA_C
#ifdef MBEDTLS_RSA_C
    if( strcmp( str, "MBEDTLS_ERR_PK_TYPE_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_TYPE_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_RSA_C
#ifdef MBEDTLS_SHA256_C
    if( strcmp( str, "MBEDTLS_ERR_PK_TYPE_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_TYPE_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_SHA256_C
#ifdef MBEDTLS_PK_PARSE_C
#ifdef MBEDTLS_FS_IO
    if( strcmp( str, "MBEDTLS_ERR_PK_TYPE_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_TYPE_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_PK_PARSE_C
#endif // MBEDTLS_FS_IO
#ifdef MBEDTLS_RSA_C
    if( strcmp( str, "MBEDTLS_PK_RSASSA_PSS" ) == 0 )
    {
        *value = ( MBEDTLS_PK_RSASSA_PSS );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_RSA_C
#ifdef MBEDTLS_RSA_C
    if( strcmp( str, "MBEDTLS_RSA_SALT_LEN_ANY" ) == 0 )
    {
        *value = ( MBEDTLS_RSA_SALT_LEN_ANY );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_RSA_C
    if( strcmp( str, "MBEDTLS_PK_ECKEY_DH" ) == 0 )
    {
        *value = ( MBEDTLS_PK_ECKEY_DH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#ifdef MBEDTLS_PK_PARSE_C
#ifdef MBEDTLS_FS_IO
    if( strcmp( str, "MBEDTLS_ERR_ECP_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_PK_PARSE_C
#endif // MBEDTLS_FS_IO
#ifdef MBEDTLS_RSA_C
    if( strcmp( str, "MBEDTLS_MD_NONE" ) == 0 )
    {
        *value = ( MBEDTLS_MD_NONE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_RSA_C
#ifdef MBEDTLS_RSA_C
    if( strcmp( str, "MBEDTLS_MD_SHA1" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA1 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_RSA_C
#ifdef MBEDTLS_RSA_C
    if( strcmp( str, "-1" ) == 0 )
    {
        *value = ( -1 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_RSA_C
#ifdef MBEDTLS_ECDSA_C
    if( strcmp( str, "MBEDTLS_ERR_ECP_VERIFY_FAILED" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_ECP_VERIFY_FAILED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_ECDSA_C
#ifdef MBEDTLS_RSA_C
    if( strcmp( str, "MBEDTLS_ERR_PK_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_RSA_C
#ifdef MBEDTLS_ECDSA_C
    if( strcmp( str, "MBEDTLS_ECP_DP_SECP192R1" ) == 0 )
    {
        *value = ( MBEDTLS_ECP_DP_SECP192R1 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_ECDSA_C
    if( strcmp( str, "MBEDTLS_PK_RSA" ) == 0 )
    {
        *value = ( MBEDTLS_PK_RSA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#ifdef MBEDTLS_RSA_C
    if( strcmp( str, "MBEDTLS_ERR_RSA_INVALID_PADDING" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_INVALID_PADDING );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_RSA_C
#ifdef MBEDTLS_RSA_C
    if( strcmp( str, "MBEDTLS_MD_SHA256" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA256 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_RSA_C
    if( strcmp( str, "MBEDTLS_PK_ECKEY" ) == 0 )
    {
        *value = ( MBEDTLS_PK_ECKEY );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#ifdef MBEDTLS_PK_PARSE_C
#ifdef MBEDTLS_FS_IO
    if( strcmp( str, "MBEDTLS_ERR_RSA_KEY_CHECK_FAILED" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_PK_PARSE_C
#endif // MBEDTLS_FS_IO
    if( strcmp( str, "MBEDTLS_PK_ECDSA" ) == 0 )
    {
        *value = ( MBEDTLS_PK_ECDSA );
        return( KEY_VALUE_MAPPING_FOUND );
    }


    mbedtls_printf( "Expected integer for parameter and got: %s\n", str );
    return( KEY_VALUE_MAPPING_NOT_FOUND );
}


/*----------------------------------------------------------------------------*/
/* Test Case code */

#line 67 "/Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.function"
void test_suite_pk_utils( int type, int size, int len, char *name )
{
    mbedtls_pk_context pk;

    mbedtls_pk_init( &pk );

    TEST_ASSERT( mbedtls_pk_setup( &pk, mbedtls_pk_info_from_type( type ) ) == 0 );
    TEST_ASSERT( pk_genkey( &pk ) == 0 );

    TEST_ASSERT( (int) mbedtls_pk_get_type( &pk ) == type );
    TEST_ASSERT( mbedtls_pk_can_do( &pk, type ) );
    TEST_ASSERT( mbedtls_pk_get_bitlen( &pk ) == (unsigned) size );
    TEST_ASSERT( mbedtls_pk_get_len( &pk ) == (unsigned) len );
    TEST_ASSERT( strcmp( mbedtls_pk_get_name( &pk), name ) == 0 );

exit:
    mbedtls_pk_free( &pk );
}

#ifdef MBEDTLS_PK_PARSE_C
#ifdef MBEDTLS_FS_IO
#line 88 "/Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.function"
void test_suite_mbedtls_pk_check_pair( char *pub_file, char *prv_file, int ret )
{
    mbedtls_pk_context pub, prv, alt;

    mbedtls_pk_init( &pub );
    mbedtls_pk_init( &prv );
    mbedtls_pk_init( &alt );

    TEST_ASSERT( mbedtls_pk_parse_public_keyfile( &pub, pub_file ) == 0 );
    TEST_ASSERT( mbedtls_pk_parse_keyfile( &prv, prv_file, NULL ) == 0 );

    TEST_ASSERT( mbedtls_pk_check_pair( &pub, &prv ) == ret );

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
    if( mbedtls_pk_get_type( &prv ) == MBEDTLS_PK_RSA )
    {
        TEST_ASSERT( mbedtls_pk_setup_rsa_alt( &alt, mbedtls_pk_rsa( prv ),
                     mbedtls_rsa_decrypt_func, mbedtls_rsa_sign_func, mbedtls_rsa_key_len_func ) == 0 );
        TEST_ASSERT( mbedtls_pk_check_pair( &pub, &alt ) == ret );
    }
#endif

    mbedtls_pk_free( &pub );
    mbedtls_pk_free( &prv );
    mbedtls_pk_free( &alt );

exit:
    return;
}
#endif /* MBEDTLS_PK_PARSE_C */
#endif /* MBEDTLS_FS_IO */

#ifdef MBEDTLS_RSA_C
#line 117 "/Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.function"
void test_suite_pk_rsa_verify_test_vec( char *message_hex_string, int digest,
                       int mod, int radix_N, char *input_N, int radix_E,
                       char *input_E, char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char result_str[1000];
    mbedtls_rsa_context *rsa;
    mbedtls_pk_context pk;
    int msg_len;

    mbedtls_pk_init( &pk );

    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( result_str, 0x00, 1000 );

    TEST_ASSERT( mbedtls_pk_setup( &pk, mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) ) == 0 );
    rsa = mbedtls_pk_rsa( pk );

    rsa->len = mod / 8;
    TEST_ASSERT( mbedtls_mpi_read_string( &rsa->N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &rsa->E, radix_E, input_E ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );
    unhexify( result_str, result_hex_str );

    if( mbedtls_md_info_from_type( digest ) != NULL )
        TEST_ASSERT( mbedtls_md( mbedtls_md_info_from_type( digest ), message_str, msg_len, hash_result ) == 0 );

    TEST_ASSERT( mbedtls_pk_verify( &pk, digest, hash_result, 0,
                            result_str, mbedtls_pk_get_len( &pk ) ) == result );

exit:
    mbedtls_pk_free( &pk );
}
#endif /* MBEDTLS_RSA_C */

#ifdef MBEDTLS_RSA_C
#line 156 "/Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.function"
void test_suite_pk_rsa_verify_ext_test_vec( char *message_hex_string, int digest,
                       int mod, int radix_N, char *input_N, int radix_E,
                       char *input_E, char *result_hex_str,
                       int pk_type, int mgf1_hash_id, int salt_len,
                       int result )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char result_str[1000];
    mbedtls_rsa_context *rsa;
    mbedtls_pk_context pk;
    mbedtls_pk_rsassa_pss_options pss_opts;
    void *options;
    int msg_len;
    size_t hash_len;

    mbedtls_pk_init( &pk );

    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( result_str, 0x00, 1000 );

    TEST_ASSERT( mbedtls_pk_setup( &pk, mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) ) == 0 );
    rsa = mbedtls_pk_rsa( pk );

    rsa->len = mod / 8;
    TEST_ASSERT( mbedtls_mpi_read_string( &rsa->N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &rsa->E, radix_E, input_E ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );
    unhexify( result_str, result_hex_str );

    if( digest != MBEDTLS_MD_NONE )
    {
        TEST_ASSERT( mbedtls_md( mbedtls_md_info_from_type( digest ),
                     message_str, msg_len, hash_result ) == 0 );
        hash_len = 0;
    }
    else
    {
        memcpy( hash_result, message_str, msg_len );
        hash_len = msg_len;
    }

    if( mgf1_hash_id < 0 )
    {
        options = NULL;
    }
    else
    {
        options = &pss_opts;

        pss_opts.mgf1_hash_id = mgf1_hash_id;
        pss_opts.expected_salt_len = salt_len;
    }

    TEST_ASSERT( mbedtls_pk_verify_ext( pk_type, options, &pk,
                                digest, hash_result, hash_len,
                                result_str, mbedtls_pk_get_len( &pk ) ) == result );

exit:
    mbedtls_pk_free( &pk );
}
#endif /* MBEDTLS_RSA_C */

#ifdef MBEDTLS_ECDSA_C
#line 222 "/Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.function"
void test_suite_pk_ec_test_vec( int type, int id, char *key_str,
                     char *hash_str, char * sig_str, int ret )
{
    mbedtls_pk_context pk;
    mbedtls_ecp_keypair *eckey;
    unsigned char hash[100], sig[500], key[500];
    size_t hash_len, sig_len, key_len;

    mbedtls_pk_init( &pk );

    memset( hash, 0, sizeof( hash ) );  hash_len = unhexify(hash, hash_str);
    memset( sig, 0, sizeof( sig ) );    sig_len = unhexify(sig, sig_str);
    memset( key, 0, sizeof( key ) );    key_len = unhexify(key, key_str);

    TEST_ASSERT( mbedtls_pk_setup( &pk, mbedtls_pk_info_from_type( type ) ) == 0 );

    TEST_ASSERT( mbedtls_pk_can_do( &pk, MBEDTLS_PK_ECDSA ) );
    eckey = mbedtls_pk_ec( pk );

    TEST_ASSERT( mbedtls_ecp_group_load( &eckey->grp, id ) == 0 );
    TEST_ASSERT( mbedtls_ecp_point_read_binary( &eckey->grp, &eckey->Q,
                                        key, key_len ) == 0 );

    TEST_ASSERT( mbedtls_pk_verify( &pk, MBEDTLS_MD_NONE,
                            hash, hash_len, sig, sig_len ) == ret );

exit:
    mbedtls_pk_free( &pk );
}
#endif /* MBEDTLS_ECDSA_C */

#ifdef MBEDTLS_SHA256_C
#line 254 "/Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.function"
void test_suite_pk_sign_verify( int type, int sign_ret, int verify_ret )
{
    mbedtls_pk_context pk;
    unsigned char hash[50], sig[5000];
    size_t sig_len;

    mbedtls_pk_init( &pk );

    memset( hash, 0x2a, sizeof hash );
    memset( sig, 0, sizeof sig );

    TEST_ASSERT( mbedtls_pk_setup( &pk, mbedtls_pk_info_from_type( type ) ) == 0 );
    TEST_ASSERT( pk_genkey( &pk ) == 0 );

    TEST_ASSERT( mbedtls_pk_sign( &pk, MBEDTLS_MD_SHA256, hash, sizeof hash,
                          sig, &sig_len, rnd_std_rand, NULL ) == sign_ret );

    TEST_ASSERT( mbedtls_pk_verify( &pk, MBEDTLS_MD_SHA256,
                            hash, sizeof hash, sig, sig_len ) == verify_ret );

exit:
    mbedtls_pk_free( &pk );
}
#endif /* MBEDTLS_SHA256_C */

#ifdef MBEDTLS_RSA_C
#line 280 "/Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.function"
void test_suite_pk_rsa_encrypt_test_vec( char *message_hex, int mod,
                            int radix_N, char *input_N,
                            int radix_E, char *input_E,
                            char *result_hex, int ret )
{
    unsigned char message[1000];
    unsigned char output[1000];
    unsigned char result[1000];
    size_t msg_len, olen, res_len;
    rnd_pseudo_info rnd_info;
    mbedtls_rsa_context *rsa;
    mbedtls_pk_context pk;

    memset( &rnd_info,  0, sizeof( rnd_pseudo_info ) );
    memset( message,    0, sizeof( message ) );
    memset( output,     0, sizeof( output ) );
    memset( result,     0, sizeof( result ) );

    msg_len = unhexify( message, message_hex );
    res_len = unhexify( result, result_hex );

    mbedtls_pk_init( &pk );
    TEST_ASSERT( mbedtls_pk_setup( &pk, mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) ) == 0 );
    rsa = mbedtls_pk_rsa( pk );

    rsa->len = mod / 8;
    TEST_ASSERT( mbedtls_mpi_read_string( &rsa->N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &rsa->E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_pk_encrypt( &pk, message, msg_len,
                             output, &olen, sizeof( output ),
                             rnd_pseudo_rand, &rnd_info ) == ret );
    TEST_ASSERT( olen == res_len );
    TEST_ASSERT( memcmp( output, result, olen ) == 0 );

exit:
    mbedtls_pk_free( &pk );
}
#endif /* MBEDTLS_RSA_C */

#ifdef MBEDTLS_RSA_C
#line 321 "/Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.function"
void test_suite_pk_rsa_decrypt_test_vec( char *cipher_hex, int mod,
                            int radix_P, char *input_P,
                            int radix_Q, char *input_Q,
                            int radix_N, char *input_N,
                            int radix_E, char *input_E,
                            char *clear_hex, int ret )
{
    unsigned char clear[1000];
    unsigned char output[1000];
    unsigned char cipher[1000];
    size_t clear_len, olen, cipher_len;
    rnd_pseudo_info rnd_info;
    mbedtls_mpi P1, Q1, H, G;
    mbedtls_rsa_context *rsa;
    mbedtls_pk_context pk;

    mbedtls_pk_init( &pk );
    mbedtls_mpi_init( &P1 ); mbedtls_mpi_init( &Q1 ); mbedtls_mpi_init( &H ); mbedtls_mpi_init( &G );

    memset( &rnd_info,  0, sizeof( rnd_pseudo_info ) );
    memset( clear,      0, sizeof( clear ) );
    memset( cipher,     0, sizeof( cipher ) );

    clear_len = unhexify( clear, clear_hex );
    cipher_len = unhexify( cipher, cipher_hex );

    /* init pk-rsa context */
    TEST_ASSERT( mbedtls_pk_setup( &pk, mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) ) == 0 );
    rsa = mbedtls_pk_rsa( pk );

    /* load public key */
    rsa->len = mod / 8;
    TEST_ASSERT( mbedtls_mpi_read_string( &rsa->N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &rsa->E, radix_E, input_E ) == 0 );

    /* load private key */
    TEST_ASSERT( mbedtls_mpi_read_string( &rsa->P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &rsa->Q, radix_Q, input_Q ) == 0 );
    TEST_ASSERT( mbedtls_mpi_sub_int( &P1, &rsa->P, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_sub_int( &Q1, &rsa->Q, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_gcd( &G, &rsa->E, &H  ) == 0 );
    TEST_ASSERT( mbedtls_mpi_inv_mod( &rsa->D , &rsa->E, &H  ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mod_mpi( &rsa->DP, &rsa->D, &P1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mod_mpi( &rsa->DQ, &rsa->D, &Q1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_inv_mod( &rsa->QP, &rsa->Q, &rsa->P ) == 0 );

    /* decryption test */
    memset( output, 0, sizeof( output ) );
    olen = 0;
    TEST_ASSERT( mbedtls_pk_decrypt( &pk, cipher, cipher_len,
                             output, &olen, sizeof( output ),
                             rnd_pseudo_rand, &rnd_info ) == ret );
    if( ret == 0 )
    {
        TEST_ASSERT( olen == clear_len );
        TEST_ASSERT( memcmp( output, clear, olen ) == 0 );
    }

exit:
    mbedtls_mpi_free( &P1 ); mbedtls_mpi_free( &Q1 ); mbedtls_mpi_free( &H ); mbedtls_mpi_free( &G );
    mbedtls_pk_free( &pk );
}
#endif /* MBEDTLS_RSA_C */

#line 387 "/Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.function"
void test_suite_pk_ec_nocrypt( int type )
{
    mbedtls_pk_context pk;
    unsigned char output[100];
    unsigned char input[100];
    rnd_pseudo_info rnd_info;
    size_t olen = 0;
    int ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;

    mbedtls_pk_init( &pk );

    memset( &rnd_info,  0, sizeof( rnd_pseudo_info ) );
    memset( output,     0, sizeof( output ) );
    memset( input,      0, sizeof( input ) );

    TEST_ASSERT( mbedtls_pk_setup( &pk, mbedtls_pk_info_from_type( type ) ) == 0 );

    TEST_ASSERT( mbedtls_pk_encrypt( &pk, input, sizeof( input ),
                             output, &olen, sizeof( output ),
                             rnd_pseudo_rand, &rnd_info ) == ret );

    TEST_ASSERT( mbedtls_pk_decrypt( &pk, input, sizeof( input ),
                             output, &olen, sizeof( output ),
                             rnd_pseudo_rand, &rnd_info ) == ret );

exit:
    mbedtls_pk_free( &pk );
}

#ifdef MBEDTLS_RSA_C
#ifdef MBEDTLS_PK_RSA_ALT_SUPPORT
#line 418 "/Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.function"
void test_suite_pk_rsa_alt( )
{
    /*
     * An rsa_alt context can only do private operations (decrypt, sign).
     * Test it against the public operations (encrypt, verify) of a
     * corresponding rsa context.
     */
    mbedtls_rsa_context raw;
    mbedtls_pk_context rsa, alt;
    mbedtls_pk_debug_item dbg_items[10];
    unsigned char hash[50], sig[1000];
    unsigned char msg[50], ciph[1000], test[1000];
    size_t sig_len, ciph_len, test_len;
    int ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;

    mbedtls_rsa_init( &raw, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE );
    mbedtls_pk_init( &rsa ); mbedtls_pk_init( &alt );

    memset( hash, 0x2a, sizeof hash );
    memset( sig, 0, sizeof sig );
    memset( msg, 0x2a, sizeof msg );
    memset( ciph, 0, sizeof ciph );
    memset( test, 0, sizeof test );

    /* Initiliaze PK RSA context with random key */
    TEST_ASSERT( mbedtls_pk_setup( &rsa,
                              mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) ) == 0 );
    TEST_ASSERT( pk_genkey( &rsa ) == 0 );

    /* Extract key to the raw rsa context */
    TEST_ASSERT( mbedtls_rsa_copy( &raw, mbedtls_pk_rsa( rsa ) ) == 0 );

    /* Initialize PK RSA_ALT context */
    TEST_ASSERT( mbedtls_pk_setup_rsa_alt( &alt, (void *) &raw,
                 mbedtls_rsa_decrypt_func, mbedtls_rsa_sign_func, mbedtls_rsa_key_len_func ) == 0 );

    /* Test administrative functions */
    TEST_ASSERT( mbedtls_pk_can_do( &alt, MBEDTLS_PK_RSA ) );
    TEST_ASSERT( mbedtls_pk_get_bitlen( &alt ) == RSA_KEY_SIZE );
    TEST_ASSERT( mbedtls_pk_get_len( &alt ) == RSA_KEY_LEN );
    TEST_ASSERT( mbedtls_pk_get_type( &alt ) == MBEDTLS_PK_RSA_ALT );
    TEST_ASSERT( strcmp( mbedtls_pk_get_name( &alt ), "RSA-alt" ) == 0 );

    /* Test signature */
    TEST_ASSERT( mbedtls_pk_sign( &alt, MBEDTLS_MD_NONE, hash, sizeof hash,
                          sig, &sig_len, rnd_std_rand, NULL ) == 0 );
    TEST_ASSERT( sig_len == RSA_KEY_LEN );
    TEST_ASSERT( mbedtls_pk_verify( &rsa, MBEDTLS_MD_NONE,
                            hash, sizeof hash, sig, sig_len ) == 0 );

    /* Test decrypt */
    TEST_ASSERT( mbedtls_pk_encrypt( &rsa, msg, sizeof msg,
                             ciph, &ciph_len, sizeof ciph,
                             rnd_std_rand, NULL ) == 0 );
    TEST_ASSERT( mbedtls_pk_decrypt( &alt, ciph, ciph_len,
                             test, &test_len, sizeof test,
                             rnd_std_rand, NULL ) == 0 );
    TEST_ASSERT( test_len == sizeof msg );
    TEST_ASSERT( memcmp( test, msg, test_len ) == 0 );

    /* Test forbidden operations */
    TEST_ASSERT( mbedtls_pk_encrypt( &alt, msg, sizeof msg,
                             ciph, &ciph_len, sizeof ciph,
                             rnd_std_rand, NULL ) == ret );
    TEST_ASSERT( mbedtls_pk_verify( &alt, MBEDTLS_MD_NONE,
                            hash, sizeof hash, sig, sig_len ) == ret );
    TEST_ASSERT( mbedtls_pk_debug( &alt, dbg_items ) == ret );

exit:
    mbedtls_rsa_free( &raw );
    mbedtls_pk_free( &rsa ); mbedtls_pk_free( &alt );
}
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */


#endif /* defined(MBEDTLS_PK_C) */


#line 75 "main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */

int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "MBEDTLS_ECP_C" ) == 0 )
    {
#if defined(MBEDTLS_ECP_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_ECP_DP_SECP192R1_ENABLED" ) == 0 )
    {
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_RSA_C" ) == 0 )
    {
#if defined(MBEDTLS_RSA_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_ECDSA_C" ) == 0 )
    {
#if defined(MBEDTLS_ECDSA_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_SHA1_C" ) == 0 )
    {
#if defined(MBEDTLS_SHA1_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_GENPRIME" ) == 0 )
    {
#if defined(MBEDTLS_GENPRIME)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_PKCS1_V15" ) == 0 )
    {
#if defined(MBEDTLS_PKCS1_V15)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_PKCS1_V21" ) == 0 )
    {
#if defined(MBEDTLS_PKCS1_V21)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_ECP_DP_SECP256R1_ENABLED" ) == 0 )
    {
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_SHA256_C" ) == 0 )
    {
#if defined(MBEDTLS_SHA256_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }


    return( DEPENDENCY_NOT_SUPPORTED );
}

int dispatch_test(int cnt, char *params[50])
{
    int ret;
    ((void) cnt);
    ((void) params);

#if defined(TEST_SUITE_ACTIVE)
    ret = DISPATCH_TEST_SUCCESS;

    if( strcmp( params[0], "pk_utils" ) == 0 )
    {

        int param1;
        int param2;
        int param3;
        char *param4 = params[4];

        if( cnt != 5 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_pk_utils( param1, param2, param3, param4 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_pk_check_pair" ) == 0 )
    {
    #ifdef MBEDTLS_PK_PARSE_C
    #ifdef MBEDTLS_FS_IO

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_pk_check_pair( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_PK_PARSE_C */
    #endif /* MBEDTLS_FS_IO */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "pk_rsa_verify_test_vec" ) == 0 )
    {
    #ifdef MBEDTLS_RSA_C

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        char *param8 = params[8];
        int param9;

        if( cnt != 10 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_pk_rsa_verify_test_vec( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_RSA_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "pk_rsa_verify_ext_test_vec" ) == 0 )
    {
    #ifdef MBEDTLS_RSA_C

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        char *param8 = params[8];
        int param9;
        int param10;
        int param11;
        int param12;

        if( cnt != 13 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 13 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[10], &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[11], &param11 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[12], &param12 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_pk_rsa_verify_ext_test_vec( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_RSA_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "pk_ec_test_vec" ) == 0 )
    {
    #ifdef MBEDTLS_ECDSA_C

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

        test_suite_pk_ec_test_vec( param1, param2, param3, param4, param5, param6 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_ECDSA_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "pk_sign_verify" ) == 0 )
    {
    #ifdef MBEDTLS_SHA256_C

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

        test_suite_pk_sign_verify( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_SHA256_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "pk_rsa_encrypt_test_vec" ) == 0 )
    {
    #ifdef MBEDTLS_RSA_C

        char *param1 = params[1];
        int param2;
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        char *param7 = params[7];
        int param8;

        if( cnt != 9 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 9 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[8], &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_pk_rsa_encrypt_test_vec( param1, param2, param3, param4, param5, param6, param7, param8 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_RSA_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "pk_rsa_decrypt_test_vec" ) == 0 )
    {
    #ifdef MBEDTLS_RSA_C

        char *param1 = params[1];
        int param2;
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        char *param11 = params[11];
        int param12;

        if( cnt != 13 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 13 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param11 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[12], &param12 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_pk_rsa_decrypt_test_vec( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_RSA_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "pk_ec_nocrypt" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_pk_ec_nocrypt( param1 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "pk_rsa_alt" ) == 0 )
    {
    #ifdef MBEDTLS_RSA_C
    #ifdef MBEDTLS_PK_RSA_ALT_SUPPORT


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_pk_rsa_alt(  );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_RSA_C */
    #endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else

    {
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

#line 118 "main_test.function"

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
    "/Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.data"


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
    const char *default_filename = "/Users/alessandrobudroni/Dev/milagro-mbedtls/tests/suites/test_suite_pk.data";
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
                mbedtls_printf("FATAL: Dep count larger than zero at start of loop\n");
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
                            mbedtls_printf("FATAL: Out of memory\n");
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
                ret = dispatch_test( cnt, params );
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

    return( total_errors != 0 );
}


