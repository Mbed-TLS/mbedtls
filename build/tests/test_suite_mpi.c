/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script: /home/clm/PATCH_mbed/mbedtls/tests/scripts/generate_code.pl
 *
 * Test file      : test_suite_mpi.c
 *
 * The following files were used to create this file.
 *
 *      Main code file  : /home/clm/PATCH_mbed/mbedtls/tests/suites/main_test.function
 *      Helper file     : /home/clm/PATCH_mbed/mbedtls/tests/suites/helpers.function
 *      Test suite file : /home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function
 *      Test suite data : /home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.data
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

#if defined(MBEDTLS_BIGNUM_C)

#include "mbedtls/bignum.h"

#endif /* defined(MBEDTLS_BIGNUM_C) */


#line 1 "main_test.function"
#if defined(MBEDTLS_BIGNUM_C)

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

    if( strcmp( str, "MBEDTLS_ERR_MPI_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "-3" ) == 0 )
    {
        *value = ( -3 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "-34" ) == 0 )
    {
        *value = ( -34 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_ERR_MPI_NOT_ACCEPTABLE" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_MPI_NOT_ACCEPTABLE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_ERR_MPI_DIVISION_BY_ZERO" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_MPI_DIVISION_BY_ZERO );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "+1" ) == 0 )
    {
        *value = ( +1 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "-1" ) == 0 )
    {
        *value = ( -1 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_ERR_MPI_INVALID_CHARACTER" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_MPI_INVALID_CHARACTER );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_ERR_MPI_NEGATIVE_VALUE" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_MPI_NEGATIVE_VALUE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#ifdef MBEDTLS_FS_IO
    if( strcmp( str, "MBEDTLS_ERR_MPI_FILE_IO_ERROR" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_MPI_FILE_IO_ERROR );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
    if( strcmp( str, "-2" ) == 0 )
    {
        *value = ( -2 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "-13" ) == 0 )
    {
        *value = ( -13 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "-9871232" ) == 0 )
    {
        *value = ( -9871232 );
        return( KEY_VALUE_MAPPING_FOUND );
    }


    mbedtls_fprintf( stderr,
                    "Expected integer for parameter and got: %s\n", str );
    return( KEY_VALUE_MAPPING_NOT_FOUND );
}


/*----------------------------------------------------------------------------*/
/* Test Case code */

#line 11 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mpi_null( )
{
    mbedtls_mpi X, Y, Z;

    mbedtls_mpi_init( &X );
    mbedtls_mpi_init( &Y );
    mbedtls_mpi_init( &Z );

    TEST_ASSERT( mbedtls_mpi_get_bit( &X, 42 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_lsb( &X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_bitlen( &X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_size( &X ) == 0 );

exit:
    mbedtls_mpi_free( &X );
}

#line 30 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mpi_read_write_string( int radix_X, char *input_X, int radix_A,
                            char *input_A, int output_size, int result_read,
                            int result_write )
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == result_read );
    if( result_read == 0 )
    {
        TEST_ASSERT( mbedtls_mpi_write_string( &X, radix_A, str, output_size, &len ) == result_write );
        if( result_write == 0 )
        {
            TEST_ASSERT( strcasecmp( str, input_A ) == 0 );
        }
    }

exit:
    mbedtls_mpi_free( &X );
}

#line 56 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_read_binary( char *input_X, int radix_A, char *input_A )
{
    mbedtls_mpi X;
    unsigned char str[1000];
    unsigned char buf[1000];
    size_t len;
    size_t input_len;

    mbedtls_mpi_init( &X );

    input_len = unhexify( buf, input_X );

    TEST_ASSERT( mbedtls_mpi_read_binary( &X, buf, input_len ) == 0 );
    TEST_ASSERT( mbedtls_mpi_write_string( &X, radix_A, (char *) str, sizeof( str ), &len ) == 0 );
    TEST_ASSERT( strcmp( (char *) str, input_A ) == 0 );

exit:
    mbedtls_mpi_free( &X );
}

#line 78 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_write_binary( int radix_X, char *input_X, char *input_A,
                       int output_size, int result )
{
    mbedtls_mpi X;
    unsigned char str[1000];
    unsigned char buf[1000];
    size_t buflen;

    memset( buf, 0x00, 1000 );
    memset( str, 0x00, 1000 );

    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );

    buflen = mbedtls_mpi_size( &X );
    if( buflen > (size_t) output_size )
        buflen = (size_t) output_size;

    TEST_ASSERT( mbedtls_mpi_write_binary( &X, buf, buflen ) == result );
    if( result == 0)
    {
        hexify( str, buf, buflen );

        TEST_ASSERT( strcasecmp( (char *) str, input_A ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X );
}

#ifdef MBEDTLS_FS_IO
#line 111 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_read_file( int radix_X, char *input_file, char *input_A,
                    int result )
{
    mbedtls_mpi X;
    unsigned char str[1000];
    unsigned char buf[1000];
    size_t buflen;
    FILE *file;
    int ret;

    memset( buf, 0x00, 1000 );
    memset( str, 0x00, 1000 );

    mbedtls_mpi_init( &X );

    file = fopen( input_file, "r" );
    TEST_ASSERT( file != NULL );
    ret = mbedtls_mpi_read_file( &X, radix_X, file );
    fclose(file);
    TEST_ASSERT( ret == result );

    if( result == 0 )
    {
        buflen = mbedtls_mpi_size( &X );
        TEST_ASSERT( mbedtls_mpi_write_binary( &X, buf, buflen ) == 0 );

        hexify( str, buf, buflen );

        TEST_ASSERT( strcasecmp( (char *) str, input_A ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X );
}
#endif /* MBEDTLS_FS_IO */

#ifdef MBEDTLS_FS_IO
#line 148 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_write_file( int radix_X, char *input_X, int output_radix,
                     char *output_file )
{
    mbedtls_mpi X, Y;
    FILE *file_out, *file_in;
    int ret;

    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );

    file_out = fopen( output_file, "w" );
    TEST_ASSERT( file_out != NULL );
    ret = mbedtls_mpi_write_file( NULL, &X, output_radix, file_out );
    fclose(file_out);
    TEST_ASSERT( ret == 0 );

    file_in = fopen( output_file, "r" );
    TEST_ASSERT( file_in != NULL );
    ret = mbedtls_mpi_read_file( &Y, output_radix, file_in );
    fclose(file_in);
    TEST_ASSERT( ret == 0 );

    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &Y ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y );
}
#endif /* MBEDTLS_FS_IO */

#line 179 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_get_bit( int radix_X, char *input_X, int pos, int val )
{
    mbedtls_mpi X;
    mbedtls_mpi_init( &X );
    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_get_bit( &X, pos ) == val );

exit:
    mbedtls_mpi_free( &X );
}

#line 192 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_set_bit( int radix_X, char *input_X, int pos, int val,
                          int radix_Y, char *output_Y, int result )
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, output_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_set_bit( &X, pos, val ) == result );

    if( result == 0 )
    {
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &Y ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y );
}

#line 213 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_lsb( int radix_X, char *input_X, int nr_bits )
{
    mbedtls_mpi X;
    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_lsb( &X ) == (size_t) nr_bits );

exit:
    mbedtls_mpi_free( &X );
}

#line 227 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_bitlen( int radix_X, char *input_X, int nr_bits )
{
    mbedtls_mpi X;
    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_bitlen( &X ) == (size_t) nr_bits );

exit:
    mbedtls_mpi_free( &X );
}

#line 241 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_gcd( int radix_X, char *input_X, int radix_Y, char *input_Y,
              int radix_A, char *input_A )
{
    mbedtls_mpi A, X, Y, Z;
    mbedtls_mpi_init( &A ); mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_gcd( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

exit:
    mbedtls_mpi_free( &A ); mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z );
}

#line 259 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_cmp_int( int input_X, int input_A, int result_CMP )
{
    mbedtls_mpi X;
    mbedtls_mpi_init( &X  );

    TEST_ASSERT( mbedtls_mpi_lset( &X, input_X ) == 0);
    TEST_ASSERT( mbedtls_mpi_cmp_int( &X, input_A ) == result_CMP);

exit:
    mbedtls_mpi_free( &X );
}

#line 273 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_cmp_mpi( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int input_A )
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &Y ) == input_A );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y );
}

#line 289 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_cmp_abs( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int input_A )
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_abs( &X, &Y ) == input_A );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y );
}

#line 305 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_copy( int input_X, int input_A )
{
    mbedtls_mpi X, Y, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_lset( &X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_lset( &Y, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_lset( &A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &Y ) != 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Y, &A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_copy( &Y, &X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Y, &A ) != 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &A );
}

#line 325 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mpi_copy_self( int input_X )
{
    mbedtls_mpi X;
    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_mpi_lset( &X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_copy( &X, &X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_int( &X, input_X ) == 0 );

exit:
    mbedtls_mpi_free( &X );
}

#line 340 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_shrink( int before, int used, int min, int after )
{
    mbedtls_mpi X;
    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_mpi_grow( &X, before ) == 0 );
    TEST_ASSERT( used <= before );
    memset( X.p, 0x2a, used * sizeof( mbedtls_mpi_uint ) );
    TEST_ASSERT( mbedtls_mpi_shrink( &X, min ) == 0 );
    TEST_ASSERT( X.n == (size_t) after );

exit:
    mbedtls_mpi_free( &X );
}

#line 357 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_safe_cond_assign( int x_sign, char *x_str,
                           int y_sign, char *y_str )
{
    mbedtls_mpi X, Y, XX;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &XX );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, 16, x_str ) == 0 );
    X.s = x_sign;
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, 16, y_str ) == 0 );
    Y.s = y_sign;
    TEST_ASSERT( mbedtls_mpi_copy( &XX, &X ) == 0 );

    TEST_ASSERT( mbedtls_mpi_safe_cond_assign( &X, &Y, 0 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &XX ) == 0 );

    TEST_ASSERT( mbedtls_mpi_safe_cond_assign( &X, &Y, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &Y ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &XX );
}

#line 381 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_safe_cond_swap( int x_sign, char *x_str,
                         int y_sign, char *y_str )
{
    mbedtls_mpi X, Y, XX, YY;

    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y );
    mbedtls_mpi_init( &XX ); mbedtls_mpi_init( &YY );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, 16, x_str ) == 0 );
    X.s = x_sign;
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, 16, y_str ) == 0 );
    Y.s = y_sign;

    TEST_ASSERT( mbedtls_mpi_copy( &XX, &X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_copy( &YY, &Y ) == 0 );

    TEST_ASSERT( mbedtls_mpi_safe_cond_swap( &X, &Y, 0 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &XX ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Y, &YY ) == 0 );

    TEST_ASSERT( mbedtls_mpi_safe_cond_swap( &X, &Y, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Y, &XX ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &YY ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y );
    mbedtls_mpi_free( &XX ); mbedtls_mpi_free( &YY );
}

#line 412 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_swap( int input_X,  int input_Y )
{
    mbedtls_mpi X, Y, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_lset( &X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_lset( &Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_lset( &A, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &Y ) != 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );
    mbedtls_mpi_swap( &X, &Y );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &Y ) != 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Y, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &A );
}

#line 432 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_add_mpi( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A )
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_add_mpi( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

#line 450 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_add_mpi_inplace( int radix_X, char *input_X, int radix_A, char *input_A )
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_sub_abs( &X, &X, &X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_int( &X, 0 ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_add_abs( &X, &X, &X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_add_mpi( &X, &X, &X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &A );
}

#line 476 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_add_abs( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A )
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_add_abs( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

#line 494 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mpi_add_abs_add_first( int radix_X, char *input_X, int radix_Y,
                            char *input_Y, int radix_A, char *input_A )
{
    mbedtls_mpi X, Y, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_add_abs( &X, &X, &Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &A );
}

#line 512 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mpi_add_abs_add_second( int radix_X, char *input_X, int radix_Y,
                             char *input_Y, int radix_A, char *input_A )
{
    mbedtls_mpi X, Y, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_add_abs( &Y, &X, &Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Y, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &A );
}

#line 530 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_add_int( int radix_X, char *input_X, int input_Y, int radix_A,
                  char *input_A )
{
    mbedtls_mpi X, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_add_int( &Z, &X, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

#line 547 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_sub_mpi( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A )
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_sub_mpi( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

#line 565 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_sub_abs( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A, int sub_result )
{
    mbedtls_mpi X, Y, Z, A;
    int res;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );

    res = mbedtls_mpi_sub_abs( &Z, &X, &Y );
    TEST_ASSERT( res == sub_result );
    if( res == 0 )
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

#line 587 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_sub_int( int radix_X, char *input_X, int input_Y, int radix_A,
                  char *input_A )
{
    mbedtls_mpi X, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_sub_int( &Z, &X, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

#line 604 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_mul_mpi( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A )
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mul_mpi( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

#line 622 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_mul_int( int radix_X, char *input_X, int input_Y, int radix_A,
                  char *input_A, char *result_comparison )
{
    mbedtls_mpi X, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mul_int( &Z, &X, input_Y ) == 0 );
    if( strcmp( result_comparison, "==" ) == 0 )
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );
    else if( strcmp( result_comparison, "!=" ) == 0 )
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) != 0 );
    else
        TEST_ASSERT( "unknown operator" == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

#line 644 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_div_mpi( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A, int radix_B, char *input_B,
                  int div_result )
{
    mbedtls_mpi X, Y, Q, R, A, B;
    int res;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Q ); mbedtls_mpi_init( &R );
    mbedtls_mpi_init( &A ); mbedtls_mpi_init( &B );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &B, radix_B, input_B ) == 0 );
    res = mbedtls_mpi_div_mpi( &Q, &R, &X, &Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Q, &A ) == 0 );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R, &B ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Q ); mbedtls_mpi_free( &R );
    mbedtls_mpi_free( &A ); mbedtls_mpi_free( &B );
}

#line 672 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_div_int( int radix_X, char *input_X, int input_Y, int radix_A,
                  char *input_A, int radix_B, char *input_B, int div_result )
{
    mbedtls_mpi X, Q, R, A, B;
    int res;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Q ); mbedtls_mpi_init( &R ); mbedtls_mpi_init( &A );
    mbedtls_mpi_init( &B );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &B, radix_B, input_B ) == 0 );
    res = mbedtls_mpi_div_int( &Q, &R, &X, input_Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Q, &A ) == 0 );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R, &B ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Q ); mbedtls_mpi_free( &R ); mbedtls_mpi_free( &A );
    mbedtls_mpi_free( &B );
}

#line 698 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_mod_mpi( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A, int div_result )
{
    mbedtls_mpi X, Y, A;
    int res;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    res = mbedtls_mpi_mod_mpi( &X, &X, &Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &A );
}

#line 721 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_mod_int( int radix_X, char *input_X, int input_Y, int input_A,
                  int div_result )
{
    mbedtls_mpi X;
    int res;
    mbedtls_mpi_uint r;
    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    res = mbedtls_mpi_mod_int( &r, &X, input_Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( r == (mbedtls_mpi_uint) input_A );
    }

exit:
    mbedtls_mpi_free( &X );
}

#line 743 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_exp_mod( int radix_A, char *input_A, int radix_E, char *input_E,
                  int radix_N, char *input_N, int radix_RR, char *input_RR,
                  int radix_X, char *input_X, int div_result )
{
    mbedtls_mpi A, E, N, RR, Z, X;
    int res;
    mbedtls_mpi_init( &A  ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &N );
    mbedtls_mpi_init( &RR ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );

    if( strlen( input_RR ) )
        TEST_ASSERT( mbedtls_mpi_read_string( &RR, radix_RR, input_RR ) == 0 );

    res = mbedtls_mpi_exp_mod( &Z, &A, &E, &N, &RR );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &X ) == 0 );
    }

exit:
    mbedtls_mpi_free( &A  ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &N );
    mbedtls_mpi_free( &RR ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &X );
}

#line 774 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_inv_mod( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A, int div_result )
{
    mbedtls_mpi X, Y, Z, A;
    int res;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    res = mbedtls_mpi_inv_mod( &Z, &X, &Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

#ifdef MBEDTLS_GENPRIME
#line 797 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_is_prime( int radix_X, char *input_X, int div_result )
{
    mbedtls_mpi X;
    int res;
    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    res = mbedtls_mpi_is_prime( &X, rnd_std_rand, NULL );
    TEST_ASSERT( res == div_result );

exit:
    mbedtls_mpi_free( &X );
}
#endif /* MBEDTLS_GENPRIME */

#ifdef MBEDTLS_GENPRIME
#line 813 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_gen_prime( int bits, int safe, int ref_ret )
{
    mbedtls_mpi X;
    int my_ret;

    mbedtls_mpi_init( &X );

    my_ret = mbedtls_mpi_gen_prime( &X, bits, safe, rnd_std_rand, NULL );
    TEST_ASSERT( my_ret == ref_ret );

    if( ref_ret == 0 )
    {
        size_t actual_bits = mbedtls_mpi_bitlen( &X );

        TEST_ASSERT( actual_bits >= (size_t) bits );
        TEST_ASSERT( actual_bits <= (size_t) bits + 1 );

        TEST_ASSERT( mbedtls_mpi_is_prime( &X, rnd_std_rand, NULL ) == 0 );
        if( safe )
        {
            mbedtls_mpi_shift_r( &X, 1 ); /* X = ( X - 1 ) / 2 */
            TEST_ASSERT( mbedtls_mpi_is_prime( &X, rnd_std_rand, NULL ) == 0 );
        }
    }

exit:
    mbedtls_mpi_free( &X );
}
#endif /* MBEDTLS_GENPRIME */

#line 844 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_shift_l( int radix_X, char *input_X, int shift_X, int radix_A,
                  char *input_A)
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_shift_l( &X, shift_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &A );
}

#line 861 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mbedtls_mpi_shift_r( int radix_X, char *input_X, int shift_X, int radix_A,
                  char *input_A )
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_shift_r( &X, shift_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &A );
}

#ifdef MBEDTLS_SELF_TEST
#line 878 "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.function"
void test_suite_mpi_selftest()
{
    TEST_ASSERT( mbedtls_mpi_self_test( 1 ) == 0 );

exit:
    return;
}
#endif /* MBEDTLS_SELF_TEST */


#endif /* defined(MBEDTLS_BIGNUM_C) */


#line 77 "main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */

int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "MBEDTLS_SELF_TEST" ) == 0 )
    {
#if defined(MBEDTLS_SELF_TEST)
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

    if( strcmp( params[0], "mpi_null" ) == 0 )
    {


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_mpi_null(  );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mpi_read_write_string" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        int param6;
        int param7;

        if( cnt != 8 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mpi_read_write_string( param1, param2, param3, param4, param5, param6, param7 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_read_binary" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        char *param3 = params[3];

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_read_binary( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_write_binary" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        int param4;
        int param5;

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_write_binary( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_read_file" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        int param4;

        if( cnt != 5 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_read_file( param1, param2, param3, param4 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_write_file" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];

        if( cnt != 5 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_write_file( param1, param2, param3, param4 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_get_bit" ) == 0 )
    {

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

        test_suite_mbedtls_mpi_get_bit( param1, param2, param3, param4 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_set_bit" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        int param5;
        char *param6 = params[6];
        int param7;

        if( cnt != 8 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_set_bit( param1, param2, param3, param4, param5, param6, param7 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_lsb" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_lsb( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_bitlen" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_bitlen( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_gcd" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_gcd( param1, param2, param3, param4, param5, param6 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_cmp_int" ) == 0 )
    {

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

        test_suite_mbedtls_mpi_cmp_int( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_cmp_mpi" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_cmp_mpi( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_cmp_abs" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_cmp_abs( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_copy" ) == 0 )
    {

        int param1;
        int param2;

        if( cnt != 3 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_copy( param1, param2 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mpi_copy_self" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mpi_copy_self( param1 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_shrink" ) == 0 )
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

        test_suite_mbedtls_mpi_shrink( param1, param2, param3, param4 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_safe_cond_assign" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];

        if( cnt != 5 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_safe_cond_assign( param1, param2, param3, param4 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_safe_cond_swap" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];

        if( cnt != 5 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_safe_cond_swap( param1, param2, param3, param4 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_swap" ) == 0 )
    {

        int param1;
        int param2;

        if( cnt != 3 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_swap( param1, param2 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_add_mpi" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_add_mpi( param1, param2, param3, param4, param5, param6 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_add_mpi_inplace" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];

        if( cnt != 5 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_add_mpi_inplace( param1, param2, param3, param4 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_add_abs" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_add_abs( param1, param2, param3, param4, param5, param6 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mpi_add_abs_add_first" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mpi_add_abs_add_first( param1, param2, param3, param4, param5, param6 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mpi_add_abs_add_second" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mpi_add_abs_add_second( param1, param2, param3, param4, param5, param6 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_add_int" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        char *param5 = params[5];

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_add_int( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_sub_mpi" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_sub_mpi( param1, param2, param3, param4, param5, param6 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_sub_abs" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;

        if( cnt != 8 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_sub_abs( param1, param2, param3, param4, param5, param6, param7 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_sub_int" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        char *param5 = params[5];

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_sub_int( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_mul_mpi" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_mul_mpi( param1, param2, param3, param4, param5, param6 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_mul_int" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        char *param5 = params[5];
        char *param6 = params[6];

        if( cnt != 7 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_mul_int( param1, param2, param3, param4, param5, param6 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_div_mpi" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;

        if( cnt != 10 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_div_mpi( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_div_int" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        int param8;

        if( cnt != 9 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 9 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[8], &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_div_int( param1, param2, param3, param4, param5, param6, param7, param8 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_mod_mpi" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;

        if( cnt != 8 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_mod_mpi( param1, param2, param3, param4, param5, param6, param7 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_mod_int" ) == 0 )
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

        test_suite_mbedtls_mpi_mod_int( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_exp_mod" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        int param11;

        if( cnt != 12 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 12 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[11], &param11 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_exp_mod( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_inv_mod" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;

        if( cnt != 8 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_inv_mod( param1, param2, param3, param4, param5, param6, param7 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_is_prime" ) == 0 )
    {
    #ifdef MBEDTLS_GENPRIME

        int param1;
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_is_prime( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_GENPRIME */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_gen_prime" ) == 0 )
    {
    #ifdef MBEDTLS_GENPRIME

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

        test_suite_mbedtls_mpi_gen_prime( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_GENPRIME */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_shift_l" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        char *param5 = params[5];

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_shift_l( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_mpi_shift_r" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        char *param5 = params[5];

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_mpi_shift_r( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mpi_selftest" ) == 0 )
    {
    #ifdef MBEDTLS_SELF_TEST


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_mpi_selftest(  );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_SELF_TEST */

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
    "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.data"


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
    const char *default_filename = "/home/clm/PATCH_mbed/mbedtls/tests/suites/test_suite_mpi.data";
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


