/*
 * Common and shared functions used by multiple modules in the Mbed TLS
 * library.
 *
 *  Copyright (C) 2018, Arm Limited, All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

/*
 * Ensure gmtime_r is available even with -std=c99; must be defined before
 * config.h, which pulls in glibc's features.h. Harmless on other platforms.
 */
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/platform_util.h"
#include "mbedtls/platform.h"
#include "mbedtls/threading.h"

#if !defined(MBEDTLS_PLATFORM_C)
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
#include "mbedtls/entropy_poll.h"
#endif

#include <stddef.h>
#include <string.h>

/* Max number of loops for mbedtls_platform_random_delay. */
#define MAX_RAND_DELAY  100

/* Parameters for the linear congruential generator used as a non-cryptographic
 * random number generator. The same parameters are used by e.g. ANSI C. */
#define RAND_MULTIPLIER 1103515245
#define RAND_INCREMENT  12345
#define RAND_MODULUS    0x80000000

/* The number of iterations after which the seed of the non-cryptographic
 * random number generator will be changed. This is used only if the
 * MBEDTLS_ENTROPY_HARDWARE_ALT option is enabled. */
#define RAND_SEED_LIFE  10000

#if !defined(MBEDTLS_PLATFORM_ZEROIZE_ALT)
/*
 * This implementation should never be optimized out by the compiler
 *
 * This implementation for mbedtls_platform_zeroize() was inspired from Colin
 * Percival's blog article at:
 *
 * http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
 *
 * It uses a volatile function pointer to the standard memset(). Because the
 * pointer is volatile the compiler expects it to change at
 * any time and will not optimize out the call that could potentially perform
 * other operations on the input buffer instead of just setting it to 0.
 * Nevertheless, as pointed out by davidtgoldblatt on Hacker News
 * (refer to http://www.daemonology.net/blog/2014-09-05-erratum.html for
 * details), optimizations of the following form are still possible:
 *
 * if( memset_func != memset )
 *     memset_func( buf, 0, len );
 *
 * Note that it is extremely difficult to guarantee that
 * mbedtls_platform_zeroize() will not be optimized out by aggressive compilers
 * in a portable way. For this reason, Mbed TLS also provides the configuration
 * option MBEDTLS_PLATFORM_ZEROIZE_ALT, which allows users to configure
 * mbedtls_platform_zeroize() to use a suitable implementation for their
 * platform and needs.
 */
void *mbedtls_platform_memset( void *, int, size_t );
static void * (* const volatile memset_func)( void *, int, size_t ) = mbedtls_platform_memset;

void *mbedtls_platform_zeroize( void *buf, size_t len )
{
    volatile size_t vlen = len;

    MBEDTLS_INTERNAL_VALIDATE_RET( ( len == 0 || buf != NULL ), NULL );

    if( vlen > 0 )
    {
        return memset_func( buf, 0, vlen );
    }
    else
    {
        mbedtls_platform_random_delay();
        if( vlen == 0 && vlen == len )
        {
            return buf;
        }
    }
    return NULL;
}
#endif /* MBEDTLS_PLATFORM_ZEROIZE_ALT */

void *mbedtls_platform_memset( void *ptr, int value, size_t num )
{
    size_t i, start_offset = 0;
    volatile size_t flow_counter = 0;
    volatile char *b = ptr;
    char rnd_data;
    if( num > 0 )
    {
        start_offset = (size_t) mbedtls_platform_random_in_range( (uint32_t) num );

        rnd_data = (char) mbedtls_platform_random_in_range( 256 );

        /* Perform a memset operations with random data and start from a random
         * location */
        for( i = start_offset; i < num; ++i )
        {
            b[i] = rnd_data;
            flow_counter++;
        }

        /* Start from a random location with target data */
        for( i = start_offset; i < num; ++i )
        {
            b[i] = value;
            flow_counter++;
        }

        /* Second memset operation with random data */
        for( i = 0; i < start_offset; ++i )
        {
            b[i] = rnd_data;
            flow_counter++;
        }

        /* Finish memset operation with correct data */
        for( i = 0; i < start_offset; ++i )
        {
            b[i] = value;
            flow_counter++;
        }
    }
    /* check the correct number of iterations */
    if( flow_counter == 2 * num )
    {
        mbedtls_platform_random_delay();
        if( flow_counter == 2 * num )
        {
            return ptr;
        }
    }

    return NULL;
}

void *mbedtls_platform_memcpy( void *dst, const void *src, size_t num )
{
    size_t i;
    volatile size_t flow_counter = 0;

    if( num > 0 )
    {
        /* Randomize start offset. */
        size_t start_offset = (size_t) mbedtls_platform_random_in_range( (uint32_t) num );
        /* Randomize initial data to prevent leakage while copying */
        uint32_t data = mbedtls_platform_random_in_range( 256 );

        /* Use memset with random value at first to increase security - memset is
        not normally part of the memcpy function and here can be useed
        with regular, unsecured implementation */
        memset( (void *) dst, data, num );

        /* Make a copy starting from a random location. */
        i = start_offset;
        do
        {
            ( (char*) dst )[i] = ( (char*) src )[i];
            flow_counter++;
        }
        while( ( i = ( i + 1 ) % num ) != start_offset );
    }

    /* check the correct number of iterations */
    if( flow_counter == num )
    {
        mbedtls_platform_random_delay();
        if( flow_counter == num )
        {
            return dst;
        }
    }
    return NULL;
}

int mbedtls_platform_memmove( void *dst, const void *src, size_t num )
{
    void *ret1 = NULL;
    void *ret2 = NULL;
    /* The buffers can have a common part, so we cannot do a copy from a random
     * location. By using a temporary buffer we can do so, but the cost of it
     * is using more memory and longer transfer time. */
    void *tmp = mbedtls_calloc( 1, num );
    if( tmp != NULL )
    {
        ret1 = mbedtls_platform_memcpy( tmp, src, num );
        ret2 = mbedtls_platform_memcpy( dst, tmp, num );
        mbedtls_free( tmp );
        if( ret1 == tmp && ret2 == dst )
        {
            return 0;
        }
        return MBEDTLS_ERR_PLATFORM_FAULT_DETECTED;
    }

    return MBEDTLS_ERR_PLATFORM_ALLOC_FAILED;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_platform_memcmp( const void *buf1, const void *buf2, size_t num )
{
    return( mbedtls_platform_memequal( buf1, buf2, num ) );
}
#endif /* MBEDTLS_DEPRECATED_REMOVED */

int mbedtls_platform_memequal( const void *buf1, const void *buf2, size_t num )
{
    volatile const unsigned char *A = (volatile const unsigned char *) buf1;
    volatile const unsigned char *B = (volatile const unsigned char *) buf2;
    volatile unsigned char diff = 0;

    /* Start from a random location and check the correct number of iterations */
    size_t i, flow_counter = 0;
    size_t start_offset = 0;
    if( num > 0 )
    {
        start_offset = (size_t) mbedtls_platform_random_in_range( (uint32_t) num );

        for( i = start_offset; i < num; i++ )
        {
            unsigned char x = A[i], y = B[i];
            flow_counter++;
            diff |= x ^ y;
        }

        for( i = 0; i < start_offset; i++ )
        {
            unsigned char x = A[i], y = B[i];
            flow_counter++;
            diff |= x ^ y;
        }
    }
    /* Return 0 only when diff is 0 and flow_counter is equal to num */
    return( (int) diff | (int) ( flow_counter ^ num ) );
}

/* This function implements a non-cryptographic random number generator based
 * on the linear congruential generator algorithm. Additionally, if the
 * MBEDTLS_ENTROPY_HARDWARE_ALT flag is defined, the seed is set at the first
 * call of this function with using a hardware random number generator and
 * changed every RAND_SEED_LIFE number of iterations.
 *
 * The value of the returned number is in the range [0; 0xffff].
 *
 * Note: The range of values with a 16-bit precision is related to the modulo
 * parameter of the generator and the fact that the function does not return the
 * full value of the internal state of the generator.
 */
static uint32_t mbedtls_platform_random_uint16( void )
{
    /* Set random_state - the first random value should not be zero. */
    static uint32_t random_state = RAND_INCREMENT;

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)

    static uint32_t random_seed_life = 0;

    if( 0 < random_seed_life )
    {
        --random_seed_life;
    }
    else
    {
        size_t olen = 0;
        uint32_t hw_random;
        mbedtls_hardware_poll( NULL,
                               (unsigned char *) &hw_random, sizeof( hw_random ),
                               &olen );
        if( olen == sizeof( hw_random ) )
        {
            random_state ^= hw_random;
            random_seed_life = RAND_SEED_LIFE;
        }
    }

#endif /* MBEDTLS_ENTROPY_HARDWARE_ALT */

    random_state = ( ( random_state * RAND_MULTIPLIER ) + RAND_INCREMENT ) % RAND_MODULUS;

    /* Do not return the entire random_state to hide generator predictability for
     * the next iteration */
    return( ( random_state >> 15 ) & 0xffff );
}

uint32_t mbedtls_platform_random_uint32( void )
{
    return( ( mbedtls_platform_random_uint16() << 16 ) |
              mbedtls_platform_random_uint16() );
}

void mbedtls_platform_random_buf( uint8_t *buf, size_t len )
{
    uint16_t val;

    while( len > 1 )
    {
        val = mbedtls_platform_random_uint16();
        buf[len-1] = (uint8_t)val;
        buf[len-2] = (uint8_t)(val>>8);
        len -= 2;
    }
    if( len == 1 )
    {
        buf[0] = (uint8_t)mbedtls_platform_random_uint16();
    }

    return;
}

uint32_t mbedtls_platform_random_in_range( uint32_t num )
{
    return mbedtls_platform_random_uint32() % num;
}

void mbedtls_platform_random_delay( void )
{
#if defined(MBEDTLS_FI_COUNTERMEASURES)
    uint32_t rn_1, rn_2, rn_3;
    volatile size_t i = 0;
    uint8_t shift;

    rn_1 = mbedtls_platform_random_in_range( MAX_RAND_DELAY );
    rn_2 = mbedtls_platform_random_in_range( 0xffffffff ) + 1;
    rn_3 = mbedtls_platform_random_in_range( 0xffffffff ) + 1;

    do
    {
        i++;
        /* Dummy calculations to increase the time between iterations and
         * make side channel attack more difficult by reducing predictability
         * of its behaviour. */
        shift = ( rn_2 & 0x07 ) + 1;
        if ( i % 2 )
            rn_2 = ( rn_2 >> shift ) | ( rn_2 << ( 32 - shift ) );
        else
            rn_3 = ( rn_3 << shift ) | ( rn_3 >> ( 32 - shift ) );
        rn_2 ^= rn_3;
    } while( i < rn_1 || rn_2 == 0 || rn_3 == 0 );

#endif /* MBEDTLS_FI_COUNTERMEASURES */
    return;
}

#if defined(MBEDTLS_HAVE_TIME_DATE) && !defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)
#include <time.h>
#if !defined(_WIN32) && (defined(unix) || \
    defined(__unix) || defined(__unix__) || (defined(__APPLE__) && \
    defined(__MACH__)))
#include <unistd.h>
#endif /* !_WIN32 && (unix || __unix || __unix__ ||
        * (__APPLE__ && __MACH__)) */

#if !( ( defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L ) ||     \
       ( defined(_POSIX_THREAD_SAFE_FUNCTIONS ) &&                     \
         _POSIX_THREAD_SAFE_FUNCTIONS >= 20112L ) )
/*
 * This is a convenience shorthand macro to avoid checking the long
 * preprocessor conditions above. Ideally, we could expose this macro in
 * platform_util.h and simply use it in platform_util.c, threading.c and
 * threading.h. However, this macro is not part of the Mbed TLS public API, so
 * we keep it private by only defining it in this file
 */
#if ! ( defined(_WIN32) && !defined(EFIX64) && !defined(EFI32) )
#define PLATFORM_UTIL_USE_GMTIME
#endif /* ! ( defined(_WIN32) && !defined(EFIX64) && !defined(EFI32) ) */

#endif /* !( ( defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L ) ||     \
             ( defined(_POSIX_THREAD_SAFE_FUNCTIONS ) &&                     \
                _POSIX_THREAD_SAFE_FUNCTIONS >= 20112L ) ) */

struct tm *mbedtls_platform_gmtime_r( const mbedtls_time_t *tt,
                                      struct tm *tm_buf )
{
#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)
    return( ( gmtime_s( tm_buf, tt ) == 0 ) ? tm_buf : NULL );
#elif !defined(PLATFORM_UTIL_USE_GMTIME)
    return( gmtime_r( tt, tm_buf ) );
#else
    struct tm *lt;

#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_lock( &mbedtls_threading_gmtime_mutex ) != 0 )
        return( NULL );
#endif /* MBEDTLS_THREADING_C */

    lt = gmtime( tt );

    if( lt != NULL )
    {
        memcpy( tm_buf, lt, sizeof( struct tm ) );
    }

#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &mbedtls_threading_gmtime_mutex ) != 0 )
        return( NULL );
#endif /* MBEDTLS_THREADING_C */

    return( ( lt == NULL ) ? NULL : tm_buf );
#endif /* _WIN32 && !EFIX64 && !EFI32 */
}
#endif /* MBEDTLS_HAVE_TIME_DATE && MBEDTLS_PLATFORM_GMTIME_R_ALT */

#if defined(MBEDTLS_VALIDATE_AES_KEYS_INTEGRITY) || defined(MBEDTLS_VALIDATE_SSL_KEYS_INTEGRITY)
uint32_t mbedtls_hash( const void *data, size_t data_len_bytes )
{
    uint32_t result = 0;
    size_t i;
    /* data_len_bytes - only multiples of 4 are considered, rest is truncated */
    for( i = 0; i < data_len_bytes >> 2; i++ )
    {
        result ^= ( (uint32_t*) data )[i];
    }
    return result;
}
#endif

unsigned char* mbedtls_platform_put_uint32_be( unsigned char *buf,
                                               size_t num )
{
    *buf++ = (unsigned char) ( num >> 24 );
    *buf++ = (unsigned char) ( num >> 16 );
    *buf++ = (unsigned char) ( num >> 8  );
    *buf++ = (unsigned char) ( num       );

    return buf;
}

unsigned char* mbedtls_platform_put_uint24_be( unsigned char *buf,
                                               size_t num )
{
    *buf++ = (unsigned char) ( num >> 16 );
    *buf++ = (unsigned char) ( num >> 8  );
    *buf++ = (unsigned char) ( num       );

    return buf;
}

unsigned char* mbedtls_platform_put_uint16_be( unsigned char *buf,
                                               size_t num )
{
    *buf++ = (unsigned char) ( num >> 8 );
    *buf++ = (unsigned char) ( num      );

    return buf;
}

size_t mbedtls_platform_get_uint32_be( const unsigned char *buf )
{
    return ( ( (unsigned int) buf[0] << 24 ) |
             ( (unsigned int) buf[1] << 16 ) |
             ( (unsigned int) buf[2] <<  8 ) |
             ( (unsigned int) buf[3]       ) );
}

size_t mbedtls_platform_get_uint24_be( const unsigned char *buf )
{
    return ( ( buf[0] << 16 ) |
             ( buf[1] <<  8)  |
             ( buf[2]      ) );
}

size_t mbedtls_platform_get_uint16_be( const unsigned char *buf )
{
    return ( ( buf[0] << 8 )  |
             ( buf[1]      ) );
}
