/*
 *  Diffie-Hellman-Merkle key exchange (prime generation)
 *
 *  Copyright (C) 2006-2012, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_FS_IO) && defined(MBEDTLS_CTR_DRBG_C) && \
    defined(MBEDTLS_GENPRIME)
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <stdio.h>
#include <string.h>
#endif

/*
 * Note: G = 4 is always a quadratic residue mod P,
 * so it is a generator of order Q (with P = 2*Q+1).
 */
#define DH_P_SIZE 1024
#define GENERATOR "4"

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||   \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_CTR_DRBG_C) ||     \
    !defined(MBEDTLS_GENPRIME)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_FS_IO and/or MBEDTLS_CTR_DRBG_C and/or "
           "MBEDTLS_GENPRIME not defined.\n");
    return( 0 );
}
#else
int main( void )
{
    int ret = 1;
    mbedtls_mpi G, P, Q;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "dh_genprime";
    FILE *fout;

    mbedtls_mpi_init( &G ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    if( ( ret = mbedtls_mpi_read_string( &G, 10, GENERATOR ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_string returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( "\nWARNING: You should not generate and use your own DHM primes\n" );
    mbedtls_printf( "         unless you are very certain of what you are doing!\n" );
    mbedtls_printf( "         Failing to follow this instruction may result in\n" );
    mbedtls_printf( "         weak security for your connections! Use the\n" );
    mbedtls_printf( "         predefined DHM parameters from dhm.h instead!\n\n" );
    mbedtls_printf( "============================================================\n\n" );

    mbedtls_printf( "  ! Generating large primes may take minutes!\n" );

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n  . Generating the modulus, please wait..." );
    fflush( stdout );

    /*
     * This can take a long time...
     */
    if( ( ret = mbedtls_mpi_gen_prime( &P, DH_P_SIZE, 1,
                               mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_gen_prime returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n  . Verifying that Q = (P-1)/2 is prime..." );
    fflush( stdout );

    if( ( ret = mbedtls_mpi_sub_int( &Q, &P, 1 ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_sub_int returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_div_int( &Q, NULL, &Q, 2 ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_div_int returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_is_prime( &Q, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_is_prime returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n  . Exporting the value in dh_prime.txt..." );
    fflush( stdout );

    if( ( fout = fopen( "dh_prime.txt", "wb+" ) ) == NULL )
    {
        ret = 1;
        mbedtls_printf( " failed\n  ! Could not create dh_prime.txt\n\n" );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_write_file( "P = ", &P, 16, fout ) != 0 ) ||
        ( ret = mbedtls_mpi_write_file( "G = ", &G, 16, fout ) != 0 ) )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n\n" );
    fclose( fout );

exit:

    mbedtls_mpi_free( &G ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    mbedtls_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_FS_IO &&
          MBEDTLS_CTR_DRBG_C && MBEDTLS_GENPRIME */
