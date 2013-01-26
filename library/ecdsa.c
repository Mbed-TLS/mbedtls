/*
 *  Elliptic curve DSA
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
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

/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 */

#include "polarssl/config.h"

#if defined(POLARSSL_ECDSA_C)

#include "polarssl/ecdsa.h"

/*
 * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
 */
int ecdsa_sign( const ecp_group *grp, mpi *r, mpi *s,
                const mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, key_tries, sign_tries;
    size_t n_size;
    ecp_point R;
    mpi k, e;

    ecp_point_init( &R );
    mpi_init( &k );
    mpi_init( &e );

    sign_tries = 0;
    do
    {
        /*
         * Steps 1-3: generate a suitable ephemeral keypair
         */
        key_tries = 0;
        do
        {
            MPI_CHK( ecp_gen_keypair( grp, &k, &R, f_rng, p_rng ) );
            MPI_CHK( mpi_copy( r, &R.X ) );

            if( key_tries++ > 10 )
                return( POLARSSL_ERR_ECP_GENERIC );
        }
        while( mpi_cmp_int( r, 0 ) == 0 );

        /*
         * Step 5: derive MPI from hashed message
         */
        n_size = (grp->nbits + 7) / 8;
        MPI_CHK( mpi_read_binary( &e, buf, blen > n_size ? n_size : blen ) );

        /*
         * Step 6: compute s = (e + r * d) / k mod n
         */
        MPI_CHK( mpi_mul_mpi( s, r, d ) );
        MPI_CHK( mpi_add_mpi( &e, &e, s ) );
        MPI_CHK( mpi_inv_mod( s, &k, &grp->N ) );
        MPI_CHK( mpi_mul_mpi( s, s, &e ) );
        MPI_CHK( mpi_mod_mpi( s, s, &grp->N ) );

        if( sign_tries++ > 10 )
            return( POLARSSL_ERR_ECP_GENERIC );
    }
    while( mpi_cmp_int( s, 0 ) == 0 );

cleanup:
    ecp_point_free( &R );
    mpi_free( &k );
    mpi_free( &e );

    return( ret );
}

#if defined(POLARSSL_SELF_TEST)

/*
 * Checkup routine
 */
int ecdsa_self_test( int verbose )
{
    return( verbose++ );
}

#endif

#endif /* defined(POLARSSL_ECDSA_C) */
