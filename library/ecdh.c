/*
 *  Elliptic curve Diffie-Hellman
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

#if defined(POLARSSL_ECP_C)

#include "polarssl/ecdh.h"

/*
 * Generate public key: simple wrapper around ecp_gen_keypair
 */
int ecdh_gen_public( const ecp_group *grp, mpi *d, ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    return ecp_gen_keypair( grp, d, Q, f_rng, p_rng );
}

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int ecdh_compute_shared( const ecp_group *grp, mpi *z,
                         const ecp_point *Q, const mpi *d )
{
    int ret;
    ecp_point P;

    ecp_point_init( &P );

    /*
     * Make sure Q is a valid pubkey before using it
     */
    MPI_CHK( ecp_check_pubkey( grp, Q ) );

    MPI_CHK( ecp_mul( grp, &P, d, Q ) );

    if( ecp_is_zero( &P ) )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    MPI_CHK( mpi_copy( z, &P.X ) );

cleanup:
    ecp_point_free( &P );

    return( ret );
}


#if defined(POLARSSL_SELF_TEST)

/*
 * Checkup routine
 */
int ecdh_self_test( int verbose )
{
    return( verbose++ );
}

#endif

#endif /* defined(POLARSSL_ECP_C) */
