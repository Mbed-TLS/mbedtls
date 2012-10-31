/*
 *  Elliptic curves over GF(p)
 *
 *  Copyright (C) 2012, Brainspark B.V.
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
 * SEC1-v2 (XXX: insert url)
 * Guide to Elliptic Curve Cryptography - Hankerson, Menezes, Vanstone
 */

#include "polarssl/config.h"

#if defined(POLARSSL_ECP_C)

#include "polarssl/ecp.h"

/*
 * Unallocate (the components of) a point
 */
void ecp_point_free( ecp_point *pt )
{
    if( pt == NULL )
        return;

    pt->is_zero = 1;
    mpi_free( &( pt->X ) );
    mpi_free( &( pt->Y ) );
}

/*
 * Unallocate (the components of) a group
 */
void ecp_group_free( ecp_group *grp )
{
    if( grp == NULL )
        return;

    mpi_free( &( grp->P ) );
    mpi_free( &( grp->B ) );
    mpi_free( &( grp->N ) );
    ecp_point_free( &( grp->G ) );
}



#if defined(POLARSSL_SELF_TEST)

/*
 * Checkup routine
 */
int ecp_self_test( int verbose )
{
    return( verbose++ );
}

#endif

#endif
