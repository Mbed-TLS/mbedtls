/**
 *  Internal bignum functions
 *
 *  Copyright The Mbed TLS Contributors
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
 */

#include "common.h"

#if defined(MBEDTLS_BIGNUM_C)

#include "mbedtls/error.h"
#include "mbedtls/bignum.h"
#include "bignum_mod.h"

#define ciL    (sizeof(mbedtls_mpi_uint))   /* chars in limb  */
#define biL    (ciL << 3)                   /* bits  in limb  */
#define biH    (ciL << 2)                   /* half limb size */

/*
 * Convert between bits/chars and number of limbs
 * Divide first in order to avoid potential overflows
 */
#define BITS_TO_LIMBS(i)  ( (i) / biL + ( (i) % biL != 0 ) )
#define CHARS_TO_LIMBS(i) ( (i) / ciL + ( (i) % ciL != 0 ) )

/*
 * Count leading zero bits in a given integer
 */
static size_t mpi_clz( const mbedtls_mpi_uint x )
{
    size_t j;
    mbedtls_mpi_uint mask = (mbedtls_mpi_uint) 1 << (biL - 1);

    for( j = 0; j < biL; j++ )
    {
        if( x & mask ) break;

        mask >>= 1;
    }

    return j;
}

/*
 * Return the number of bits
 */
static size_t mpi_bitlen( const mbedtls_mpi_uint *X, size_t nx )
{
    size_t i, j;

    if( nx == 0 )
        return( 0 );

    for( i = nx - 1; i > 0; i-- )
        if( X[i] != 0 )
            break;

    j = biL - mpi_clz( X[i] );

    return( ( i * biL ) + j );
}

void mbedtls_mpi_mod_residue_release( mbedtls_mpi_mod_residue *r )
{
    if ( r == NULL )
        return;

    r->n = 0;
    r->p = NULL;
}

int mbedtls_mpi_mod_residue_setup( mbedtls_mpi_mod_residue *r,
                                   mbedtls_mpi_mod_modulus *m,
                                   mbedtls_mpi_uint *X )
{
    if( X == NULL || m == NULL || r == NULL || X >= m->p)
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    r->n = m->n;
    r->p = X;

    return( 0 );
}

void mbedtls_mpi_mod_modulus_init( mbedtls_mpi_mod_modulus *m )
{
    if ( m == NULL )
        return;

    m->rep.mont = 0;
}

void mbedtls_mpi_mod_modulus_free( mbedtls_mpi_mod_modulus *m )
{
    if ( m == NULL )
        return;

    m->p = NULL;
    m->n = 0;
    m->plen = 0;
    m->ext_rep = 0;
    m->int_rep = 0;
    m->rep.mont = NULL;
    m->rep.ored = NULL;
}

int mbedtls_mpi_mod_modulus_setup( mbedtls_mpi_mod_modulus *m,
                                   mbedtls_mpi_uint *X,
                                   size_t nx,
                                   int ext_rep,
                                   int int_rep )
{
    if ( X == NULL || m == NULL )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    m->p = X;
    m->n = nx;
    m->ext_rep = ext_rep;
    m->int_rep = int_rep;
    m->plen = mpi_bitlen( X, nx );

    return( 0 );
}

#endif /* MBEDTLS_BIGNUM_C */
