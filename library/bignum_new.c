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

#include <string.h>

#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/bignum.h"
#include "bignum_core.h"
#include "bignum_mod.h"
#include "bignum_mod_raw.h"
#include "constant_time_internal.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf      printf
#define mbedtls_calloc      calloc
#define mbedtls_free        free
#endif

int mbedtls_mpi_mod_residue_setup( mbedtls_mpi_mod_residue *r,
                                   mbedtls_mpi_mod_modulus *m,
                                   mbedtls_mpi_uint *p,
                                   size_t pn )
{
    if( p == NULL || m == NULL || r == NULL )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    if( pn < m->n || !mbedtls_mpi_core_lt_ct( m->p, p, pn ) )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    r->n = m->n;
    r->p = p;

    return( 0 );
}

void mbedtls_mpi_mod_residue_release( mbedtls_mpi_mod_residue *r )
{
    if ( r == NULL )
        return;

    r->n = 0;
    r->p = NULL;
}

void mbedtls_mpi_mod_modulus_init( mbedtls_mpi_mod_modulus *m )
{
    if ( m == NULL )
        return;

    m->p = NULL;
    m->n = 0;
    m->plen = 0;
    m->ext_rep = MBEDTLS_MPI_MOD_EXT_REP_INVALID;
    m->int_rep = MBEDTLS_MPI_MOD_REP_INVALID;
}

void mbedtls_mpi_mod_modulus_free( mbedtls_mpi_mod_modulus *m )
{
    if ( m == NULL )
        return;

    switch( m->int_rep )
    {
        case MBEDTLS_MPI_MOD_REP_MONTGOMERY:
            mbedtls_free( m->rep.mont ); break;
        case MBEDTLS_MPI_MOD_REP_OPT_RED:
            mbedtls_free( m->rep.ored ); break;
        default:
            break;
    }

    m->p = NULL;
    m->n = 0;
    m->plen = 0;
    m->ext_rep = MBEDTLS_MPI_MOD_EXT_REP_INVALID;
    m->int_rep = MBEDTLS_MPI_MOD_REP_INVALID;
}

int mbedtls_mpi_mod_modulus_setup( mbedtls_mpi_mod_modulus *m,
                                   mbedtls_mpi_uint *p,
                                   size_t pn,
                                   int ext_rep,
                                   int int_rep )
{
    int ret = 0;

    if ( p == NULL || m == NULL )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    m->p = p;
    m->n = pn;
    m->plen = mbedtls_mpi_core_bitlen( p, pn );

    switch( ext_rep )
    {
        case MBEDTLS_MPI_MOD_EXT_REP_LE:
        case MBEDTLS_MPI_MOD_EXT_REP_BE:
            m->ext_rep = ext_rep; break;
        default:
            ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
            goto exit;
    }

    switch( int_rep )
    {
        case MBEDTLS_MPI_MOD_REP_MONTGOMERY:
            m->int_rep = int_rep;
            m->rep.mont = NULL; break;
        case MBEDTLS_MPI_MOD_REP_OPT_RED:
            m->int_rep = int_rep;
            m->rep.ored = NULL; break;
        default:
            ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
            goto exit;
    }

exit:

    if( ret != 0 )
    {
        mbedtls_mpi_mod_modulus_free( m );
    }

    return( ret );
}

int mbedtls_mpi_mod_raw_read( mbedtls_mpi_uint *X,
                              mbedtls_mpi_mod_modulus *m,
                              unsigned char *buf,
                              size_t buflen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( m->ext_rep == MBEDTLS_MPI_MOD_EXT_REP_LE )
        ret = mbedtls_mpi_core_read_le( X, m->n, buf, buflen );

    else if( m->ext_rep == MBEDTLS_MPI_MOD_EXT_REP_BE )
        ret = mbedtls_mpi_core_read_be( X, m->n, buf, buflen );
    else
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    if( ret != 0 )
        goto cleanup;

    if( !mbedtls_mpi_core_lt_ct( X, m->p, m->n ) )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

cleanup:

    return( ret );
}

int mbedtls_mpi_mod_raw_write( mbedtls_mpi_uint *X,
                               mbedtls_mpi_mod_modulus *m,
                               unsigned char *buf,
                               size_t buflen )
{
    if( m->ext_rep == MBEDTLS_MPI_MOD_EXT_REP_LE )
        return mbedtls_mpi_core_write_le( X, m->n, buf, buflen );

    else if( m->ext_rep == MBEDTLS_MPI_MOD_EXT_REP_BE )
        return mbedtls_mpi_core_write_be( X, m->n, buf, buflen );

    else
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    return( 0 );
}

#endif /* MBEDTLS_BIGNUM_C */
