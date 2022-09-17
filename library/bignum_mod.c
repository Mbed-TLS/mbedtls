/**
 *  Modular bignum functions
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

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf      printf
#define mbedtls_calloc      calloc
#define mbedtls_free        free
#endif

#include "bignum_core.h"
#include "bignum_mod.h"
#include "bignum_mod_raw.h"
#include "constant_time_internal.h"

int mbedtls_mpi_mod_residue_setup( mbedtls_mpi_mod_residue *r,
                                   const mbedtls_mpi_mod_modulus *m,
                                   mbedtls_mpi_uint *p,
                                   size_t p_limbs )
{
    if( p_limbs < m->limbs || !mbedtls_mpi_core_lt_ct( m->p, p, p_limbs ) )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    r->limbs = m->limbs;
    r->p = p;

    return( 0 );
}

void mbedtls_mpi_mod_residue_release( mbedtls_mpi_mod_residue *r )
{
    if ( r == NULL )
        return;

    r->limbs = 0;
    r->p = NULL;
}

void mbedtls_mpi_mod_modulus_init( mbedtls_mpi_mod_modulus *m )
{
    if ( m == NULL )
        return;

    m->p = NULL;
    m->limbs = 0;
    m->bits = 0;
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
            mbedtls_free( m->rep.mont );
            break;
        case MBEDTLS_MPI_MOD_REP_OPT_RED:
            mbedtls_free( m->rep.ored );
            break;
        case MBEDTLS_MPI_MOD_REP_INVALID:
            break;
    }

    m->p = NULL;
    m->limbs = 0;
    m->bits = 0;
    m->ext_rep = MBEDTLS_MPI_MOD_EXT_REP_INVALID;
    m->int_rep = MBEDTLS_MPI_MOD_REP_INVALID;
}

int mbedtls_mpi_mod_modulus_setup( mbedtls_mpi_mod_modulus *m,
                                   const mbedtls_mpi_uint *p,
                                   size_t p_limbs,
                                   mbedtls_mpi_mod_ext_rep ext_rep,
                                   mbedtls_mpi_mod_rep_selector int_rep )
{
    int ret = 0;

    m->p = p;
    m->limbs = p_limbs;
    m->bits = mbedtls_mpi_core_bitlen( p, p_limbs );

    switch( ext_rep )
    {
        case MBEDTLS_MPI_MOD_EXT_REP_LE:
        case MBEDTLS_MPI_MOD_EXT_REP_BE:
            m->ext_rep = ext_rep;
            break;
        default:
            ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
            goto exit;
    }

    switch( int_rep )
    {
        case MBEDTLS_MPI_MOD_REP_MONTGOMERY:
            m->int_rep = int_rep;
            m->rep.mont = NULL;
            break;
        case MBEDTLS_MPI_MOD_REP_OPT_RED:
            m->int_rep = int_rep;
            m->rep.ored = NULL;
            break;
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

#endif /* MBEDTLS_BIGNUM_C */
