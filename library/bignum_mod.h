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

#ifndef MBEDTLS_BIGNUM_MOD_H
#define MBEDTLS_BIGNUM_MOD_H

#include "common.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif


typedef struct
{
    size_t n;
    mbedtls_mpi_uint *p;
} mbedtls_mpi_mod_residue;

typedef void* mbedtls_mpi_mont_struct;
typedef void* mbedtls_mpi_opt_red_struct;

typedef struct {
    mbedtls_mpi_uint *p;
    size_t n;       // number of limbs
    size_t plen;    // bitlen of p
    int ext_rep;    // signals external representation (eg. byte order)
    int int_rep;    // selector to signal the active member of the union
    union rep
    {
        mbedtls_mpi_mont_struct mont;
        mbedtls_mpi_opt_red_struct ored;
    } rep;
} mbedtls_mpi_mod_modulus;

typedef enum
{
    MBEDTLS_MPI_MOD_REP_INVALID    = 0,
    MBEDTLS_MPI_MOD_REP_MONTGOMERY,
    MBEDTLS_MPI_MOD_REP_OPT_RED
} mbedtls_mpi_mod_rep_selector;

typedef enum
{
    MBEDTLS_MPI_MOD_EXT_REP_INVALID    = 0,
    MBEDTLS_MPI_MOD_EXT_REP_LE,
    MBEDTLS_MPI_MOD_EXT_REP_BE
} mbedtls_mpi_mod_ext_rep;

void mbedtls_mpi_mod_residue_release( mbedtls_mpi_mod_residue *r );

int mbedtls_mpi_mod_residue_setup( mbedtls_mpi_mod_residue *r,
                                   mbedtls_mpi_mod_modulus *m,
                                   mbedtls_mpi_uint *p,
                                   size_t pn );

void mbedtls_mpi_mod_modulus_init( mbedtls_mpi_mod_modulus *m );

void mbedtls_mpi_mod_modulus_free( mbedtls_mpi_mod_modulus *m );

int mbedtls_mpi_mod_modulus_setup( mbedtls_mpi_mod_modulus *m,
                                   mbedtls_mpi_uint *p,
                                   size_t n,
                                   int ext_rep,
                                   int int_rep );

#endif /* MBEDTLS_BIGNUM_MOD_H */
