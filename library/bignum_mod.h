/**
 *  Modular bignum functions
 *
 * This module implements operations on integers modulo some fixed modulus.
 */

/*
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

/* Skip 1 as it is slightly easier to accidentally pass to functions. */
typedef enum
{
    MBEDTLS_MPI_MOD_REP_INVALID    = 0,
    MBEDTLS_MPI_MOD_REP_MONTGOMERY = 2,
    MBEDTLS_MPI_MOD_REP_OPT_RED
} mbedtls_mpi_mod_rep_selector;

/* Make mbedtls_mpi_mod_rep_selector and mbedtls_mpi_mod_ext_rep disjoint to
 * make it easier to catch when they are accidentally swapped. */
typedef enum
{
    MBEDTLS_MPI_MOD_EXT_REP_INVALID = 0,
    MBEDTLS_MPI_MOD_EXT_REP_LE      = 8,
    MBEDTLS_MPI_MOD_EXT_REP_BE
} mbedtls_mpi_mod_ext_rep;

typedef struct
{
    mbedtls_mpi_uint *p;
    size_t limbs;
} mbedtls_mpi_mod_residue;

typedef struct {
    mbedtls_mpi_uint const *rr;  /* The residue for 2^{2*n*biL} mod N */
    mbedtls_mpi_uint mm;         /* Montgomery const for -N^{-1} mod 2^{ciL} */
} mbedtls_mpi_mont_struct;

typedef void *mbedtls_mpi_opt_red_struct;

typedef struct {
    const mbedtls_mpi_uint *p;
    size_t limbs;                            // number of limbs
    size_t bits;                             // bitlen of p
    mbedtls_mpi_mod_ext_rep ext_rep;         // signals external representation (eg. byte order)
    mbedtls_mpi_mod_rep_selector int_rep;    // selector to signal the active member of the union
    union rep
    {
        mbedtls_mpi_mont_struct mont;
        mbedtls_mpi_opt_red_struct ored;
    } rep;
} mbedtls_mpi_mod_modulus;

/** Setup a residue structure.
 *
 * \param[out] r    The address of residue to setup. The size is determined by
 *                  \p m.
 *                  (In particular, it must have at least as many limbs as the
 *                  modulus \p m.)
 * \param[in] m     The address of the modulus related to \p r.
 * \param[in] p     The address of the limb array storing the value of \p r.
 *                  The memory pointed to by \p p will be used by \p r and must
 *                  not be modified in any way until after
 *                  mbedtls_mpi_mod_residue_release() is called.
 * \param p_limbs   The number of limbs of \p p.
 *
 * \return      \c 0 if successful.
 * \return      #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if \p p_limbs is less than the
 *              limbs in \p m or if \p p is not less than \p m.
 */
int mbedtls_mpi_mod_residue_setup( mbedtls_mpi_mod_residue *r,
                                   const mbedtls_mpi_mod_modulus *m,
                                   mbedtls_mpi_uint *p,
                                   size_t p_limbs );

/** Unbind elements of a residue structure.
 *
 * This function removes the reference to the limb array that was passed to
 * mbedtls_mpi_mod_residue_setup() to make it safe to free or use again.
 *
 * This function invalidates \p r and it must not be used until after
 * mbedtls_mpi_mod_residue_setup() is called on it again.
 *
 * \param[out] r     The address of residue to release.
 */
void mbedtls_mpi_mod_residue_release( mbedtls_mpi_mod_residue *r );

/** Initialize a modulus structure.
 *
 * \param[out] m     The address of the modulus structure to initialize.
 */
void mbedtls_mpi_mod_modulus_init( mbedtls_mpi_mod_modulus *m );

/** Setup a modulus structure.
 *
 * \param[out] m    The address of the modulus structure to populate.
 * \param[in] p     The address of the limb array storing the value of \p m.
 *                  The memory pointed to by \p p will be used by \p m and must
 *                  not be modified in any way until after
 *                  mbedtls_mpi_mod_modulus_free() is called.
 * \param p_limbs   The number of limbs of \p p.
 * \param ext_rep   The external representation to be used for residues
 *                  associated with \p m (see #mbedtls_mpi_mod_ext_rep).
 * \param int_rep   The internal representation to be used for residues
 *                  associated with \p m (see #mbedtls_mpi_mod_rep_selector).
 *
 * \return      \c 0 if successful.
 * \return      #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if \p ext_rep or \p int_rep is
 *              invalid.
 */
int mbedtls_mpi_mod_modulus_setup( mbedtls_mpi_mod_modulus *m,
                                   const mbedtls_mpi_uint *p,
                                   size_t p_limbs,
                                   mbedtls_mpi_mod_ext_rep ext_rep,
                                   mbedtls_mpi_mod_rep_selector int_rep );

/** Free elements of a modulus structure.
 *
 * This function frees any memory allocated by mbedtls_mpi_mod_modulus_setup().
 *
 * \warning This function does not free the limb array passed to
 *          mbedtls_mpi_mod_modulus_setup() only removes the reference to it,
 *          making it safe to free or to use it again.
 *
 * \param[in,out] m     The address of the modulus structure to free.
 */
void mbedtls_mpi_mod_modulus_free( mbedtls_mpi_mod_modulus *m );

/* BEGIN MERGE SLOT 1 */

/* END MERGE SLOT 1 */

/* BEGIN MERGE SLOT 2 */

/* END MERGE SLOT 2 */

/* BEGIN MERGE SLOT 3 */

/* END MERGE SLOT 3 */

/* BEGIN MERGE SLOT 4 */

/* END MERGE SLOT 4 */

/* BEGIN MERGE SLOT 5 */

/* END MERGE SLOT 5 */

/* BEGIN MERGE SLOT 6 */

/* END MERGE SLOT 6 */

/* BEGIN MERGE SLOT 7 */

/* END MERGE SLOT 7 */

/* BEGIN MERGE SLOT 8 */

/* END MERGE SLOT 8 */

/* BEGIN MERGE SLOT 9 */

/* END MERGE SLOT 9 */

/* BEGIN MERGE SLOT 10 */

/* END MERGE SLOT 10 */

#endif /* MBEDTLS_BIGNUM_MOD_H */
