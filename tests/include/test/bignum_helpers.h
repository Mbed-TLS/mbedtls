/**
 * \file bignum_helpers.h
 *
 * \brief   This file contains the prototypes of helper functions for
 *          bignum-related testing.
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

#ifndef TEST_BIGNUM_HELPERS_H
#define TEST_BIGNUM_HELPERS_H

#include <mbedtls/build_info.h>

#if defined(MBEDTLS_BIGNUM_C)

#include <mbedtls/bignum.h>
#include <bignum_mod.h>

/** Allocate and populate a core MPI from a test case argument.
 *
 * This function allocates exactly as many limbs as necessary to fit
 * the length of the input. In other words, it preserves leading zeros.
 *
 * The limb array is allocated with mbedtls_calloc() and must later be
 * freed with mbedtls_free().
 *
 * \param[in,out] pX    The address where a pointer to the allocated limb
 *                      array will be stored.
 *                      \c *pX must be null on entry.
 *                      On exit, \c *pX is null on error or if the number
 *                      of limbs is 0.
 * \param[out] plimbs   The address where the number of limbs will be stored.
 * \param[in] input     The test argument to read.
 *                      It is interpreted as a hexadecimal representation
 *                      of a non-negative integer.
 *
 * \return \c 0 on success, an \c MBEDTLS_ERR_MPI_xxx error code otherwise.
 */
int mbedtls_test_read_mpi_core(mbedtls_mpi_uint **pX, size_t *plimbs,
                               const char *input);

/** Read a modulus from a hexadecimal string.
 *
 * This function allocates exactly as many limbs as necessary to fit
 * the length of the input. In other words, it preserves leading zeros.
 *
 * The limb array is allocated with mbedtls_calloc() and must later be
 * freed with mbedtls_free(). You can do that by calling
 * mbedtls_test_mpi_mod_modulus_free_with_limbs().
 *
 * \param[in,out] N     A modulus structure. It must be initialized, but
 *                      not set up.
 * \param[in] s         The null-terminated hexadecimal string to read from.
 * \param int_rep       The desired representation of residues.
 *
 * \return \c 0 on success, an \c MBEDTLS_ERR_MPI_xxx error code otherwise.
 */
int mbedtls_test_read_mpi_modulus(mbedtls_mpi_mod_modulus *N,
                                  const char *s,
                                  mbedtls_mpi_mod_rep_selector int_rep);

/** Free a modulus and its limbs.
 *
 * \param[in] N         A modulus structure such that there is no other
 *                      reference to `N->p`.
 */
void mbedtls_test_mpi_mod_modulus_free_with_limbs(mbedtls_mpi_mod_modulus *N);

/** Read an MPI from a hexadecimal string.
 *
 * Like mbedtls_mpi_read_string(), but with tighter guarantees around
 * edge cases.
 *
 * - This function guarantees that if \p s begins with '-' then the sign
 *   bit of the result will be negative, even if the value is 0.
 *   When this function encounters such a "negative 0", it
 *   increments #mbedtls_test_case_uses_negative_0.
 * - The size of the result is exactly the minimum number of limbs needed
 *   to fit the digits in the input. In particular, this function constructs
 *   a bignum with 0 limbs for an empty string, and a bignum with leading 0
 *   limbs if the string has sufficiently many leading 0 digits.
 *   This is important so that the "0 (null)" and "0 (1 limb)" and
 *   "leading zeros" test cases do what they claim.
 *
 * \param[out] X        The MPI object to populate. It must be initialized.
 * \param[in] s         The null-terminated hexadecimal string to read from.
 *
 * \return \c 0 on success, an \c MBEDTLS_ERR_MPI_xxx error code otherwise.
 */
int mbedtls_test_read_mpi(mbedtls_mpi *X, const char *s);

/** Nonzero if the current test case had an input parsed with
 * mbedtls_test_read_mpi() that is a negative 0 (`"-"`, `"-0"`, `"-00"`, etc.,
 * constructing a result with the sign bit set to -1 and the value being
 * all-limbs-0, which is not a valid representation in #mbedtls_mpi but is
 * tested for robustness).
 */
extern unsigned mbedtls_test_case_uses_negative_0;

#endif /* MBEDTLS_BIGNUM_C */

#endif /* TEST_BIGNUM_HELPERS_H */
