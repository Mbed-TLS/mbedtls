/**
 *  Low level bignum functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_BIGNUM_INTERNAL_H
#define MBEDTLS_BIGNUM_INTERNAL_H

#include "mbedtls/bignum.h"

/**
 * \brief Calculate the square of the Montgomery constant. (Needed
 *        for conversion and operations in Montgomery form.)
 *
 * \param[out] X  A pointer to the result of the calculation of
 *                the square of the Montgomery constant:
 *                2^{2*n*biL} mod N.
 * \param[in]  N  Little-endian presentation of the modulus, which must be odd.
 *
 * \return        0 if successful.
 * \return        #MBEDTLS_ERR_MPI_ALLOC_FAILED if there is not enough space
 *                to store the value of Montgomery constant squared.
 * \return        #MBEDTLS_ERR_MPI_DIVISION_BY_ZERO if \p N modulus is zero.
 * \return        #MBEDTLS_ERR_MPI_NEGATIVE_VALUE if \p N modulus is negative.
 */
int mbedtls_mpi_get_mont_r2_unsafe(mbedtls_mpi *X,
                                   const mbedtls_mpi *N);

#endif /* MBEDTLS_BIGNUM_INTERNAL_H */
