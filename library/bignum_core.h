/**
 *  Core bignum functions
 *
 *  This interface only should be used by the legacy bignum module (bignum.h)
 *  and the modular bignum modules (bignum_mod.c, bignum_mod_raw.c). All other
 *  modules should use the high level modular bignum interface (bignum_mod.h)
 *  or the legacy bignum interface (bignum.h).
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

#ifndef MBEDTLS_BIGNUM_CORE_H
#define MBEDTLS_BIGNUM_CORE_H

#include "common.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

/** Count leading zero bits in a given integer.
 *
 * \param x     Integer to count leading zero bits.
 *
 * \return      The number of leading zero bits in \p x.
 */
size_t mbedtls_mpi_core_clz( const mbedtls_mpi_uint x );

/** Return the the minimum number of bits required to represent the value held
 * in the MPI.
 *
 * \note This function returns 0 if all the limbs of \p X are 0.
 *
 * \param X     The address of the MPI.
 * \param nx    The number of limbs of \p X.
 *
 * \return      The number of bits in \p X.
 */
size_t mbedtls_mpi_core_bitlen( const mbedtls_mpi_uint *X, size_t nx );

/** Convert a big-endian byte array aligned to the size of mbedtls_mpi_uint
 * into the storage form used by mbedtls_mpi.
 *
 * \param X     The address of the MPI.
 * \param limbs The number of limbs of \p X.
 */
void mbedtls_mpi_core_bigendian_to_host( mbedtls_mpi_uint * const X,
                                         size_t limbs );

/** Import X from unsigned binary data, little endian.
 *
 * The MPI needs to have enough limbs to store the full value (including any
 * most significant zero bytes in the input).
 *
 * \param X      The address of the MPI.
 * \param nx     The number of limbs of \p X.
 * \param buf    The input buffer to import from.
 * \param buflen The length in bytes of \p buf.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p X isn't
 *               large enough to hold the value in \p buf.
 */
int mbedtls_mpi_core_read_le( mbedtls_mpi_uint *X,
                              size_t nx,
                              const unsigned char *buf,
                              size_t buflen );

/** Import X from unsigned binary data, big endian.
 *
 * The MPI needs to have enough limbs to store the full value (including any
 * most significant zero bytes in the input).
 *
 * \param X      The address of the MPI.
 *               May only be #NULL if \nx is 0 and \p buflen is 0.
 * \param nx     The number of limbs of \p X.
 * \param buf    The input buffer to import from.
 *               May only be #NULL if \p buflen is 0.
 * \param buflen The length in bytes of \p buf.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p X isn't
 *               large enough to hold the value in \p buf.
 */
int mbedtls_mpi_core_read_be( mbedtls_mpi_uint *X,
                              size_t nx,
                              const unsigned char *buf,
                              size_t buflen );

/** Export X into unsigned binary data, little endian.
 *
 * \note If \p buf is shorter than \p X the export is still successful if the
 *       value held in \p X fits in the buffer (that is, if enough of the most
 *       significant bytes of \p X are 0).
 *
 * \param X      The address of the MPI.
 * \param nx     The number of limbs of \p X.
 * \param buf    The output buffer to export to.
 * \param buflen The length in bytes of \p buf.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p buf isn't
 *               large enough to hold the value of \p X.
 */
int mbedtls_mpi_core_write_le( const mbedtls_mpi_uint *X,
                               size_t nx,
                               unsigned char *buf,
                               size_t buflen );

/** Export X into unsigned binary data, big endian.
 *
 * \note If \p buf is shorter than \p X the export is still successful if the
 *       value held in \p X fits in the buffer (that is, if enough of the most
 *       significant bytes of \p X are 0).
 *
 * \param X      The address of the MPI.
 * \param nx     The number of limbs of \p X.
 * \param buf    The output buffer to export to.
 * \param buflen The length in bytes of \p buf.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p buf isn't
 *               large enough to hold the value of \p X.
 */
int mbedtls_mpi_core_write_be( const mbedtls_mpi_uint *X,
                               size_t nx,
                               unsigned char *buf,
                               size_t buflen );

#define ciL    (sizeof(mbedtls_mpi_uint))   /* chars in limb  */
#define biL    (ciL << 3)                   /* bits  in limb  */
#define biH    (ciL << 2)                   /* half limb size */

/*
 * Convert between bits/chars and number of limbs
 * Divide first in order to avoid potential overflows
 */
#define BITS_TO_LIMBS(i)  ( (i) / biL + ( (i) % biL != 0 ) )
#define CHARS_TO_LIMBS(i) ( (i) / ciL + ( (i) % ciL != 0 ) )
/* Get a specific byte, without range checks. */
#define GET_BYTE( X, i )                                \
    ( ( ( X )[( i ) / ciL] >> ( ( ( i ) % ciL ) * 8 ) ) & 0xff )

#endif /* MBEDTLS_BIGNUM_CORE_H */
