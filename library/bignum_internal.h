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

#ifndef MBEDTLS_BIGNUM_INTERNAL_H
#define MBEDTLS_BIGNUM_INTERNAL_H

#include "common.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

/** Helper for mbedtls_mpi multiplication.
 *
 * Add \p b * \p s to \p d.
 *
 * \param[in,out] d     The bignum to add to.
 * \param d_len         The number of limbs of \p d. This must be
 *                      at least \p s_len.
 * \param s_len         The number of limbs of \p s.
 * \param[in] s         A bignum to multiply, of size \p i.
 *                      It may overlap with \p d, but only if
 *                      \p d <= \p s.
 *                      Its leading limb must not be \c 0.
 * \param b             A scalar to multiply.
 *
 * \return c            The carry at the end of the operation.
 */
mbedtls_mpi_uint mbedtls_mpi_core_mla( mbedtls_mpi_uint *d, size_t d_len ,
                                       const mbedtls_mpi_uint *s, size_t s_len,
                                       mbedtls_mpi_uint b );

#endif /* MBEDTLS_BIGNUM_INTERNAL_H */
