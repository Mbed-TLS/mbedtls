/**
 * \file ecp_arith.h
 *
 * \brief Wrappers for internal EC point and coordinate structures
 *        and low-level prime modular arithmetic operating on them
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

#ifndef MBEDTLS_ECP_ARITH_H
#define MBEDTLS_ECP_ARITH_H

/*
 * The internal API consists of the following macros and functions
 *
 * Types
 * =====
 * - mbedtls_ecp_point_internal
 * - mbedtls_ecp_mpi_internal
 * - mbedtls_ecp_group_internal
 *
 * Init/Free
 * =========
 * - mbedtls_ecp_mpi_internal_init
 * - mbedtls_ecp_mpi_internal_free
 * - mbedtls_ecp_point_internal_init
 * - mbedtls_ecp_point_internal_free
 *
 * Getters
 * =======
 * Point getters:
 * - getX, getY, getZ: point -> coordinate
 * Group getters:
 * - getA, getB: group -> coordinate
 * - getB: group -> point
 * - getGrp: internal group -> public group
 *
 * Abstraction for the allocation of temporaries
 * =============================================
 * Point:
 * - ECP_DECL_TEMP_POINT
 * - ECP_SETUP_TEMP_POINT
 * - ECP_FREE_TEMP_POINT
 *
 * Single width coordinate:
 * - ECP_DECL_TEMP_MPI
 * - ECP_SETUP_TEMP_MPI
 * - ECP_FREE_TEMP_MPI
 *
 * Static array of single width coordinates:
 * - ECP_DECL_TEMP_MPI_STATIC_ARRAY
 * - ECP_SETUP_TEMP_MPI_STATIC_ARRAY
 * - ECP_FREE_TEMP_MPI_STATIC_ARRAY
 *
 * Dynamic array of single width coordinates:
 * - #define ECP_DECL_TEMP_MPI_DYNAMIC_ARRAY
 * - #define ECP_SETUP_TEMP_MPI_DYNAMIC_ARRAY
 * - #define ECP_FREE_TEMP_MPI_DYNAMIC_ARRAY
 *
 *
 * Conversion between public and internal types
 * ============================================
 *
 * Input points:
 * - ECP_DECL_INTERNAL_INPUT
 * - ECP_CONVERT_INPUT
 * - ECP_FREE_INTERNAL_INPUT
 *
 * Output points:
 * - ECP_INTERNAL_OUTPUT
 * - ECP_CONVERT_OUTPUT
 * - ECP_DECL_INTERNAL_OUTPUT
 * - ECP_SAVE_INTERNAL_OUTPUT
 * - ECP_FREE_INTERNAL_OUTPUT
 *
 * Input/Output points:
 * - ECP_INTERNAL_INOUT
 * - ECP_DECL_INTERNAL_INOUT
 * - ECP_CONVERT_INOUT
 * - ECP_SAVE_INTERNAL_INOUT
 * - ECP_FREE_INTERNAL_INOUT
 *
 * Group:
 * - ECP_DECL_INTERNAL_GROUP
 * - ECP_CONVERT_GROUP
 * - ECP_SAVE_INTERNAL_GROUP
 * - ECP_FREE_INTERNAL_GROUP
 *
 * Modular arithmetic
 * ==================
 *
 * - ECP_MPI_ADD
 * - ECP_MPI_SUB
 * - ECP_MPI_SUB_INT
 * - ECP_MPI_MUL
 * - ECP_MPI_SQR
 * - ECP_MPI_MUL_INT
 * - ECP_MPI_INV
 * - ECP_MPI_MOV
 * - ECP_MOV
 * - ECP_ZERO
 * - ECP_MPI_SHIFT_L
 * - ECP_MPI_LSET
 * - ECP_MPI_CMP_INT
 * - ECP_MPI_CMP
 * - ECP_MPI_RAND
 * - ECP_MPI_COND_NEG
 * - ECP_MPI_NEG
 * - ECP_MPI_VALID
 * - ECP_MPI_COND_ASSIGN
 * - ECP_MPI_COND_SWAP
 * - ECP_MPI_REDUCE
 */

/* Currently there is only one implementation to choose from:
 *
 * - ECP_ARITH_WRAPPER_FIXSIZE_HEAP:
 *   This wraps public types in dummy structs and ensures that coordinates
 *   have standard size. The underlying modular arithmetic is implemented
 *   by unwrapping and calling mbedtls_mpi_foo() as before.
 *
 * To add a new implementation, add a macro identifier here, implement
 * the new internal types in ecp_arith_foo_typedefs.h and the rest in
 * ecp_arith_foo.h, and conditionally include ecp_arith_foo_typedefs.h below.
 */

#include "mbedtls/build_info.h"
#include "ecp_arith_typedefs.h"

/* Most modular arithmetic operations are needed unconditionally.
 * Modular subtraction and left-shift, however, may be unnecessary
 * provided alternative implementations for suitable parts of the
 * ECP module have been plugged in. */

#if ( defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED) && \
      !( defined(MBEDTLS_ECP_NO_FALLBACK) && \
         defined(MBEDTLS_ECP_DOUBLE_JAC_ALT) && \
         defined(MBEDTLS_ECP_ADD_MIXED_ALT) ) ) || \
    ( defined(MBEDTLS_ECP_MONTGOMERY_ENABLED) && \
      !( defined(MBEDTLS_ECP_NO_FALLBACK) && \
         defined(MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT) ) )
#define ECP_MPI_NEED_SUB_MOD
#endif

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED) && \
    !( defined(MBEDTLS_ECP_NO_FALLBACK) && \
       defined(MBEDTLS_ECP_DOUBLE_JAC_ALT) && \
       defined(MBEDTLS_ECP_ADD_MIXED_ALT) )
#define ECP_MPI_NEED_SHIFT_L_MOD
#endif

#if defined(ECP_ARITH_WRAPPER_FIXSIZE_HEAP)
#include "ecp_arith_wrapper_fixsize_heap.h"
#endif /* ECP_ARITH_WRAPPER_FIXSIZE_HEAP */

#endif /* ecp_arith.h */
