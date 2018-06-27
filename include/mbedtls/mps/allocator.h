/**
 * \file allocator.h
 *
 * \brief The allocation interface used by various parts of MPS
 *        to acquire and release memory.
 *
 *  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_MPS_ALLOCATOR_H
#define MBEDTLS_MPS_ALLOCATOR_H

#include <stdio.h>
#include <stdint.h>

struct mps_alloc;
typedef struct mps_alloc mps_alloc;

/* TODO: Integrate MPS error codes with rest of the library. */
#define MPS_ERR_ALLOC_OUT_OF_SPACE    0x1
#define MPS_ERR_ALLOC_NOT_ALLOCATED   0x2
#define MPS_ERR_ALLOC_INVALID_PURPOSE 0x3

typedef enum
{
    MPS_ALLOC_L1_IN = 0,
    MPS_ALLOC_L1_OUT
} mps_alloc_type;

/**
 * \brief           Initialize an MPS allocator context.
 *
 * \param ctx        The allocator context to initialize.
 * \param l1_len     The length of the buffers passed to the
 *                   read- and write-sides of MPS Layer 1.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 */
int mps_alloc_init( mps_alloc *ctx,
                    size_t l1_len );

/**
 * \brief           Free an MPS allocator context.
 *
 * \param ctx       The allocator context to free.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 */
int mps_alloc_free( mps_alloc *ctx );

/**
 * \brief           Request a buffer for a given purpose from the allocator.
 *
 * \param ctx       The allocator context to use.
 * \param purpose   The identifier indicating the purpose of the buffer.
 * \param buf       The address to which to write the address of the
 *                  buffer returned from allocator.
 * \param buflen    The address to which to write the length of the
 *                  provided buffer.
 *
 * \return          \c 0 on success.
 * \return          #MPS_ERR_ALLOC_INVALID_PURPOSE if the provided
 *                  purpose is invalid.
 * \return          #MPS_ERR_ALLOC_OUT_OF_SPACE if a buffer
 *                  for the requested purpose couldn't be provided.
 */
int mps_alloc_acquire( mps_alloc *ctx, mps_alloc_type purpose,
                       unsigned char **buf, size_t *buflen );

/**
 * \brief           Release a buffer previously acquired from the allocator.
 *
 * \param ctx       The allocator context to use.
 * \param purpose   The identifier indicating the purpose of the buffer.
 *
 * \return          \c 0 on success.
 * \return          #MPS_ERR_ALLOC_INVALID_PURPOSE if the provided
 *                  purpose is invalid.
 * \return          #MPS_ERR_ALLOC_NOT_ALLOCATED if the buffer
 *                  hasn't been allocated.
 */
int mps_alloc_release( mps_alloc* ctx, mps_alloc_type purpose );

/**
 * \brief     Reference implementation of the allocator, maintaining
 *            different buffers for each purpose.
 */
struct mps_alloc
{
    uint32_t       alloc_state; /*!< Bit-flag indicating the status
                                 *   of allocation. */

    unsigned char *l1_in;      /*!< The buffer for the read-side of Layer 1. */
    size_t         l1_in_len;  /*!< The length in bytes of l1_in.            */

    unsigned char *l1_out;     /*!< The buffer for the write-side of Layer 1. */
    size_t         l1_out_len; /*!< The length in bytes of l1_out.            */
};

#endif /* MBEDTLS_MPS_ALLOCATOR_H */
