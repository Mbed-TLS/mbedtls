/**
 * \file entropy_poll.h
 *
 * \brief Platform-specific and custom entropy polling functions
 */
/*
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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
#ifndef MBEDTLS_ENTROPY_POLL_H
#define MBEDTLS_ENTROPY_POLL_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Default thresholds for built-in sources, in bytes
 */
#define MBEDTLS_ENTROPY_MIN_PLATFORM     32     /**< Minimum for platform source    */
#define MBEDTLS_ENTROPY_MIN_HAVEGE       32     /**< Minimum for HAVEGE             */
#define MBEDTLS_ENTROPY_MIN_HARDCLOCK     4     /**< Minimum for mbedtls_timing_hardclock()        */
#if !defined(MBEDTLS_ENTROPY_MIN_HARDWARE)
#define MBEDTLS_ENTROPY_MIN_HARDWARE     32     /**< Minimum for the hardware source */
#endif

/**
 * \brief           Entropy poll callback that provides 0 entropy.
 */
#if defined(MBEDTLS_TEST_NULL_ENTROPY)
    int mbedtls_null_entropy_poll( void *data,
                                unsigned char *output, size_t len, size_t *olen );
#endif

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
/**
 * \brief           Platform-specific entropy initialization
 *
 * Most applications do not need to call this function directly, because
 * it is called from mbedtls_entropy_init(). You may call it explicitly
 * to initialize the platform entropy sources earlier.
 *
 * - On POSIX/Unix-like platforms, this function opens `/dev/urandom`.
 * - On Windows, this function does nothing.
 * - If you port this library to another platform and do not define
 *   `MBEDTLS_NO_PLATFORM_ENTROPY`, you will need to implement this
 *   function. This may be a function that does nothing if
 *   mbedtls_platform_entropy_poll() does not require prior initialization.
 */
int mbedtls_platform_entropy_init( void );

/**
 * \brief           Platform-specific entropy poll callback
 *
 * This function is meant to be registered with mbedtls_entropy_add_source().
 *
 * - On Windows, this function calls CryptGenRandom().
 * - On Linux, this function calls the getrandom() system call if it is
 *   available both at build time and at compile time.
 * - On Unix/POSIX platforms, including Linux without getrandom(), this
 *   function reads from `/dev/urandom`.
 * - If you port this library to another platform, you should write an
 *   implementation of this function that accesses the randomness source
 *   provided by the operating system or hardware. If there is no randomness
 *   source, build the library with the macro `MBEDTLS_NO_PLATFORM_ENTROPY`
 *   defined.
 *
 * \param data      Unused.
 * \param output    Output buffer.
 * \param len       Number of bytes requested.
 * \param olen      Number of bytes of entropy written to \c output.
 *
 * \return          0 for success,
 *                  or MBEDTLS_ERR_ENTROPY_SOURCE_FAILED on failure.
 */
int mbedtls_platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen );
#endif

#if defined(MBEDTLS_HAVEGE_C)
/**
 * \brief           HAVEGE-based entropy poll callback
 *
 * This function is meant to be registered with mbedtls_entropy_add_source().
 *
 * \param data      Pointer to a #mbedtls_havege_state structure.
 * \param output    Output buffer.
 * \param len       Number of bytes requested.
 * \param olen      Number of bytes of entropy written to \c output.
 *
 * \return          0 for success,
 *                  or MBEDTLS_ERR_ENTROPY_SOURCE_FAILED on failure.
 */
int mbedtls_havege_poll( void *data,
                 unsigned char *output, size_t len, size_t *olen );
#endif

#if defined(MBEDTLS_TIMING_C)
/**
 * \brief           mbedtls_timing_hardclock-based entropy poll callback
 *
 * This function is meant to be registered with mbedtls_entropy_add_source().
 *
 * \warning         This function gathers entropy from timing variations.
 *                  This is generally a poor source of entropy, especially
 *                  on a system with light load. It should only be used
 *                  as a complement of other, stronger entropy sources.
 *
 * \param data      Unused.
 * \param output    Output buffer.
 * \param len       Number of bytes requested.
 * \param olen      Number of bytes of entropy written to \c output.
 *
 * \return          0 for success,
 *                  or MBEDTLS_ERR_ENTROPY_SOURCE_FAILED on failure.
 */
int mbedtls_hardclock_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen );
#endif

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
/**
 * \brief           Entropy poll callback for a hardware source
 *
 * \warning         This is not provided by mbed TLS!
 *                  See \c MBEDTLS_ENTROPY_HARDWARE_ALT in config.h.
 *
 * This function is meant to be registered with mbedtls_entropy_add_source().
 *
 * \param data      Custom data. The function *must* accept \c NULL as the
 *                  \c data argument.
 * \param output    Output buffer.
 * \param len       Number of bytes requested.
 * \param olen      Number of bytes of entropy written to \c output.
 *
 * \return          0 for success,
 *                  or MBEDTLS_ERR_ENTROPY_SOURCE_FAILED on failure.
 */
int mbedtls_hardware_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen );
#endif

#if defined(MBEDTLS_ENTROPY_NV_SEED)
/**
 * \brief           Entropy poll callback for a non-volatile seed file
 *
 * This function is meant to be registered with mbedtls_entropy_add_source().
 *
 * This function reads and updates a seed file by calling
 * mbedtls_nv_seed_read() and mbedtls_nv_seed_write(). The default
 * implementation of these functions is mbedtls_platform_std_nv_seed_read()
 * and mbedtls_platform_std_nv_seed_write() respectively but they may be
 * overridden at build time.
 *
 * \param data      Unused.
 * \param output    Output buffer.
 * \param len       Number of bytes requested.
 * \param olen      Number of bytes of entropy written to \c output.
 *
 * \return          0 for success,
 *                  or MBEDTLS_ERR_ENTROPY_SOURCE_FAILED on failure.
 */
int mbedtls_nv_seed_poll( void *data,
                          unsigned char *output, size_t len, size_t *olen );
#endif

#ifdef __cplusplus
}
#endif

#endif /* entropy_poll.h */
