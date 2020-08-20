/**
 * \file random.h
 *
 * \brief   This file contains the prototypes of helper functions to generate
 *          random numbers for the purpose of testing.
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

#ifndef TEST_RANDOM_H
#define TEST_RANDOM_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    unsigned char *buf;
    size_t length;
} mbedtls_test_rnd_buf_info;

/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} mbedtls_test_rnd_pseudo_info;

/**
 * This function just returns data from rand().
 * Although predictable and often similar on multiple
 * runs, this does not result in identical random on
 * each run. So do not use this if the results of a
 * test depend on the random data that is generated.
 *
 * rng_state shall be NULL.
 */
int mbedtls_test_rnd_std_rand( void *rng_state,
                               unsigned char *output,
                               size_t len );

/**
 * This function only returns zeros
 *
 * rng_state shall be NULL.
 */
int mbedtls_test_rnd_zero_rand( void *rng_state,
                                unsigned char *output,
                                size_t len );

/**
 * This function returns random based on a buffer it receives.
 *
 * rng_state shall be a pointer to a rnd_buf_info structure.
 *
 * The number of bytes released from the buffer on each call to
 * the random function is specified by per_call. (Can be between
 * 1 and 4)
 *
 * After the buffer is empty it will return rand();
 */
int mbedtls_test_rnd_buffer_rand( void *rng_state,
                                  unsigned char *output,
                                  size_t len );

/**
 * This function returns random based on a pseudo random function.
 * This means the results should be identical on all systems.
 * Pseudo random is based on the XTEA encryption algorithm to
 * generate pseudorandom.
 *
 * rng_state shall be a pointer to a rnd_pseudo_info structure.
 */
int mbedtls_test_rnd_pseudo_rand( void *rng_state,
                                  unsigned char *output,
                                  size_t len );

#endif /* TEST_RANDOM_H */
