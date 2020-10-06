/**
 * \file helpers.h
 *
 * \brief   This file contains the prototypes of helper functions for the
 *          purpose of testing.
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

#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#define mbedtls_exit       exit
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#include <stddef.h>
#include <stdint.h>

int mbedtls_test_platform_setup( void );
void mbedtls_test_platform_teardown( void );

/**
 * \brief          This function decodes the hexadecimal representation of
 *                 data.
 *
 * \note           The output buffer can be the same as the input buffer. For
 *                 any other overlapping of the input and output buffers, the
 *                 behavior is undefined.
 *
 * \param obuf     Output buffer.
 * \param obufmax  Size in number of bytes of \p obuf.
 * \param ibuf     Input buffer.
 * \param len      The number of unsigned char written in \p obuf. This must
 *                 not be \c NULL.
 *
 * \return         \c 0 on success.
 * \return         \c -1 if the output buffer is too small or the input string
 *                 is not a valid hexadecimal representation.
 */
int mbedtls_test_unhexify( unsigned char *obuf, size_t obufmax,
                           const char *ibuf, size_t *len );

void mbedtls_test_hexify( unsigned char *obuf,
                          const unsigned char *ibuf,
                          int len );

/**
 * Allocate and zeroize a buffer.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
unsigned char *mbedtls_test_zero_alloc( size_t len );

/**
 * Allocate and fill a buffer from hex data.
 *
 * The buffer is sized exactly as needed. This allows to detect buffer
 * overruns (including overreads) when running the test suite under valgrind.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
unsigned char *mbedtls_test_unhexify_alloc( const char *ibuf, size_t *olen );

int mbedtls_test_hexcmp( uint8_t * a, uint8_t * b,
                         uint32_t a_len, uint32_t b_len );

#if defined(MBEDTLS_CHECK_PARAMS)

typedef struct
{
    const char *failure_condition;
    const char *file;
    int line;
}
mbedtls_test_param_failed_location_record_t;

/**
 * \brief   Get the location record of the last call to
 *          mbedtls_test_param_failed().
 *
 * \note    The call expectation is set up and active until the next call to
 *          mbedtls_test_param_failed_check_expected_call() or
 *          mbedtls_param_failed() that cancels it.
 */
void mbedtls_test_param_failed_get_location_record(
         mbedtls_test_param_failed_location_record_t *location_record );

/**
 * \brief   State that a call to mbedtls_param_failed() is expected.
 *
 * \note    The call expectation is set up and active until the next call to
 *          mbedtls_test_param_failed_check_expected_call() or
 *          mbedtls_param_failed that cancel it.
 */
void mbedtls_test_param_failed_expect_call( void );

/**
 * \brief   Check whether mbedtls_param_failed() has been called as expected.
 *
 * \note    Check whether mbedtls_param_failed() has been called between the
 *          last call to mbedtls_test_param_failed_expect_call() and the call
 *          to this function.
 *
 * \return  \c 0 Since the last call to mbedtls_param_failed_expect_call(),
 *               mbedtls_param_failed() has been called.
 *          \c -1 Otherwise.
 */
int mbedtls_test_param_failed_check_expected_call( void );

/**
 * \brief   Get the address of the object of type jmp_buf holding the execution
 *          state information used by mbedtls_param_failed() to do a long jump.
 *
 * \note    If a call to mbedtls_param_failed() is not expected in the sense
 *          that there is no call to mbedtls_test_param_failed_expect_call()
 *          preceding it, then mbedtls_param_failed() will try to restore the
 *          execution to the state stored in the jmp_buf object whose address
 *          is returned by the present function.
 *
 * \note    This function is intended to provide the parameter of the
 *          setjmp() function to set-up where mbedtls_param_failed() should
 *          long-jump if it has to. It is foreseen to be used as:
 *
 *          setjmp( mbedtls_test_param_failed_get_state_buf() ).
 *
 * \note    The type of the returned value is not jmp_buf as jmp_buf is an
 *          an array type (C specification) and a function cannot return an
 *          array type.
 *
 * \note    The type of the returned value is not jmp_buf* as then the return
 *          value couldn't be used by setjmp(), as its parameter's type is
 *          jmp_buf.
 *
 * \return  Address of the object of type jmp_buf holding the execution state
 *          information used by mbedtls_param_failed() to do a long jump.
 */
void* mbedtls_test_param_failed_get_state_buf( void );

/**
 * \brief   Reset the execution state used by mbedtls_param_failed() to do a
 *          long jump.
 *
 * \note    If a call to mbedtls_param_failed() is not expected in the sense
 *          that there is no call to mbedtls_test_param_failed_expect_call()
 *          preceding it, then mbedtls_param_failed() will try to restore the
 *          execution state that this function reset.
 *
 * \note    It is recommended to reset the execution state when the state
 *          is not relevant anymore. That way an unexpected call to
 *          mbedtls_param_failed() will not trigger a long jump with
 *          undefined behavior but rather a long jump that will rather fault.
 */
void mbedtls_test_param_failed_reset_state( void );
#endif /* MBEDTLS_CHECK_PARAMS */

#endif /* TEST_HELPERS_H */
