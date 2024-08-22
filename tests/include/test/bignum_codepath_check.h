/** Support for path tracking in optionally safe bignum functions
 *
 * The functions are called when an optionally safe path is taken and logs it with a single
 * variable. This variable is at any time in one of three states:
 *      - MBEDTLS_MPI_IS_TEST: No optionally safe path has been taken since the last reset
 *      - MBEDTLS_MPI_IS_SECRET: Only safe paths were teken since the last reset
 *      - MBEDTLS_MPI_IS_PUBLIC: At least one unsafe path has been taken since the last reset
 *
 * Using a simple global variable to track execution path. Making it work with multithreading
 * doesn't worth the effort as multithreaded tests add little to no value here.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef BIGNUM_CODEPATH_CHECK_H
#define BIGNUM_CODEPATH_CHECK_H

#include "bignum_core.h"

#if defined(MBEDTLS_TEST_HOOKS) && !defined(MBEDTLS_THREADING_C)

extern int mbedtls_codepath_check;

/**
 * \brief         Setup the codepath test hooks used by optionally safe bignum functions to signal
 *                the path taken.
 */
void mbedtls_codepath_test_hooks_setup(void);

/**
 * \brief         Teardown the codepath test hooks used by optionally safe bignum functions to
 *                signal the path taken.
 */
void mbedtls_codepath_test_hooks_teardown(void);

/**
 * \brief         Reset the state of the codepath to the initial state.
 */
static inline void mbedtls_codepath_reset(void)
{
    mbedtls_codepath_check = MBEDTLS_MPI_IS_TEST;
}

#endif /* MBEDTLS_TEST_HOOKS && !MBEDTLS_THREADING_C */

#endif /* BIGNUM_CODEPATH_CHECK_H */
