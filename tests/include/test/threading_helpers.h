/**
 * \file threading_helpers.h
 *
 * \brief This file contains the prototypes of helper functions for the purpose
 *        of testing threading.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef THREADING_HELPERS_H
#define THREADING_HELPERS_H

#if defined MBEDTLS_THREADING_C

#if defined(MBEDTLS_THREADING_PTHREAD) && defined(MBEDTLS_TEST_HOOKS)
#define MBEDTLS_TEST_MUTEX_USAGE
#endif

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
/**
 *  Activate the mutex usage verification framework. See threading_helpers.c for
 *  information.
 */
void mbedtls_test_mutex_usage_init(void);

/**
 *  Deactivate the mutex usage verification framework. See threading_helpers.c
 *  for information.
 */
void mbedtls_test_mutex_usage_end(void);

/**
 *  Call this function after executing a test case to check for mutex usage
 * errors.
 */
void mbedtls_test_mutex_usage_check(void);
#endif /* MBEDTLS_TEST_MUTEX_USAGE */

#endif /* MBEDTLS_THREADING_C */

#endif /* THREADING_HELPERS_H */

