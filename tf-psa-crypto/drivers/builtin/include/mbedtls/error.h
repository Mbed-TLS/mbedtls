/**
 * \file error.h
 *
 * \brief Error to string translation
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_ERROR_H
#define MBEDTLS_ERROR_H

#include "mbedtls/build_info.h"
#include "mbedtls/error_common.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Translate an Mbed TLS error code into a string representation.
 *        The result is truncated if necessary and always includes a
 *        terminating null byte.
 *
 * \param errnum    error code
 * \param buffer    buffer to place representation in
 * \param buflen    length of the buffer
 */
void mbedtls_strerror(int errnum, char *buffer, size_t buflen);

/**
 * \brief Translate the high-level part of an Mbed TLS error code into a string
 *        representation.
 *
 * This function returns a const pointer to an un-modifiable string. The caller
 * must not try to modify the string. It is intended to be used mostly for
 * logging purposes.
 *
 * \param error_code    error code
 *
 * \return The string representation of the error code, or \c NULL if the error
 *         code is unknown.
 */
const char *mbedtls_high_level_strerr(int error_code);

/**
 * \brief Translate the low-level part of an Mbed TLS error code into a string
 *        representation.
 *
 * This function returns a const pointer to an un-modifiable string. The caller
 * must not try to modify the string. It is intended to be used mostly for
 * logging purposes.
 *
 * \param error_code    error code
 *
 * \return The string representation of the error code, or \c NULL if the error
 *         code is unknown.
 */
const char *mbedtls_low_level_strerr(int error_code);

#ifdef __cplusplus
}
#endif

#endif /* error.h */
