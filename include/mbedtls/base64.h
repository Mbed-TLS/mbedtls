/**
 * \file base64.h
 *
 * \brief RFC 1521 base64 encoding/decoding
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_BASE64_H
#define MBEDTLS_BASE64_H

#include <stddef.h>

#define MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL               -0x002A  /**< Output buffer too small. */
#define MBEDTLS_ERR_BASE64_INVALID_CHARACTER              -0x002C  /**< Invalid character in input. */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Encode a buffer into base64 format
 *
 * \param dst      destination buffer
 * \param dlen     size of the buffer
 * \param src      source buffer
 * \param slen     amount of data to be encoded
 *
 * \return         0 if successful, or MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL.
 *                 *dlen is always updated to reflect the amount
 *                 of data that has (or would have) been written.
 *
 * \note           Call this function with *dlen = 0 to obtain the
 *                 required buffer size in *dlen
 */
int mbedtls_base64_encode( unsigned char *dst, size_t *dlen,
                   const unsigned char *src, size_t slen );

/**
 * \brief          Decode a base64-formatted buffer
 *
 * \param dst      destination buffer (can be NULL for checking size)
 * \param dlen     size of the buffer
 * \param src      source buffer
 * \param slen     amount of data to be decoded
 *
 * \return         0 if successful, MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL, or
 *                 MBEDTLS_ERR_BASE64_INVALID_CHARACTER if the input data is
 *                 not correct. *dlen is always updated to reflect the amount
 *                 of data that has (or would have) been written.
 *
 * \note           Call this function with *dst = NULL or *dlen = 0 to obtain
 *                 the required buffer size in *dlen
 */
int mbedtls_base64_decode( unsigned char *dst, size_t *dlen,
                   const unsigned char *src, size_t slen );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_base64_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* base64.h */
