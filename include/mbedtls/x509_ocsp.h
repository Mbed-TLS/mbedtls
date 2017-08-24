/**
 * \file x509_ocsp.h
 *
 * \brief OCSP generic defines and structures
 *
 *  Copyright (C) 2017, ARM Limited, All Rights Reserved
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
#ifndef MBEDTLS_X509_OCSP_H
#define MBEDTLS_X509_OCSP_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "x509.h"
#include "x509_crt.h"
#include "md.h"
#include "pk.h"

#include <stdint.h>

#define MBEDTLS_ERR_X509_OCSP_INVALID_RESPONSE_STATUS    -0x2A00 /**< The OCSP response status is invalid */
#define MBEDTLS_ERR_X509_OCSP_INVALID_RESPONSE_TYPE      -0x2A10 /**< The OCSP response type is invalid */

/* OCSP response status values as defined in RFC 6960 Section 4.2.1 */
#define MBEDTLS_X509_OCSP_RESPONSE_STATUS_SUCCESSFUL        0
#define MBEDTLS_X509_OCSP_RESPONSE_STATUS_MALFORMED_REQ     1
#define MBEDTLS_X509_OCSP_RESPONSE_STATUS_INTERNAL_ERR      2
#define MBEDTLS_X509_OCSP_RESPONSE_STATUS_TRY_LATER         3
#define MBEDTLS_X509_OCSP_RESPONSE_STATUS_SIG_REQUIRED      5
#define MBEDTLS_X509_OCSP_RESPONSE_STATUS_UNAUTHORIZED      6

/**
 * \addtogroup x509_module
 * \{
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \name Structures and functions for parsing and writing X.509 OCSP responses
 * \{
 */

/**
 * Container for an X.509 OCSP response.
 */
typedef struct mbedtls_x509_ocsp_response {
    mbedtls_x509_buf raw;               /**< The raw response data (DER). */

    mbedtls_x509_buf resp_type;         /**< The type of response e.g. OCSP or BASIC */

    uint8_t resp_status;                /**< The OCSP response status */
} mbedtls_x509_ocsp_response;

/**
 * \brief          Initialize an OCSP response container
 *
 * \param crt      OCSP response to initialize
 */
void mbedtls_x509_ocsp_response_init( mbedtls_x509_ocsp_response *resp );

/**
 * \brief          Unallocate all OCSP response data
 *
 * \param resp     OCSP response to free
 */
void mbedtls_x509_ocsp_response_free( mbedtls_x509_ocsp_response *resp );

/**
 * \brief          Returns an informational string about the OCSP response
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param prefix   A line prefix
 * \param crt      The X509 certificate to represent
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int mbedtls_x509_ocsp_response_info( char *buf, size_t size,
                                     const char *prefix,
                                     const mbedtls_x509_ocsp_response *resp );

/**
 * \brief          Parse a single OCSP response
 *
 * \param resp     points to the struct that will contain the parsed values
 * \param buf      buffer holding the OCSP response data in DER format
 * \param buflen   size of the buffer
 *
 * \return         0 if the ocsp response was parsed successfully, otherwise a
 *                 specific X.509 error
 */
int mbedtls_x509_ocsp_parse_response( mbedtls_x509_ocsp_response *resp,
                                      unsigned char *buf, size_t buflen );

#if defined(MBEDTLS_FS_IO)
/**
 * \brief          Load and parse a single OCSP response from a file encoded in
 *                 DER format.
 *
 * \param resp     points to the struct that will contained the parsed values
 * \param path     filename to read the from
 *
 * \return         0 if the ocsp response was parsed successfully, otherwise a
 *                 specific X509 error
 */
int mbedtls_x509_ocsp_parse_response_file( mbedtls_x509_ocsp_response *resp,
                                           const char *path );
#endif /* MBEDTLS_FS_IO */

/* \} name */
/* \} addtogroup x509_module */

#ifdef __cplusplus
}
#endif

#endif /* !MBEDTLS_X509_OCSP_H */
