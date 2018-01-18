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

/* OCSP response status values as defined in RFC 6960 Section 4.2.1 */
#define MBEDTLS_X509_OCSP_RESPONSE_STATUS_SUCCESSFUL        0
#define MBEDTLS_X509_OCSP_RESPONSE_STATUS_MALFORMED_REQ     1
#define MBEDTLS_X509_OCSP_RESPONSE_STATUS_INTERNAL_ERR      2
#define MBEDTLS_X509_OCSP_RESPONSE_STATUS_TRY_LATER         3
#define MBEDTLS_X509_OCSP_RESPONSE_STATUS_SIG_REQUIRED      5
#define MBEDTLS_X509_OCSP_RESPONSE_STATUS_UNAUTHORIZED      6

#define MBEDTLS_X509_OCSP_VERSION_1                         0

#define MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_NAME            1
#define MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_KEY_HASH        2

#define MBEDTLS_X509_OCSP_CERT_STATUS_GOOD                  0
#define MBEDTLS_X509_OCSP_CERT_STATUS_REVOKED               1
#define MBEDTLS_X509_OCSP_CERT_STATUS_UNKNOWN               2

#if defined(MBEDTLS_X509_OCSP_PARSE_C)
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
 * Container for an X.509 OCSP ResponderID.
 */
typedef struct mbedtls_x509_ocsp_responder_id {
    int type;                   /**< Flag that indicates whether the ID is a X.509 Name or a KeyHash */
    union {
        mbedtls_x509_name name; /**< Internal representation of the ResponderID as an X.509 Name */
        mbedtls_x509_buf key;   /**< The ResponderID as the SHA1 hash of the responder's public key */
    } id;                       /**< Internal representation of the ResponderID, which is an X.509 CHOICE component */
} mbedtls_x509_ocsp_responder_id;

/**
 * Container for an X.509 OCSP SingleResponse.
 */
typedef struct mbedtls_x509_ocsp_single_response {
    mbedtls_x509_buf md_oid;            /**< Hash algorithm used to generate issuerHashName and issuesKeyHash */
    mbedtls_md_type_t md_alg;           /**< Internal representation of the MD algorithm of the hash algorithm, e.g. MBEDTLS_MD_SHA256 */
    mbedtls_x509_buf issuer_name_hash;  /**< Hash of the issues's distinduished name (DN) */
    mbedtls_x509_buf issuer_key_hash;   /**< Hash of issuer's public key */
    mbedtls_x509_buf serial;            /**< The serial of the certificate that this SingleResponse corresponds to */

    uint8_t cert_status;                /**< The revocation status of the certificate with CertID, e.g. good, revoked, unknown */
    uint8_t revocation_reason;          /**< Optional value that identifies the reason for the certificate revocation, e.g. keyCompromise, cACompromise, etc */
    int has_revocation_reason;          /**< Whether the revocationReason value is present in the OCSP resposne */
    mbedtls_x509_time revocation_time;  /**< The time at which the certificate was revoked or placed on hold */

    mbedtls_x509_time this_update;      /**< The most recent time at which the status is known to the responder to have been correct */

    mbedtls_x509_time next_update;      /**< The time at or before which newer information will be available about the status of the certificate */
    int has_next_update;                /**< Whether the nextUpdate value is present in the OCSP response */

    struct mbedtls_x509_ocsp_single_response *next; /**< Next SingleResponse in the list */
} mbedtls_x509_ocsp_single_response;

/**
 * Container for an X.509 OCSP response.
 */
typedef struct mbedtls_x509_ocsp_response {
    mbedtls_x509_buf raw;                           /**< The raw response data (DER). */

    uint8_t resp_status;                            /**< The OCSP response status */

    mbedtls_x509_buf resp_type;                     /**< The type of response e.g. OCSP or BASIC */

    int version;                                    /**< The OCSP response version. (0=v1) */
    mbedtls_x509_ocsp_responder_id responder_id;    /**< Internal representation of the ResponderID */
    mbedtls_x509_time produced_at;                  /**< The time at which the OCSP responder signed this response */
    mbedtls_x509_ocsp_single_response single_resp;  /**< List of SingleResponse containers each containing the revocation status of a certificate */

    mbedtls_x509_buf sig;                           /**< Signature computed on the hash of the ResponseData */
    mbedtls_x509_buf response_data;                 /**< The raw ResponseData value used to verify the response's signature */

    mbedtls_x509_buf sig_oid;                       /**< Signature algorithm OID, e.g. sha1RSA */
    mbedtls_md_type_t sig_md;                       /**< Internal representation of the MD algorithm of the signature algorithm, e.g. MBEDTLS_MD_SHA256 */
    mbedtls_pk_type_t sig_pk;                       /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. MBEDTLS_PK_RSA */
    void *sig_opts;                                 /**< Signature options passed to mbedtls_pk_verify_ext(), e.g. for RSASSA-PSS */

    mbedtls_x509_crt certs;                         /**< List of certificates included in the OCSP response */
} mbedtls_x509_ocsp_response;

/**
 * \brief          Initialize an OCSP response container
 *
 * \param resp     OCSP response to initialize
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
 * \param resp     The OCSP response to represent
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int mbedtls_x509_ocsp_response_info( char *buf, size_t size,
                                     const char *prefix,
                                     const mbedtls_x509_ocsp_response *resp );

/**
 * \brief          Returns an informational string about the
 *                 verification status of an OCSP response.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param prefix   A line prefix
 * \param flags    Verification flags created by
 *                 mbedtls_x509_ocsp_response_verify()
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int mbedtls_x509_ocsp_response_verify_info( char *buf, size_t size,
                                            const char *prefix,
                                            uint32_t flags );

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
int mbedtls_x509_ocsp_response_parse( mbedtls_x509_ocsp_response *resp,
                                      const unsigned char *buf,
                                      size_t buflen );

/**
 * \brief           Verify an OCSP response
 *
 * \param resp      parsed OCSP response
 * \param req_chain chain of certificates whose status is to be verified
 * \param chain     chain of untrusted certificates. This will be searched
 *                  to find the OCSP response signer and the parent of the
 *                  signer when needed
 * \param trust_ca  chain of certificates fully trusted certificates
 * \param flags     the result of the OCSP response verification
 *
 * \return          0 if the OCSP response was verified successfully, otherwise
 *                  a specific X.509 error
 */
int mbedtls_x509_ocsp_response_verify( mbedtls_x509_ocsp_response *resp,
                                       mbedtls_x509_crt *req_chain,
                                       mbedtls_x509_crt *chain,
                                       mbedtls_x509_crt *trust_ca,
                                       uint32_t *flags );

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
int mbedtls_x509_ocsp_response_parse_file( mbedtls_x509_ocsp_response *resp,
                                           const char *path );
#endif /* MBEDTLS_FS_IO */

/* \} name */
/* \} addtogroup x509_module */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_X509_OCSP_PARSE_C */

#endif /* !MBEDTLS_X509_OCSP_H */
