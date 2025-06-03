/**
 * \file x509_oid.h
 *
 * \brief Object Identifier (OID) database
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_X509_OID_H
#define MBEDTLS_X509_OID_H
#include "mbedtls/private_access.h"

#include "mbedtls/asn1.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"

#include <stddef.h>

#include "mbedtls/md.h"

/*
 * Maximum number of OID components allowed
 */
#define MBEDTLS_OID_MAX_COMPONENTS              128

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Base OID descriptor structure
 */
typedef struct {
    const char *MBEDTLS_PRIVATE(asn1);               /*!< OID ASN.1 representation       */
    size_t MBEDTLS_PRIVATE(asn1_len);                /*!< length of asn1                 */
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    const char *MBEDTLS_PRIVATE(name);               /*!< official name (e.g. from RFC)  */
    const char *MBEDTLS_PRIVATE(description);        /*!< human friendly description     */
#endif
} mbedtls_x509_oid_descriptor_t;

/**
 * \brief          Translate an X.509 extension OID into local values
 *
 * \param oid      OID to use
 * \param ext_type place to store the extension type
 *
 * \return         0 if successful, or MBEDTLS_ERR_X509_UNKNOWN_OID
 */
int mbedtls_x509_oid_get_x509_ext_type(const mbedtls_asn1_buf *oid, int *ext_type);

/**
 * \brief          Translate an X.509 attribute type OID into the short name
 *                 (e.g. the OID for an X520 Common Name into "CN")
 *
 * \param oid      OID to use
 * \param short_name    place to store the string pointer
 *
 * \return         0 if successful, or MBEDTLS_ERR_X509_UNKNOWN_OID
 */
int mbedtls_x509_oid_get_attr_short_name(const mbedtls_asn1_buf *oid, const char **short_name);

/**
 * \brief          Translate SignatureAlgorithm OID into md_type and pk_type
 *
 * \param oid      OID to use
 * \param md_alg   place to store message digest algorithm
 * \param pk_alg   place to store public key algorithm
 *
 * \return         0 if successful, or MBEDTLS_ERR_X509_UNKNOWN_OID
 */
int mbedtls_x509_oid_get_sig_alg(const mbedtls_asn1_buf *oid,
                                 mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg);

/**
 * \brief          Translate SignatureAlgorithm OID into description
 *
 * \param oid      OID to use
 * \param desc     place to store string pointer
 *
 * \return         0 if successful, or MBEDTLS_ERR_X509_UNKNOWN_OID
 */
int mbedtls_x509_oid_get_sig_alg_desc(const mbedtls_asn1_buf *oid, const char **desc);

/**
 * \brief          Translate md_type and pk_type into SignatureAlgorithm OID
 *
 * \param md_alg   message digest algorithm
 * \param pk_alg   public key algorithm
 * \param oid      place to store ASN.1 OID string pointer
 * \param olen     length of the OID
 *
 * \return         0 if successful, or MBEDTLS_ERR_X509_UNKNOWN_OID
 */
int mbedtls_x509_oid_get_oid_by_sig_alg(mbedtls_pk_type_t pk_alg, mbedtls_md_type_t md_alg,
                                        const char **oid, size_t *olen);

/**
 * \brief          Translate hash algorithm OID into md_type
 *
 * \param oid      OID to use
 * \param md_alg   place to store message digest algorithm
 *
 * \return         0 if successful, or MBEDTLS_ERR_X509_UNKNOWN_OID
 */
int mbedtls_x509_oid_get_md_alg(const mbedtls_asn1_buf *oid, mbedtls_md_type_t *md_alg);

#if !defined(MBEDTLS_X509_REMOVE_INFO)
/**
 * \brief          Translate Extended Key Usage OID into description
 *
 * \param oid      OID to use
 * \param desc     place to store string pointer
 *
 * \return         0 if successful, or MBEDTLS_ERR_X509_UNKNOWN_OID
 */
int mbedtls_x509_oid_get_extended_key_usage(const mbedtls_asn1_buf *oid, const char **desc);
#endif

/**
 * \brief          Translate certificate policies OID into description
 *
 * \param oid      OID to use
 * \param desc     place to store string pointer
 *
 * \return         0 if successful, or MBEDTLS_ERR_X509_UNKNOWN_OID
 */
int mbedtls_x509_oid_get_certificate_policies(const mbedtls_asn1_buf *oid, const char **desc);

#ifdef __cplusplus
}
#endif

#endif /* x509_oid.h */
