/**
 * \file x509.h
 *
 * \brief Internal part of the public "x509.h".
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_X509_INTERNAL_H
#define MBEDTLS_X509_INTERNAL_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/x509.h"
#include "mbedtls/asn1.h"
#include "pk_internal.h"

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif

/**
 * \brief          Return the next relative DN in an X509 name.
 *
 * \note           Intended use is to compare function result to dn->next
 *                 in order to detect boundaries of multi-valued RDNs.
 *
 * \param dn       Current node in the X509 name
 *
 * \return         Pointer to the first attribute-value pair of the
 *                 next RDN in sequence, or NULL if end is reached.
 */
static inline mbedtls_x509_name *mbedtls_x509_dn_get_next(
    mbedtls_x509_name *dn)
{
    while (dn->MBEDTLS_PRIVATE(next_merged) && dn->next != NULL) {
        dn = dn->next;
    }
    return dn->next;
}

/**
 * \brief          Store the certificate serial in printable form into buf;
 *                 no more than size characters will be written.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param serial   The X509 serial to represent
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int mbedtls_x509_serial_gets(char *buf, size_t size, const mbedtls_x509_buf *serial);

/**
 * \brief          Compare pair of mbedtls_x509_time.
 *
 * \param t1       mbedtls_x509_time to compare
 * \param t2       mbedtls_x509_time to compare
 *
 * \return         < 0 if t1 is before t2
 *                   0 if t1 equals t2
 *                 > 0 if t1 is after t2
 */
int mbedtls_x509_time_cmp(const mbedtls_x509_time *t1, const mbedtls_x509_time *t2);

#if defined(MBEDTLS_HAVE_TIME_DATE)
/**
 * \brief          Fill mbedtls_x509_time with provided mbedtls_time_t.
 *
 * \param tt       mbedtls_time_t to convert
 * \param now      mbedtls_x509_time to fill with converted mbedtls_time_t
 *
 * \return         \c 0 on success
 * \return         A non-zero return value on failure.
 */
int mbedtls_x509_time_gmtime(mbedtls_time_t tt, mbedtls_x509_time *now);
#endif /* MBEDTLS_HAVE_TIME_DATE */

/**
 * \brief          Check a given mbedtls_x509_time against the system time
 *                 and tell if it's in the past.
 *
 * \note           Intended usage is "if( is_past( valid_to ) ) ERROR".
 *                 Hence the return value of 1 if on internal errors.
 *
 * \param to       mbedtls_x509_time to check
 *
 * \return         1 if the given time is in the past or an error occurred,
 *                 0 otherwise.
 */
int mbedtls_x509_time_is_past(const mbedtls_x509_time *to);

/**
 * \brief          Check a given mbedtls_x509_time against the system time
 *                 and tell if it's in the future.
 *
 * \note           Intended usage is "if( is_future( valid_from ) ) ERROR".
 *                 Hence the return value of 1 if on internal errors.
 *
 * \param from     mbedtls_x509_time to check
 *
 * \return         1 if the given time is in the future or an error occurred,
 *                 0 otherwise.
 */
int mbedtls_x509_time_is_future(const mbedtls_x509_time *from);

/**
 * \brief          This function parses an item in the SubjectAlternativeNames
 *                 extension. Please note that this function might allocate
 *                 additional memory for a subject alternative name, thus
 *                 mbedtls_x509_free_subject_alt_name has to be called
 *                 to dispose of this additional memory afterwards.
 *
 * \param san_buf  The buffer holding the raw data item of the subject
 *                 alternative name.
 * \param san      The target structure to populate with the parsed presentation
 *                 of the subject alternative name encoded in \p san_buf.
 *
 * \note           Supported GeneralName types, as defined in RFC 5280:
 *                 "rfc822Name", "dnsName", "directoryName",
 *                 "uniformResourceIdentifier" and "hardware_module_name"
 *                 of type "otherName", as defined in RFC 4108.
 *
 * \note           This function should be called on a single raw data of
 *                 subject alternative name. For example, after successful
 *                 certificate parsing, one must iterate on every item in the
 *                 \c crt->subject_alt_names sequence, and pass it to
 *                 this function.
 *
 * \warning        The target structure contains pointers to the raw data of the
 *                 parsed certificate, and its lifetime is restricted by the
 *                 lifetime of the certificate.
 *
 * \return         \c 0 on success
 * \return         #MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE for an unsupported
 *                 SAN type.
 * \return         Another negative value for any other failure.
 */
int mbedtls_x509_parse_subject_alt_name(const mbedtls_x509_buf *san_buf,
                                        mbedtls_x509_subject_alternative_name *san);
/**
 * \brief          Unallocate all data related to subject alternative name
 *
 * \param san      SAN structure - extra memory owned by this structure will be freed
 */
void mbedtls_x509_free_subject_alt_name(mbedtls_x509_subject_alternative_name *san);

int mbedtls_x509_get_name(unsigned char **p, const unsigned char *end,
                          mbedtls_x509_name *cur);
int mbedtls_x509_get_alg_null(unsigned char **p, const unsigned char *end,
                              mbedtls_x509_buf *alg);
int mbedtls_x509_get_alg(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf *alg, mbedtls_x509_buf *params);
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
int mbedtls_x509_get_rsassa_pss_params(const mbedtls_x509_buf *params,
                                       mbedtls_md_type_t *md_alg, mbedtls_md_type_t *mgf_md,
                                       int *salt_len);
#endif
int mbedtls_x509_get_sig(unsigned char **p, const unsigned char *end, mbedtls_x509_buf *sig);
int mbedtls_x509_get_sig_alg(const mbedtls_x509_buf *sig_oid, const mbedtls_x509_buf *sig_params,
                             mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg,
                             void **sig_opts);
int mbedtls_x509_get_time(unsigned char **p, const unsigned char *end,
                          mbedtls_x509_time *t);
int mbedtls_x509_get_serial(unsigned char **p, const unsigned char *end,
                            mbedtls_x509_buf *serial);
int mbedtls_x509_get_ext(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf *ext, int tag);
#if !defined(MBEDTLS_X509_REMOVE_INFO)
int mbedtls_x509_sig_alg_gets(char *buf, size_t size, const mbedtls_x509_buf *sig_oid,
                              mbedtls_pk_type_t pk_alg, mbedtls_md_type_t md_alg,
                              const void *sig_opts);
#endif
int mbedtls_x509_key_size_helper(char *buf, size_t buf_size, const char *name);
int mbedtls_x509_set_extension(mbedtls_asn1_named_data **head, const char *oid, size_t oid_len,
                               int critical, const unsigned char *val,
                               size_t val_len);
int mbedtls_x509_write_extensions(unsigned char **p, unsigned char *start,
                                  mbedtls_asn1_named_data *first);
int mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data *first);
int mbedtls_x509_write_sig(unsigned char **p, unsigned char *start,
                           const char *oid, size_t oid_len,
                           unsigned char *sig, size_t size,
                           mbedtls_pk_type_t pk_alg);
int mbedtls_x509_get_ns_cert_type(unsigned char **p,
                                  const unsigned char *end,
                                  unsigned char *ns_cert_type);
int mbedtls_x509_get_key_usage(unsigned char **p,
                               const unsigned char *end,
                               unsigned int *key_usage);
int mbedtls_x509_get_subject_alt_name(unsigned char **p,
                                      const unsigned char *end,
                                      mbedtls_x509_sequence *subject_alt_name);
int mbedtls_x509_get_subject_alt_name_ext(unsigned char **p,
                                          const unsigned char *end,
                                          mbedtls_x509_sequence *subject_alt_name);
int mbedtls_x509_info_subject_alt_name(char **buf, size_t *size,
                                       const mbedtls_x509_sequence
                                       *subject_alt_name,
                                       const char *prefix);
int mbedtls_x509_info_cert_type(char **buf, size_t *size,
                                unsigned char ns_cert_type);
int mbedtls_x509_info_key_usage(char **buf, size_t *size,
                                unsigned int key_usage);

int mbedtls_x509_write_set_san_common(mbedtls_asn1_named_data **extensions,
                                      const mbedtls_x509_san_list *san_list);

#endif /* MBEDTLS_X509_INTERNAL_H */
