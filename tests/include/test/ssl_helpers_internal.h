/** \file ssl_helpers.h
 *
 * \brief This file contains helper functions for TLS that rely on private
 *        headers.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef SSL_HELPERS_INTERNAL_H
#define SSL_HELPERS_INTERNAL_H

#if defined(MBEDTLS_SSL_TLS_C)
#include <ssl_misc.h>

#define PSA_TO_MBEDTLS_ERR(status) PSA_TO_MBEDTLS_ERR_LIST(status, \
                                                           psa_to_ssl_errors, \
                                                           psa_generic_status_to_mbedtls)

enum {
#define MBEDTLS_SSL_TLS1_3_LABEL(name, string)          \
    tls13_label_ ## name,
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
#undef MBEDTLS_SSL_TLS1_3_LABEL
};

/*
 * Helper function setting up inverse record transformations
 * using given cipher, hash, EtM mode, authentication tag length,
 * and version.
 */
#define CHK(x)                                  \
    do                                          \
    {                                           \
        if (!(x))                               \
        {                                       \
            ret = -1;                           \
            goto cleanup;                       \
        }                                       \
    } while (0)

#if MBEDTLS_SSL_CID_OUT_LEN_MAX > MBEDTLS_SSL_CID_IN_LEN_MAX
#define SSL_CID_LEN_MIN MBEDTLS_SSL_CID_IN_LEN_MAX
#else
#define SSL_CID_LEN_MIN MBEDTLS_SSL_CID_OUT_LEN_MAX
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(PSA_WANT_ALG_CBC_NO_PADDING) && defined(PSA_WANT_KEY_TYPE_AES)
int mbedtls_test_psa_cipher_encrypt_helper(mbedtls_ssl_transform *transform,
                                           const unsigned char *iv,
                                           size_t iv_len,
                                           const unsigned char *input,
                                           size_t ilen,
                                           unsigned char *output,
                                           size_t *olen);
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 && PSA_WANT_ALG_CBC_NO_PADDING &&
          PSA_WANT_KEY_TYPE_AES */

int mbedtls_test_ssl_build_transforms(mbedtls_ssl_transform *t_in,
                                      mbedtls_ssl_transform *t_out,
                                      int cipher_type, int hash_id,
                                      int etm, int tag_mode,
                                      mbedtls_ssl_protocol_version tls_version,
                                      size_t cid0_len,
                                      size_t cid1_len);

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)
/**
 * \param[in,out] record        The record to prepare.
 *                              It must contain the data to MAC at offset
 *                              `record->data_offset`, of length
 *                              `record->data_length`.
 *                              On success, write the MAC immediately
 *                              after the data and increment
 *                              `record->data_length` accordingly.
 * \param[in,out] transform_out The out transform, typically prepared by
 *                              mbedtls_test_ssl_build_transforms().
 *                              Its HMAC context may be used. Other than that
 *                              it is treated as an input parameter.
 *
 * \return                      0 on success, an `MBEDTLS_ERR_xxx` error code
 *                              or -1 on error.
 */
int mbedtls_test_ssl_prepare_record_mac(mbedtls_record *record,
                                        mbedtls_ssl_transform *transform_out);
#endif /* MBEDTLS_SSL_SOME_SUITES_USE_MAC */

#if defined(MBEDTLS_TEST_HOOKS)
/*
 * Tweak vector lengths in a TLS 1.3 Certificate message
 *
 * \param[in]       buf    Buffer containing the Certificate message to tweak
 * \param[in]]out]  end    End of the buffer to parse
 * \param           tweak  Tweak identifier (from 1 to the number of tweaks).
 * \param[out]  expected_result  Error code expected from the parsing function
 * \param[out]  args  Arguments of the MBEDTLS_SSL_CHK_BUF_READ_PTR call that
 *                    is expected to fail. All zeroes if no
 *                    MBEDTLS_SSL_CHK_BUF_READ_PTR failure is expected.
 */
int mbedtls_test_tweak_tls13_certificate_msg_vector_len(
    unsigned char *buf, unsigned char **end, int tweak,
    int *expected_result, mbedtls_ssl_chk_buf_ptr_args *args);
#endif /* MBEDTLS_TEST_HOOKS */

#endif /* MBEDTLS_SSL_TLS_C */

#endif /* SSL_HELPERS_INTERNAL_H */
