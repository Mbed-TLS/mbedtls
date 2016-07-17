/* See RFC 5869 */

#ifndef MBEDTLS_HKDF_H
#define MBEDTLS_HKDF_H

#include "md.h"

/**
 *  \name X509 Error codes
 *  \{
 */
#define MBEDTLS_ERR_HKDF_BAD_PARAM  -0x5300  /**< Bad parameter */
/* \} name */

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  \brief  HMAC-based Extract-and-Expand Key Derivation Function
 *
 *  \param  md        a hash function; md.size denotes the length of the hash
 *                    function output in bytes
 *  \param  salt      optional salt value (a non-secret random value);
 *                    if not provided, it is set to a string of md.size zeros.
 *  \param  salt_len  length in bytes of the optional \p salt
 *  \param  ikm       (low-entropy) input keying material
 *  \param  ikm_len   length in bytes of \p ikm
 *  \param  info      optional context and application specific information
 *                    (can be a zero-length string)
 *  \param  info_len  length of \p info in bytes
 *  \param  okm       output keying material (of \p okm_len bytes)
 *  \param  okm_len   length of output keying material in octets
 *                    (<= 255*md.size)
 *
 *  \return 0 on success or one of the failure codes from mbedtls_hkdf_extract
 *          or mbedtls_hkdf_expand
 */
int mbedtls_hkdf(const mbedtls_md_info_t *md, const unsigned char *salt,
                 int salt_len, const unsigned char *ikm, int ikm_len,
                 const unsigned char *info, int info_len, unsigned char *okm,
                 int okm_len);

/**
 *  \brief  Take the input keying material \p ikm and extract from it a
 *          fixed-length pseudorandom key \p prk
 *
 *  \param  md        a hash function; md.size denotes the length of the hash
 *                    function output in bytes
 *  \param  salt      optional salt value (a non-secret random value);
 *                    if not provided, it is set to a string of md.size zeros.
 *  \param  salt_len  length in bytes of the optional \p salt
 *  \param  ikm       (low-entropy) input keying material
 *  \param  ikm_len   length in bytes of \p ikm
 *  \param  prk       a pseudorandom key (of md.size bytes)
 *
 *  \return 0 on success, MBEDTLS_ERR_HKDF_BAD_PARAM or one of mbedtls_md_*
 *          error codes on failure
 */
int mbedtls_hkdf_extract(const mbedtls_md_info_t *md, const unsigned char *salt,
                         int salt_len, const unsigned char *ikm, int ikm_len,
                         unsigned char *prk);

/**
 *  \brief  Expand the supplied \p prk into several additional pseudorandom keys
 *          (the output of the KDF).
 *
 *  \param  md          a hash function; md.size denotes the length of the hash
 *                      function output in bytes
 *  \param  prk         a pseudorandom key of at least md.size bytes; usually,
 *                      the output from the extract step
 *  \param  prk_len     length of \p prk in bytes
 *  \param  info        optional context and application specific information
 *                      (can be a zero-length string)
 *  \param  info_len    length of \p info in bytes
 *  \param  okm         output keying material (of \p okm_len bytes)
 *  \param  okm_len     length of output keying material in octets
 *                      (<= 255*md.size)
 *
 *  \return 0 on success, MBEDTLS_ERR_HKDF_BAD_PARAM or a failure code from the
 *          mbedtls_md_* family
 */
int mbedtls_hkdf_expand(const mbedtls_md_info_t *md, const unsigned char *prk,
                        int prk_len, const unsigned char *info, int info_len,
                        unsigned char *okm, int okm_len);

#ifdef __cplusplus
}
#endif

#endif  // !MBEDTLS_HKDF_H
