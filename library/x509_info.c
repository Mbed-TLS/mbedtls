/*
 *  X.509 info stringification for display
 *
 *  Copyright The Mbed TLS Contributors
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
 */
/*
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 *  http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *
 *  [SIRO] https://cabforum.org/wp-content/uploads/Chunghwatelecom201503cabforumV4.pdf
 */

#include "common.h"

#include "mbedtls/x509.h"
#include "mbedtls/asn1.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"

#include <string.h>

#if !defined(MBEDTLS_X509_REMOVE_INFO)

#if defined(MBEDTLS_X509_CRT_PARSE_C) \
    || defined(MBEDTLS_X509_CSR_PARSE_C) \
    || defined(MBEDTLS_X509_CRL_PARSE_C)

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#include "mbedtls/x509_crt.h"
#endif

#if defined(MBEDTLS_X509_CSR_PARSE_C)
#include "mbedtls/x509_csr.h"
#endif

#if defined(MBEDTLS_X509_CRL_PARSE_C)
#include "mbedtls/x509_crl.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_snprintf   snprintf
#endif

#define mbedtls_allpcpy_lim(p, lim, str) \
    mbedtls_mempcpy_lim((p), (lim), (str), sizeof(str) - 1)

/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
static char *mbedtls_x509_time_str(char *dst, const char *lim, const mbedtls_x509_time *tm);

/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
static intptr_t mbedtls_strterm(char *buf, char *p, const char *lim);

/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
/*__attribute__((__returns_nonnull__))*//*(XXX: should use where supported)*/
static char *mbedtls_strpcpy_lim(char *dst, const char *lim, const char *src);

/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
/*__attribute__((__returns_nonnull__))*//*(XXX: should use where supported)*/
static char *mbedtls_mempcpy_lim(char *dst, const char *lim, const void *src, size_t len);

/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
static char *mbedtls_strhex_lim(char *dst, const char *lim, const unsigned char *src, size_t len);

/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
/*__attribute__((__returns_nonnull__))*//*(XXX: should use where supported)*/
static char *mbedtls_itoa_lim(char *dst, const char *lim, int i);

#endif /* MBEDTLS_X509_*_PARSE_C */


#if defined(MBEDTLS_X509_USE_C)

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
/*
 * Convert md type to string
 */
static inline const char *md_type_to_string(mbedtls_md_type_t md_alg)
{
    switch (md_alg) {
#if defined(MBEDTLS_HAS_ALG_MD5_VIA_MD_OR_PSA)
        case MBEDTLS_MD_MD5:
            return "MD5";
#endif
#if defined(MBEDTLS_HAS_ALG_SHA_1_VIA_MD_OR_PSA)
        case MBEDTLS_MD_SHA1:
            return "SHA1";
#endif
#if defined(MBEDTLS_HAS_ALG_SHA_224_VIA_MD_OR_PSA)
        case MBEDTLS_MD_SHA224:
            return "SHA224";
#endif
#if defined(MBEDTLS_HAS_ALG_SHA_256_VIA_MD_OR_PSA)
        case MBEDTLS_MD_SHA256:
            return "SHA256";
#endif
#if defined(MBEDTLS_HAS_ALG_SHA_384_VIA_MD_OR_PSA)
        case MBEDTLS_MD_SHA384:
            return "SHA384";
#endif
#if defined(MBEDTLS_HAS_ALG_SHA_512_VIA_MD_OR_PSA)
        case MBEDTLS_MD_SHA512:
            return "SHA512";
#endif
#if defined(MBEDTLS_HAS_ALG_RIPEMD160_VIA_MD_OR_PSA)
        case MBEDTLS_MD_RIPEMD160:
            return "RIPEMD160";
#endif
        case MBEDTLS_MD_NONE:
            return NULL;
        default:
            return NULL;
    }
}
#endif

/*
 * Helper for writing signature algorithms
 */
int mbedtls_x509_sig_alg_gets(char *buf, size_t size, const mbedtls_x509_buf *sig_oid,
                              mbedtls_pk_type_t pk_alg, mbedtls_md_type_t md_alg,
                              const void *sig_opts)
{
    const char *desc;
    if (0 != mbedtls_oid_get_sig_alg_desc(sig_oid, &desc)) {
        desc = "???";
    }

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    if (pk_alg == MBEDTLS_PK_RSASSA_PSS) {
        const mbedtls_pk_rsassa_pss_options *pss_opts;
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        pss_opts = (const mbedtls_pk_rsassa_pss_options *) sig_opts;

        const char *name = md_type_to_string(md_alg);
        const char *mgf_name = md_type_to_string(pss_opts->mgf1_hash_id);

      #if 1
        ret = mbedtls_snprintf(buf, size, "%s (%s, MGF1-%s, 0x%02X)", desc,
                               name ? name : "???",
                               mgf_name ? mgf_name : "???",
                               (unsigned int) pss_opts->expected_salt_len);
        if (ret < 0 || (size_t) ret >= size) {
            return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        }
        return ret;
      #else  /*(alternate w/o snprintf; probably not worth extra code size)*/
        char *p = buf;
        const char * const lim = buf + size;
        p = mbedtls_strpcpy_lim(p, lim, desc);
        p = mbedtls_allpcpy_lim(p, lim, " (");
        desc = name ? name : "???";
        p = mbedtls_strpcpy_lim(p, lim, desc);
        p = mbedtls_allpcpy_lim(p, lim, ", MGF1-");
        desc = mgf_name ? mgf_name : "???";
        p = mbedtls_strpcpy_lim(p, lim, desc);
        {
            static const char hex_chars_uc[] = "0123456789ABCDEF";
            char xbuf[16] = ", 0x"; /* large enough for ", 0x00000000)" */
            char *x = xbuf+4;
            const unsigned int salt = (unsigned int) pss_opts->expected_salt_len;
            for (int bits = 32; bits;) {
                unsigned int u = 0xFF & (salt >> (bits -= 8));
                if (u == 0 || bits >= 16) {
                    continue;
                }
                *x++ = hex_chars_uc[0x0F & (u >> 4)];
                *x++ = hex_chars_uc[0x0F & u];
            }
            *x++ = ')';
            p = mbedtls_mempcpy_lim(p, lim, xbuf, (size_t) (x - xbuf));
        }
        return (int) mbedtls_strterm(buf, p, lim);
      #endif
    }
#else
    ((void) pk_alg);
    ((void) md_alg);
    ((void) sig_opts);
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */
    {
        char *p = mbedtls_strpcpy_lim(buf, buf + size, desc);
        return (int) mbedtls_strterm(buf, p, buf + size);
    }
}

#endif /* MBEDTLS_X509_USE_C */


#if defined(MBEDTLS_X509_CRT_PARSE_C) \
    || defined(MBEDTLS_X509_CSR_PARSE_C)
static char *x509_info_pk_key_size(char * const buf, const char * const lim,
                                   const mbedtls_pk_context *pk, size_t pad)
{
  #if 1
    char *p = buf;
    size_t n;

    /* "RSA" "EC" "EC_DH" "ECDSA" "RSA-alt" "Opaque" */
    p = mbedtls_strpcpy_lim(p, lim, mbedtls_pk_get_name(pk));
    p = mbedtls_allpcpy_lim(p, lim, " key size");
    n = (size_t) (p - buf);
    if (n < pad) { /*(caller value for pad must not exceed "   " length below)*/
        p = mbedtls_mempcpy_lim(p, lim, "                  ", pad - n);
    }
    p = mbedtls_allpcpy_lim(p, lim, ": ");
    p = mbedtls_itoa_lim(p, lim, (int) mbedtls_pk_get_bitlen(pk));
    p = mbedtls_allpcpy_lim(p, lim, " bits");

    return p;
  #else
    static const char spaces[] = "         ";
    const char *name = mbedtls_pk_get_name(pk);
    size_t n = strlen(name);
    int ret;

    pad = (pad > n + 9 ? pad - n + 9 : 0);   /* " key size " is 9 chars */
    /*assert( pad < sizeof(spaces) );*//*(expecting input param of 14 or 18)*/
    n = (size_t) (lim - buf);
    ret = snprintf(buf, n, "%s key size%s: %d bits",
                   name, spaces + sizeof(spaces) - 1 - pad,
                   (int) mbedtls_pk_get_bitlen(pk));
    return buf + ((ret >= 0 && (size_t) ret < n) ? (size_t) ret : n);
  #endif
}
#endif /* MBEDTLS_X509_CRT_PARSE_C || MBEDTLS_X509_CSR_PARSE_C */


#if defined(MBEDTLS_X509_CRT_PARSE_C)

static char *x509_info_subject_alt_name(char *buf, size_t size,
                                        const mbedtls_x509_sequence
                                        *subject_alt_name,
                                        const char *prefix, const size_t plen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    char *p = buf;
    char * const lim = buf + size;
    const mbedtls_x509_sequence *cur;
    mbedtls_x509_subject_alternative_name san;

    for (cur = subject_alt_name; cur != NULL; cur = cur->next) {
        p = mbedtls_mempcpy_lim(p, lim, prefix, plen);

        ret = mbedtls_x509_parse_subject_alt_name(&cur->buf, &san);
        if (ret != 0) {
            if (ret == MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE) {
                p = mbedtls_allpcpy_lim(p, lim, "    <unsupported>");
            } else {
                p = mbedtls_allpcpy_lim(p, lim, "    <malformed>");
            }
            continue;
        }

        switch (san.type) {
            /*
             * otherName
             */
            case MBEDTLS_X509_SAN_OTHER_NAME:
            {
                mbedtls_x509_san_other_name *other_name = &san.san.other_name;

                p = mbedtls_allpcpy_lim(p, lim, "    otherName :");

                if (MBEDTLS_OID_CMP(MBEDTLS_OID_ON_HW_MODULE_NAME,
                                    &other_name->value.hardware_module_name.oid) != 0) {
                    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
                    p = mbedtls_allpcpy_lim(p, lim,
                                            "        hardware module name :");
                    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
                    p = mbedtls_allpcpy_lim(p, lim,
                                            "            hardware type          : ");
                    ret = mbedtls_oid_get_numeric_string(p, (size_t) (lim - p),
                                                         &other_name->value.hardware_module_name.oid);
                    p = (ret >= 0) ? p + ret : lim;

                    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
                    p = mbedtls_allpcpy_lim(p, lim,
                                            "            hardware serial number : ");
                    p = mbedtls_strhex_lim(p, lim,
                                           other_name->value.hardware_module_name.val.p,
                                           other_name->value.hardware_module_name.val.len);
                }/* MBEDTLS_OID_ON_HW_MODULE_NAME */
                break;
            }

            /*
             * dNSName
             */
            case MBEDTLS_X509_SAN_DNS_NAME:
                p = mbedtls_allpcpy_lim(p, lim, "    dNSName : ");
                p = mbedtls_mempcpy_lim(p, lim,
                                        san.san.unstructured_name.p,
                                        san.san.unstructured_name.len);
                break;

            /*
             * Type not supported, skip item.
             */
            default:
                p = mbedtls_allpcpy_lim(p, lim, "    <unsupported>");
                break;
        }
    }

    return p;
}

/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
/*__attribute__((__returns_nonnull__))*//*(XXX: should use where supported)*/
static char *x509_append_item(char *p, const char *lim, const char *buf, const char *item);

static char *x509_info_cert_type(char * const buf, const char * const lim,
                                 unsigned char ns_cert_type)
{
    char *p = buf;

    #define CERT_TYPE(type, name)                    \
    if (ns_cert_type & (type))                 \
    p = x509_append_item(p, lim, buf, name);

    CERT_TYPE(MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT,         "SSL Client");
    CERT_TYPE(MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER,         "SSL Server");
    CERT_TYPE(MBEDTLS_X509_NS_CERT_TYPE_EMAIL,              "Email");
    CERT_TYPE(MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING,     "Object Signing");
    CERT_TYPE(MBEDTLS_X509_NS_CERT_TYPE_RESERVED,           "Reserved");
    CERT_TYPE(MBEDTLS_X509_NS_CERT_TYPE_SSL_CA,             "SSL CA");
    CERT_TYPE(MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA,           "Email CA");
    CERT_TYPE(MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA,  "Object Signing CA");

    return p;
}

static char *x509_info_key_usage(char * const buf, const char * const lim,
                                 unsigned int key_usage)
{
    char *p = buf;

    #define KEY_USAGE(code, name)    \
    if (key_usage & (code))    \
    p = x509_append_item(p, lim, buf, name);

    KEY_USAGE(MBEDTLS_X509_KU_DIGITAL_SIGNATURE,    "Digital Signature");
    KEY_USAGE(MBEDTLS_X509_KU_NON_REPUDIATION,      "Non Repudiation");
    KEY_USAGE(MBEDTLS_X509_KU_KEY_ENCIPHERMENT,     "Key Encipherment");
    KEY_USAGE(MBEDTLS_X509_KU_DATA_ENCIPHERMENT,    "Data Encipherment");
    KEY_USAGE(MBEDTLS_X509_KU_KEY_AGREEMENT,        "Key Agreement");
    KEY_USAGE(MBEDTLS_X509_KU_KEY_CERT_SIGN,        "Key Cert Sign");
    KEY_USAGE(MBEDTLS_X509_KU_CRL_SIGN,             "CRL Sign");
    KEY_USAGE(MBEDTLS_X509_KU_ENCIPHER_ONLY,        "Encipher Only");
    KEY_USAGE(MBEDTLS_X509_KU_DECIPHER_ONLY,        "Decipher Only");

    return p;
}

static char *x509_info_ext_key_usage(char * const buf, const char * const lim,
                                     const mbedtls_x509_sequence *extended_key_usage)
{
    const char *desc;
    char *p = buf;
    const mbedtls_x509_sequence *cur;

    for (cur = extended_key_usage; cur != NULL; cur = cur->next) {
        if (mbedtls_oid_get_extended_key_usage(&cur->buf, &desc) != 0) {
            desc = "???";
        }
        p = x509_append_item(p, lim, buf, desc);
    }

    return p;
}

static char *x509_info_cert_policies(char * const buf, const char * const lim,
                                     const mbedtls_x509_sequence *certificate_policies)
{
    const char *desc;
    char *p = buf;
    const mbedtls_x509_sequence *cur;

    for (cur = certificate_policies; cur != NULL; cur = cur->next) {
        if (mbedtls_oid_get_certificate_policies(&cur->buf, &desc) != 0) {
            desc = "???";
        }
        p = x509_append_item(p, lim, buf, desc);
    }

    return p;
}

/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
/*__attribute__((__returns_nonnull__))*//*(XXX: should use where supported)*/
static char *x509_append_item(char *p, const char *lim, const char *buf, const char *item)
{
    if (p != buf) {
        p = mbedtls_allpcpy_lim(p, lim, ", ");
    }
    return mbedtls_strpcpy_lim(p, lim, item);
}

/*
 * Return an informational string about the certificate.
 */
int mbedtls_x509_crt_info(char *buf, size_t size, const char *prefix,
                          const mbedtls_x509_crt *crt)
{
    char *p = buf;
    char * const lim = buf + size;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t plen = 1;
    char pre[64] = "\n";

    if (NULL == crt) {
        p = mbedtls_allpcpy_lim(p, lim, "\nCertificate is uninitialised!\n");
        return (int) mbedtls_strterm(buf, p, lim);
    }

    if (*prefix) {
        plen = (size_t)
               (mbedtls_strpcpy_lim(pre + 1, pre + sizeof(pre), prefix) - pre);
    }
    prefix = pre;

    p = mbedtls_mempcpy_lim(p, lim, prefix + 1, plen - 1);
    p = mbedtls_allpcpy_lim(p, lim, "cert. version     : ");
    p = mbedtls_itoa_lim(p, lim, crt->version);

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = mbedtls_allpcpy_lim(p, lim, "serial number     : ");
    ret = mbedtls_x509_serial_gets(p, (size_t) (lim - p), &crt->serial);
    p = (ret >= 0) ? p + ret : lim;

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = mbedtls_allpcpy_lim(p, lim, "issuer name       : ");
    ret = mbedtls_x509_dn_gets(p, (size_t) (lim - p), &crt->issuer);
    p = (ret >= 0) ? p + ret : lim;

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = mbedtls_allpcpy_lim(p, lim, "subject name      : ");
    ret = mbedtls_x509_dn_gets(p, (size_t) (lim - p), &crt->subject);
    p = (ret >= 0) ? p + ret : lim;

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = mbedtls_allpcpy_lim(p, lim, "issued  on        : ");
    p = mbedtls_x509_time_str(p, lim, &crt->valid_from);

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = mbedtls_allpcpy_lim(p, lim, "expires on        : ");
    p = mbedtls_x509_time_str(p, lim, &crt->valid_to);

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = mbedtls_allpcpy_lim(p, lim, "signed using      : ");
    ret = mbedtls_x509_sig_alg_gets(p, (size_t) (lim - p),
                                    &crt->sig_oid, crt->sig_pk,
                                    crt->sig_md, crt->sig_opts);
    p = (ret >= 0) ? p + ret : lim;

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = x509_info_pk_key_size(p, lim, &crt->pk, 18);

    /*
     * Optional extensions
     */

    if (crt->ext_types & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS) {
        p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
        if (crt->ca_istrue) {
            p = mbedtls_allpcpy_lim(p, lim, "basic constraints : CA=true");
        } else {
            p = mbedtls_allpcpy_lim(p, lim, "basic constraints : CA=false");
        }

        if (crt->max_pathlen > 0) {
            p = mbedtls_allpcpy_lim(p, lim, ", max_pathlen=");
            p = mbedtls_itoa_lim(p, lim, crt->max_pathlen - 1);
        }
    }

    if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
        p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
        p = mbedtls_allpcpy_lim(p, lim, "subject alt name  :");
        p = x509_info_subject_alt_name(p, (size_t) (lim - p),
                                       &crt->subject_alt_names,
                                       prefix, plen);
    }

    if (crt->ext_types & MBEDTLS_X509_EXT_NS_CERT_TYPE) {
        p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
        p = mbedtls_allpcpy_lim(p, lim, "cert. type        : ");
        p = x509_info_cert_type(p, lim, crt->ns_cert_type);
    }

    if (crt->ext_types & MBEDTLS_X509_EXT_KEY_USAGE) {
        p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
        p = mbedtls_allpcpy_lim(p, lim, "key usage         : ");
        p = x509_info_key_usage(p, lim, crt->key_usage);
    }

    if (crt->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE) {
        p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
        p = mbedtls_allpcpy_lim(p, lim, "ext key usage     : ");
        p = x509_info_ext_key_usage(p, lim, &crt->ext_key_usage);
    }

    if (crt->ext_types & MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES) {
        p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
        p = mbedtls_allpcpy_lim(p, lim, "certificate policies : ");
        p = x509_info_cert_policies(p, lim, &crt->certificate_policies);
    }

    p = mbedtls_mempcpy_lim(p, lim, "\n", 1);
    return (int) mbedtls_strterm(buf, p, lim);
}

int mbedtls_x509_crt_verify_info(char *buf, size_t size, const char *prefix,
                                 uint32_t flags)
{
    struct x509_crt_verify_string {
        int code;
        const char *string;
    };

    #define X509_CRT_ERROR_INFO(err, err_str, info) { err, info },
    static const struct x509_crt_verify_string x509_crt_verify_strings[] = {
        MBEDTLS_X509_CRT_ERROR_INFO_LIST
        { 0, NULL }
    };
    #undef X509_CRT_ERROR_INFO

    const struct x509_crt_verify_string *cur;
    char *p = buf;
    char * const lim = buf + size;
    const size_t plen = strlen(prefix);

    for (cur = x509_crt_verify_strings; cur->string != NULL; cur++) {
        if ((flags & cur->code) == 0) {
            continue;
        }
        flags ^= cur->code;

        p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
        p = mbedtls_strpcpy_lim(p, lim, cur->string);
        p = mbedtls_mempcpy_lim(p, lim, "\n", 1);
    }

    if (flags != 0) {
        p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
        p = mbedtls_allpcpy_lim(p, lim,
                                "Unknown reason (this should not happen)\n");
    }

    return (int) mbedtls_strterm(buf, p, lim);
}

#endif /* MBEDTLS_X509_CRT_PARSE_C */


#if defined(MBEDTLS_X509_CSR_PARSE_C)

/*
 * Return an informational string about the CSR.
 */
int mbedtls_x509_csr_info(char *buf, size_t size, const char *prefix,
                          const mbedtls_x509_csr *csr)
{
    char *p = buf;
    char * const lim = buf + size;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t plen = 1;
    char pre[64] = "\n";

    if (*prefix) {
        plen = (size_t)
               (mbedtls_strpcpy_lim(pre + 1, pre + sizeof(pre), prefix) - pre);
    }
    prefix = pre;

    p = mbedtls_mempcpy_lim(p, lim, prefix + 1, plen - 1);
    p = mbedtls_allpcpy_lim(p, lim, "CSR version   : ");
    p = mbedtls_itoa_lim(p, lim, csr->version);

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = mbedtls_allpcpy_lim(p, lim, "subject name  : ");
    ret = mbedtls_x509_dn_gets(p, (size_t) (lim - p), &csr->subject);
    p = (ret >= 0) ? p + ret : lim;

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = mbedtls_allpcpy_lim(p, lim, "signed using  : ");
    ret = mbedtls_x509_sig_alg_gets(p, (size_t) (lim - p),
                                    &csr->sig_oid, csr->sig_pk,
                                    csr->sig_md, csr->sig_opts);
    p = (ret >= 0) ? p + ret : lim;

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = x509_info_pk_key_size(p, lim, &csr->pk, 14);

    p = mbedtls_mempcpy_lim(p, lim, "\n", 1);
    return (int) mbedtls_strterm(buf, p, lim);
}

#endif /* MBEDTLS_X509_CSR_PARSE_C */


#if defined(MBEDTLS_X509_CRL_PARSE_C)

/*
 * Return an informational string about the CRL.
 */
int mbedtls_x509_crl_info(char *buf, size_t size, const char *prefix,
                          const mbedtls_x509_crl *crl)
{
    char *p = buf;
    char * const lim = buf + size;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_x509_crl_entry *entry;
    size_t plen = 1;
    char pre[64] = "\n";

    if (*prefix) {
        plen = (size_t)
               (mbedtls_strpcpy_lim(pre + 1, pre + sizeof(pre), prefix) - pre);
    }
    prefix = pre;

    p = mbedtls_mempcpy_lim(p, lim, prefix + 1, plen - 1);
    p = mbedtls_allpcpy_lim(p, lim, "CRL version   : ");
    p = mbedtls_itoa_lim(p, lim, crl->version);

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = mbedtls_allpcpy_lim(p, lim, "issuer name   : ");
    ret = mbedtls_x509_dn_gets(p, (size_t) (lim - p), &crl->issuer);
    p = (ret >= 0) ? p + ret : lim;

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = mbedtls_allpcpy_lim(p, lim, "this update   : ");
    p = mbedtls_x509_time_str(p, lim, &crl->this_update);

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = mbedtls_allpcpy_lim(p, lim, "next update   : ");
    p = mbedtls_x509_time_str(p, lim, &crl->next_update);

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = mbedtls_allpcpy_lim(p, lim, "Revoked certificates:");

    entry = &crl->entry;
    while (entry != NULL && entry->raw.len != 0) {
        p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
        p = mbedtls_allpcpy_lim(p, lim, "serial number: ");
        ret = mbedtls_x509_serial_gets(p, (size_t) (lim - p),
                                       &entry->serial);
        p = (ret >= 0) ? p + ret : lim;

        p = mbedtls_allpcpy_lim(p, lim, " revocation date: ");
        p = mbedtls_x509_time_str(p, lim, &entry->revocation_date);

        entry = entry->next;
    }

    p = mbedtls_mempcpy_lim(p, lim, prefix, plen);
    p = mbedtls_allpcpy_lim(p, lim, "signed using  : ");
    ret = mbedtls_x509_sig_alg_gets(p, (size_t) (lim - p),
                                    &crl->sig_oid, crl->sig_pk,
                                    crl->sig_md, crl->sig_opts);
    p = (ret >= 0) ? p + ret : lim;

    p = mbedtls_mempcpy_lim(p, lim, "\n", 1);
    return (int) mbedtls_strterm(buf, p, lim);
}

#endif /* MBEDTLS_X509_CRL_PARSE_C */


#if defined(MBEDTLS_X509_USE_C)

/* funcs placed near bottom of file to avoid inlining in older compilers */

/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
static char *mbedtls_x509_time_str(char *dst, const char *lim,
                                   const mbedtls_x509_time *tm)
{
    size_t n = (size_t) (lim - dst);
    int ret = mbedtls_snprintf(dst, n, "%04d-%02d-%02d %02d:%02d:%02d",
                               tm->year, tm->mon, tm->day,
                               tm->hour, tm->min, tm->sec);
    return (ret >= 0 && (size_t) ret < n) ? dst + ret : dst + n;
}

/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
static intptr_t mbedtls_strterm(char *buf, char *p, const char *lim)
{
    if (p < lim) {
        p[0] = '\0';
        return (intptr_t) (p - buf);
    } else {
        if (p != buf) {
            p[-1] = '\0';
        }
        return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
    }
}

/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
/*__attribute__((__returns_nonnull__))*//*(XXX: should use where supported)*/
static char *mbedtls_strpcpy_lim(char *dst, const char *lim, const char *src)
{
    return mbedtls_mempcpy_lim(dst, lim, src, strlen(src));
}

/*
 * Append to dst up to len bytes from src, limited by lim (dst + dst_sz)
 * Note: like mempcpy(), this function does not '\0' terminate string.
 * Caller may call this function repeatedly, passing in dst as the return value
 * from a prior invocation, even if lim has been reached.  Before using result,
 * caller must detect truncated string by checking if return value == lim.
 * Final length of string (not '\0' terminated) is return value - original dst
 * and may be '\0' terminated by final_dst[(final_dst <= lim ? 0 : -1)] = '\0'
 */
/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
/*__attribute__((__returns_nonnull__))*//*(XXX: should use where supported)*/
static char *mbedtls_mempcpy_lim(char *dst, const char *lim,
                                 const void *src, size_t len)
{
    if (len > (size_t) (lim - dst)) {
        len = lim - dst;
    }
  #ifdef HAVE_MEMPCPY
    return mempcpy(dst, src, len);
  #else
    memcpy(dst, src, len);
    return dst + len;
  #endif
}

/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
static char *mbedtls_strhex_lim(char *dst, const char *lim,
                                const unsigned char *src, size_t len)
{
    len <<= 1;
    if (len > (size_t) (lim - dst)) {
        len = lim - dst;
    }
    for (size_t i = 0; i < len; i += 2) {
        static const char hex_chars_uc[] = "0123456789ABCDEF";
        uint8_t u = src[(i >> 1)];
        dst[i] = hex_chars_uc[(u >> 4) & 0xF];
        if (i + 1 < len) {
            dst[i+1] = hex_chars_uc[(u & 0xF)];
        }
    }
    return dst + len;
}

/*__attribute__((__noinline__))*//*(XXX: should use where supported)*/
/*__attribute__((__nonnull__))*//*(XXX: should use where supported)*/
/*__attribute__((__returns_nonnull__))*//*(XXX: should use where supported)*/
static char *mbedtls_itoa_lim(char *dst, const char *lim, int i)
{
    /* XXX: custom itoa() might be faster, but would increase code size */
    const size_t n = (size_t) (lim - dst);
    const int ret = mbedtls_snprintf(dst, n, "%d", i);
    return dst + ((ret >= 0 && (size_t) ret < n) ? (size_t) ret : n);
}

#endif /* MBEDTLS_X509_USE_C */

#endif /* MBEDTLS_X509_REMOVE_INFO */


#if defined(MBEDTLS_X509_USE_C)

/*
 * Store the name in printable form into buf; no more
 * than size characters will be written
 */
int mbedtls_x509_dn_gets(char *buf, size_t size, const mbedtls_x509_name *dn)
{
    size_t n = 0, plen = 0, klen;
    const char *short_name;

    for (const mbedtls_x509_name *rdn = dn; rdn != NULL; rdn = rdn->next) {
        if (!rdn->oid.p) {
            continue;
        }

        if (0 != mbedtls_oid_get_attr_short_name(&rdn->oid, &short_name)) {
            short_name = "??";
        }
        klen = strlen(short_name);

        /*(space check for: prefix + 'short_name=val' + '\0')*/
        if (plen + klen + 1 + rdn->val.len + 1 > size - n) {
            if (size) {
                buf[n] = '\0';
            }
            return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        }

        if (plen) {
            memcpy(buf+n, plen == 2 ? ", " : " + ", plen);
            n += plen;
        }

        memcpy(buf+n, short_name, klen);
        n += klen;
        buf[n++] = '=';

        for (size_t i = 0; i < rdn->val.len; ++i) {
            unsigned int c = rdn->val.p[i];
            if (c - 32 >= 127 - 32) {
                c = '?';
            } else if (memchr("\"#+,;<=>\\", (int) c,
                              sizeof("\"#+,;<=>\\") - 1)) {
                /* Special characters requiring escaping, RFC 1779 */
                if (rdn->val.len - i + 2 > size - n) {
                    buf[n] = '\0';
                    return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
                }
                buf[n++] = '\\';
            }
            buf[n++] = c;
        }

        plen = rdn->next_merged ? 3 : 2; /*(" + " or ", ")*/
    }

    if (size) {
        buf[n] = '\0';
    }
    return (int) n;
}

/*
 * Store the serial in printable form into buf; no more
 * than size characters will be written
 */
int mbedtls_x509_serial_gets(char *buf, size_t size, const mbedtls_x509_buf *serial)
{
    char xbuf[100]; /* large enough for (2 x 32) nibbles + 31 ':' */
    char *x = xbuf;
    const int nr = (serial->len <= 32) ? (int) serial->len : 28;

    int i = 0; /* skip leading 0's per Distinguished Encoding Rules (DER) */
    while (i < nr && serial->p[i] == 0) {
        ++i;
    }
    if (i == nr) {
        --i;
    }

    for (;;) {
        static const char hex_chars_uc[] = "0123456789ABCDEF";
        unsigned int u = serial->p[i];
        *x++ = hex_chars_uc[0x0F & (u >> 4)];
        *x++ = hex_chars_uc[0x0F & u];

        if (++i < nr) {
            *x++ = ':';
        } else {
            break;
        }
    }

    if ((size_t) nr != serial->len) {
        memcpy(x, "....", 4);
        x += 4;
    }

    {
      #if 0 /*(limit use of mbedtls_*pcpy_lim() to !MBEDTLS_X509_REMOVE_INFO)*/
        const char * const lim = buf + size;
        char *p = mbedtls_mempcpy_lim(buf, lim, xbuf, (size_t) (x - xbuf));
        return (int) mbedtls_strterm(buf, p, lim);
      #else
        const size_t xlen = (size_t) (x - xbuf);
        if (size) {
            const size_t len = xlen < size ? xlen : size - 1;
            memcpy(buf, xbuf, len);
            buf[len] = '\0';
        }
        return (xlen < size) ? (int) xlen : MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
      #endif
    }
}

#if defined(MBEDTLS_X509_REMOVE_INFO)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_snprintf   snprintf
#endif
#endif
/*
 * Helper for writing "RSA key size", "EC key size", etc
 */
int mbedtls_x509_key_size_helper(char *buf, size_t buf_size, const char *name)
{
    /* XXX: unused func; deprecate */
  #if 0 /*(limit use of mbedtls_*pcpy_lim() to !MBEDTLS_X509_REMOVE_INFO)*/
    char *p = buf;
    const char * const lim = buf + buf_size;
    p = mbedtls_strpcpy_lim(p, lim, name);
    p = mbedtls_allpcpy_lim(p, lim, " key size");
    int ret = (int) mbedtls_strterm(buf, p, lim);
    return (ret >= 0) ? 0 : ret;
  #else
    int ret = mbedtls_snprintf(buf, buf_size, "%s key size", name);
    if (ret < 0 || (size_t) ret >= buf_size) {
        return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
    }
    return 0;
  #endif
}

#endif /* MBEDTLS_X509_USE_C */
