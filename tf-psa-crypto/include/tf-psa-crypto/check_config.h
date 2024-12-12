/**
 * \file tf-psa-crypto/check_config.h
 *
 * \brief Consistency checks for configuration options
 *
 * This is an internal header. Do not include it directly.
 *
 * This header is included automatically by all public TF-PSA-Crypto headers
 * (via tf-psa-crypto/build_info.h). Do not include it directly in a
 * configuration file such as psa/crypto_config.h or #TF_PSA_CRYPTO_USER_CONFIG_FILE!
 * It would run at the wrong time due to missing derived symbols.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_CHECK_CONFIG_H
#define TF_PSA_CRYPTO_CHECK_CONFIG_H

/* *INDENT-OFF* */

#if !defined(TF_PSA_CRYPTO_CONFIG_IS_FINALIZED)
#warning "Do not include mbedtls/check_config.h manually! " \
         "This may cause spurious errors. " \
         "It is included automatically at the right point since Mbed TLS 3.0."
#endif /* !TF_PSA_CRYPTO_CONFIG_IS_FINALIZED */

/*
 * We assume CHAR_BIT is 8 in many places. In practice, this is true on our
 * target platforms, so not an issue, but let's just be extra sure.
 */
#include <limits.h>
#if CHAR_BIT != 8
#error "Mbed TLS requires a platform with 8-bit chars"
#endif

#include <stdint.h>

#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER <= 1900)
#if !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_C is required on Windows"
#endif
/* See auto-enabling SNPRINTF_ALT and VSNPRINTF_ALT
 * in * config_adjust_legacy_crypto.h */
#endif /* _MINGW32__ || (_MSC_VER && (_MSC_VER <= 1900)) */

#if defined(MBEDTLS_DEPRECATED_WARNING) && \
    !defined(__GNUC__) && !defined(__clang__)
#error "MBEDTLS_DEPRECATED_WARNING only works with GCC and Clang"
#endif

/* Limitations on ECC key types acceleration: if we have any of `PUBLIC_KEY`,
 * `KEY_PAIR_BASIC`, `KEY_PAIR_IMPORT`, `KEY_PAIR_EXPORT` then we must have
 * all 4 of them.
 */
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_BASIC) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_IMPORT) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_EXPORT)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY) || \
    !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_BASIC) || \
    !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_IMPORT) || \
    !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_EXPORT)
#error "Unsupported partial support for ECC key type acceleration, see docs/driver-only-builds.md"
#endif /* not all of public, basic, import, export */
#endif /* one of public, basic, import, export */

/* Limitations on ECC curves acceleration: partial curve acceleration is only
 * supported with crypto excluding PK, X.509 or TLS.
 * Note: no need to check X.509 as it depends on PK. */
#if defined(MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_256) || \
    defined(MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_384) || \
    defined(MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_512) || \
    defined(MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_255) || \
    defined(MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_448) || \
    defined(MBEDTLS_PSA_ACCEL_ECC_SECP_K1_192) || \
    defined(MBEDTLS_PSA_ACCEL_ECC_SECP_K1_224) || \
    defined(MBEDTLS_PSA_ACCEL_ECC_SECP_K1_256) || \
    defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_192) || \
    defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_224) || \
    defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_256) || \
    defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_384) || \
    defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_521)
#if defined(MBEDTLS_PSA_ECC_ACCEL_INCOMPLETE_CURVES)
#if defined(MBEDTLS_PK_C)
#error "Unsupported partial support for ECC curves acceleration, see docs/driver-only-builds.md"
#endif /* modules beyond what's supported */
#endif /* not all curves accelerated */
#endif /* some curve accelerated */

#if defined(MBEDTLS_CTR_DRBG_C) && !(defined(MBEDTLS_AES_C) || \
    (defined(MBEDTLS_PSA_CRYPTO_CLIENT) && defined(PSA_WANT_KEY_TYPE_AES) && \
    defined(PSA_WANT_ALG_ECB_NO_PADDING)))
#error "MBEDTLS_CTR_DRBG_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_DHM_C) && !defined(MBEDTLS_BIGNUM_C)
#error "MBEDTLS_DHM_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_CMAC_C) && \
    ( !defined(MBEDTLS_CIPHER_C ) || ( !defined(MBEDTLS_AES_C) && !defined(MBEDTLS_DES_C) ) )
#error "MBEDTLS_CMAC_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_NIST_KW_C) && \
    ( !defined(MBEDTLS_AES_C) || !defined(MBEDTLS_CIPHER_C) )
#error "MBEDTLS_NIST_KW_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
#if defined(PSA_WANT_ALG_CBC_NO_PADDING)
#error "MBEDTLS_BLOCK_CIPHER_NO_DECRYPT and PSA_WANT_ALG_CBC_NO_PADDING cannot be defined simultaneously"
#endif
#if defined(PSA_WANT_ALG_CBC_PKCS7)
#error "MBEDTLS_BLOCK_CIPHER_NO_DECRYPT and PSA_WANT_ALG_CBC_PKCS7 cannot be defined simultaneously"
#endif
#if defined(PSA_WANT_ALG_ECB_NO_PADDING)
#error "MBEDTLS_BLOCK_CIPHER_NO_DECRYPT and PSA_WANT_ALG_ECB_NO_PADDING cannot be defined simultaneously"
#endif
#if defined(PSA_WANT_KEY_TYPE_DES)
#error "MBEDTLS_BLOCK_CIPHER_NO_DECRYPT and PSA_WANT_KEY_TYPE_DES cannot be defined simultaneously"
#endif
#endif

#if defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
#if defined(MBEDTLS_CIPHER_MODE_CBC)
#error "MBEDTLS_BLOCK_CIPHER_NO_DECRYPT and MBEDTLS_CIPHER_MODE_CBC cannot be defined simultaneously"
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
#error "MBEDTLS_BLOCK_CIPHER_NO_DECRYPT and MBEDTLS_CIPHER_MODE_XTS cannot be defined simultaneously"
#endif
#if defined(MBEDTLS_DES_C)
#error "MBEDTLS_BLOCK_CIPHER_NO_DECRYPT and MBEDTLS_DES_C cannot be defined simultaneously"
#endif
#if defined(MBEDTLS_NIST_KW_C)
#error "MBEDTLS_BLOCK_CIPHER_NO_DECRYPT and MBEDTLS_NIST_KW_C cannot be defined simultaneously"
#endif
#endif

#if defined(MBEDTLS_ECDH_C) && !defined(MBEDTLS_ECP_C)
#error "MBEDTLS_ECDH_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECDSA_C) &&            \
    ( !defined(MBEDTLS_ECP_C) ||           \
      !( defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED) || \
         defined(MBEDTLS_ECP_DP_BP256R1_ENABLED) ||   \
         defined(MBEDTLS_ECP_DP_BP384R1_ENABLED) ||   \
         defined(MBEDTLS_ECP_DP_BP512R1_ENABLED) ) || \
      !defined(MBEDTLS_ASN1_PARSE_C) ||    \
      !defined(MBEDTLS_ASN1_WRITE_C) )
#error "MBEDTLS_ECDSA_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(PSA_HAVE_ALG_ECDSA_SIGN) && !defined(MBEDTLS_ASN1_WRITE_C)
#error "MBEDTLS_PK_C with MBEDTLS_USE_PSA_CRYPTO needs MBEDTLS_ASN1_WRITE_C for ECDSA signature"
#endif
#if defined(PSA_HAVE_ALG_ECDSA_VERIFY) && !defined(MBEDTLS_ASN1_PARSE_C)
#error "MBEDTLS_PK_C with MBEDTLS_USE_PSA_CRYPTO needs MBEDTLS_ASN1_PARSE_C for ECDSA verification"
#endif
#endif /* MBEDTLS_PK_C && MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_ECJPAKE_C) && \
    !defined(MBEDTLS_ECP_C)
#error "MBEDTLS_ECJPAKE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)           && \
    !defined(MBEDTLS_ECP_C)
#error "MBEDTLS_ECP_RESTARTABLE defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECDSA_DETERMINISTIC) && !defined(MBEDTLS_HMAC_DRBG_C)
#error "MBEDTLS_ECDSA_DETERMINISTIC defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ECP_LIGHT) && ( !defined(MBEDTLS_BIGNUM_C) || (    \
    !defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)   &&                  \
    !defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)   &&                  \
    !defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)   &&                  \
    !defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED) &&                  \
    !defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) &&                 \
    !defined(MBEDTLS_ECP_DP_CURVE448_ENABLED) ) )
#error "MBEDTLS_ECP_C defined (or a subset enabled), but not all prerequisites"
#endif

#if defined(MBEDTLS_ENTROPY_C) && \
    !(defined(PSA_WANT_ALG_SHA_512) || defined(PSA_WANT_ALG_SHA_256))
#error "MBEDTLS_ENTROPY_C defined, but not all prerequisites"
#endif
#if defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_CTR_DRBG_ENTROPY_LEN) && (MBEDTLS_CTR_DRBG_ENTROPY_LEN > 64)
#error "MBEDTLS_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(MBEDTLS_ENTROPY_C) &&                                            \
    (defined(MBEDTLS_ENTROPY_FORCE_SHA256) || !defined(PSA_WANT_ALG_SHA_512)) \
    && defined(MBEDTLS_CTR_DRBG_ENTROPY_LEN) && (MBEDTLS_CTR_DRBG_ENTROPY_LEN > 32)
#error "MBEDTLS_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_ENTROPY_FORCE_SHA256) && !defined(PSA_WANT_ALG_SHA_256)
#error "MBEDTLS_ENTROPY_FORCE_SHA256 defined, but not all prerequisites"
#endif

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#define MBEDTLS_HAS_MEMSAN // #undef at the end of this paragraph
#endif
#endif
#if defined(MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN) &&  !defined(MBEDTLS_HAS_MEMSAN)
#error "MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN requires building with MemorySanitizer"
#endif
#if defined(MBEDTLS_HAS_MEMSAN) && defined(MBEDTLS_HAVE_ASM)
#error "MemorySanitizer does not support assembly implementation"
#endif
#undef MBEDTLS_HAS_MEMSAN // temporary macro defined above

#if defined(MBEDTLS_CCM_C) && \
    !(defined(MBEDTLS_CCM_GCM_CAN_AES) || defined(MBEDTLS_CCM_GCM_CAN_ARIA) || \
    defined(MBEDTLS_CCM_GCM_CAN_CAMELLIA))
#error "MBEDTLS_CCM_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_GCM_C) && \
    !(defined(MBEDTLS_CCM_GCM_CAN_AES) || defined(MBEDTLS_CCM_GCM_CAN_ARIA) || \
    defined(MBEDTLS_CCM_GCM_CAN_CAMELLIA))
#error "MBEDTLS_GCM_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_CHACHAPOLY_C) && !defined(MBEDTLS_CHACHA20_C)
#error "MBEDTLS_CHACHAPOLY_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_CHACHAPOLY_C) && !defined(MBEDTLS_POLY1305_C)
#error "MBEDTLS_CHACHAPOLY_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_HKDF_C) && !defined(MBEDTLS_MD_C)
#error "MBEDTLS_HKDF_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_HMAC_DRBG_C) && !defined(MBEDTLS_MD_C)
#error "MBEDTLS_HMAC_DRBG_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_MD_C) && \
    !defined(PSA_WANT_ALG_MD5) && \
    !defined(PSA_WANT_ALG_RIPEMD160) && \
    !defined(PSA_WANT_ALG_SHA_1) && \
    !defined(PSA_WANT_ALG_SHA_224) && \
    !defined(PSA_WANT_ALG_SHA_256) && \
    !defined(PSA_WANT_ALG_SHA_384) && \
    !defined(PSA_WANT_ALG_SHA_512) && \
    !defined(PSA_WANT_ALG_SHA3_224) && \
    !defined(PSA_WANT_ALG_SHA3_256) && \
    !defined(PSA_WANT_ALG_SHA3_384) && \
    !defined(PSA_WANT_ALG_SHA3_512)
#error "MBEDTLS_MD_C defined, but no hash algorithm"
#endif

#if defined(MBEDTLS_LMS_C) &&                                          \
    ! ( defined(MBEDTLS_PSA_CRYPTO_CLIENT) && defined(PSA_WANT_ALG_SHA_256) )
#error "MBEDTLS_LMS_C requires MBEDTLS_PSA_CRYPTO_C and PSA_WANT_ALG_SHA_256"
#endif

#if defined(MBEDTLS_LMS_PRIVATE) &&                                    \
    ( !defined(MBEDTLS_LMS_C) )
#error "MBEDTLS_LMS_PRIVATE requires MBEDTLS_LMS_C"
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) &&                          \
    ( !defined(MBEDTLS_PLATFORM_C) || !defined(MBEDTLS_PLATFORM_MEMORY) )
#error "MBEDTLS_MEMORY_BUFFER_ALLOC_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_MEMORY_BACKTRACE) && !defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#error "MBEDTLS_MEMORY_BACKTRACE defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_MEMORY_DEBUG) && !defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#error "MBEDTLS_MEMORY_DEBUG defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PEM_PARSE_C) && !defined(MBEDTLS_BASE64_C)
#error "MBEDTLS_PEM_PARSE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PEM_WRITE_C) && !defined(MBEDTLS_BASE64_C)
#error "MBEDTLS_PEM_WRITE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PK_C) && \
    !defined(MBEDTLS_RSA_C) && !defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
#error "MBEDTLS_PK_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PK_PARSE_C) && \
    (!defined(MBEDTLS_ASN1_PARSE_C) || \
     !defined(MBEDTLS_OID_C)        || \
     !defined(MBEDTLS_PK_C))
#error "MBEDTLS_PK_PARSE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PK_WRITE_C) && \
    (!defined(MBEDTLS_ASN1_WRITE_C) || \
     !defined(MBEDTLS_OID_C)        || \
     !defined(MBEDTLS_PK_C))
#error "MBEDTLS_PK_WRITE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_EXIT_ALT) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_EXIT_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_EXIT_MACRO) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_EXIT_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_EXIT_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_EXIT) ||\
        defined(MBEDTLS_PLATFORM_EXIT_ALT) )
#error "MBEDTLS_PLATFORM_EXIT_MACRO and MBEDTLS_PLATFORM_STD_EXIT/MBEDTLS_PLATFORM_EXIT_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_SETBUF_ALT) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_SETBUF_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_SETBUF_MACRO) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_SETBUF_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_SETBUF_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_SETBUF) ||\
        defined(MBEDTLS_PLATFORM_SETBUF_ALT) )
#error "MBEDTLS_PLATFORM_SETBUF_MACRO and MBEDTLS_PLATFORM_STD_SETBUF/MBEDTLS_PLATFORM_SETBUF_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_TIME_ALT) &&\
    ( !defined(MBEDTLS_PLATFORM_C) ||\
        !defined(MBEDTLS_HAVE_TIME) )
#error "MBEDTLS_PLATFORM_TIME_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_TIME_MACRO) &&\
    ( !defined(MBEDTLS_PLATFORM_C) ||\
        !defined(MBEDTLS_HAVE_TIME) )
#error "MBEDTLS_PLATFORM_TIME_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO) &&\
    ( !defined(MBEDTLS_PLATFORM_C) || !defined(MBEDTLS_HAVE_TIME) )
#error "MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_MS_TIME_ALT)   && \
    ( !defined(MBEDTLS_PLATFORM_C) || !defined(MBEDTLS_HAVE_TIME) )
#error "MBEDTLS_PLATFORM_MS_TIME_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_TIME_TYPE_MACRO) &&\
    ( !defined(MBEDTLS_PLATFORM_C) ||\
        !defined(MBEDTLS_HAVE_TIME) )
#error "MBEDTLS_PLATFORM_TIME_TYPE_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_TIME_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_TIME) ||\
        defined(MBEDTLS_PLATFORM_TIME_ALT) )
#error "MBEDTLS_PLATFORM_TIME_MACRO and MBEDTLS_PLATFORM_STD_TIME/MBEDTLS_PLATFORM_TIME_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_TIME_TYPE_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_TIME) ||\
        defined(MBEDTLS_PLATFORM_TIME_ALT) )
#error "MBEDTLS_PLATFORM_TIME_TYPE_MACRO and MBEDTLS_PLATFORM_STD_TIME/MBEDTLS_PLATFORM_TIME_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_FPRINTF_ALT) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_FPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_FPRINTF_MACRO) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_FPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_FPRINTF_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_FPRINTF) ||\
        defined(MBEDTLS_PLATFORM_FPRINTF_ALT) )
#error "MBEDTLS_PLATFORM_FPRINTF_MACRO and MBEDTLS_PLATFORM_STD_FPRINTF/MBEDTLS_PLATFORM_FPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_FREE_MACRO) &&\
    ( !defined(MBEDTLS_PLATFORM_C) || !defined(MBEDTLS_PLATFORM_MEMORY) )
#error "MBEDTLS_PLATFORM_FREE_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_FREE_MACRO) &&\
    defined(MBEDTLS_PLATFORM_STD_FREE)
#error "MBEDTLS_PLATFORM_FREE_MACRO and MBEDTLS_PLATFORM_STD_FREE cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_FREE_MACRO) && !defined(MBEDTLS_PLATFORM_CALLOC_MACRO)
#error "MBEDTLS_PLATFORM_CALLOC_MACRO must be defined if MBEDTLS_PLATFORM_FREE_MACRO is"
#endif

#if defined(MBEDTLS_PLATFORM_CALLOC_MACRO) &&\
    ( !defined(MBEDTLS_PLATFORM_C) || !defined(MBEDTLS_PLATFORM_MEMORY) )
#error "MBEDTLS_PLATFORM_CALLOC_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_CALLOC_MACRO) &&\
    defined(MBEDTLS_PLATFORM_STD_CALLOC)
#error "MBEDTLS_PLATFORM_CALLOC_MACRO and MBEDTLS_PLATFORM_STD_CALLOC cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_CALLOC_MACRO) && !defined(MBEDTLS_PLATFORM_FREE_MACRO)
#error "MBEDTLS_PLATFORM_FREE_MACRO must be defined if MBEDTLS_PLATFORM_CALLOC_MACRO is"
#endif

#if defined(MBEDTLS_PLATFORM_MEMORY) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_MEMORY defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_PRINTF_ALT) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_PRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_PRINTF_MACRO) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_PRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_PRINTF_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_PRINTF) ||\
        defined(MBEDTLS_PLATFORM_PRINTF_ALT) )
#error "MBEDTLS_PLATFORM_PRINTF_MACRO and MBEDTLS_PLATFORM_STD_PRINTF/MBEDTLS_PLATFORM_PRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_SNPRINTF_ALT) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_SNPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_SNPRINTF_MACRO) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_SNPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_SNPRINTF_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_SNPRINTF) ||\
        defined(MBEDTLS_PLATFORM_SNPRINTF_ALT) )
#error "MBEDTLS_PLATFORM_SNPRINTF_MACRO and MBEDTLS_PLATFORM_STD_SNPRINTF/MBEDTLS_PLATFORM_SNPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_VSNPRINTF_ALT) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_VSNPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_VSNPRINTF_MACRO) && !defined(MBEDTLS_PLATFORM_C)
#error "MBEDTLS_PLATFORM_VSNPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_VSNPRINTF_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_VSNPRINTF) ||\
        defined(MBEDTLS_PLATFORM_VSNPRINTF_ALT) )
#error "MBEDTLS_PLATFORM_VSNPRINTF_MACRO and MBEDTLS_PLATFORM_STD_VSNPRINTF/MBEDTLS_PLATFORM_VSNPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_STD_MEM_HDR) &&\
    !defined(MBEDTLS_PLATFORM_NO_STD_FUNCTIONS)
#error "MBEDTLS_PLATFORM_STD_MEM_HDR defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_CALLOC) && !defined(MBEDTLS_PLATFORM_MEMORY)
#error "MBEDTLS_PLATFORM_STD_CALLOC defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_FREE) && !defined(MBEDTLS_PLATFORM_MEMORY)
#error "MBEDTLS_PLATFORM_STD_FREE defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_EXIT) &&\
    !defined(MBEDTLS_PLATFORM_EXIT_ALT)
#error "MBEDTLS_PLATFORM_STD_EXIT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_TIME) &&\
    ( !defined(MBEDTLS_PLATFORM_TIME_ALT) ||\
        !defined(MBEDTLS_HAVE_TIME) )
#error "MBEDTLS_PLATFORM_STD_TIME defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_FPRINTF) &&\
    !defined(MBEDTLS_PLATFORM_FPRINTF_ALT)
#error "MBEDTLS_PLATFORM_STD_FPRINTF defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_PRINTF) &&\
    !defined(MBEDTLS_PLATFORM_PRINTF_ALT)
#error "MBEDTLS_PLATFORM_STD_PRINTF defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_SNPRINTF) &&\
    !defined(MBEDTLS_PLATFORM_SNPRINTF_ALT)
#error "MBEDTLS_PLATFORM_STD_SNPRINTF defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_ENTROPY_NV_SEED) &&\
    ( !defined(MBEDTLS_PLATFORM_C) || !defined(MBEDTLS_ENTROPY_C) )
#error "MBEDTLS_ENTROPY_NV_SEED defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_NV_SEED_ALT) &&\
    !defined(MBEDTLS_ENTROPY_NV_SEED)
#error "MBEDTLS_PLATFORM_NV_SEED_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_NV_SEED_READ) &&\
    !defined(MBEDTLS_PLATFORM_NV_SEED_ALT)
#error "MBEDTLS_PLATFORM_STD_NV_SEED_READ defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_STD_NV_SEED_WRITE) &&\
    !defined(MBEDTLS_PLATFORM_NV_SEED_ALT)
#error "MBEDTLS_PLATFORM_STD_NV_SEED_WRITE defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PLATFORM_NV_SEED_READ_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_NV_SEED_READ) ||\
      defined(MBEDTLS_PLATFORM_NV_SEED_ALT) )
#error "MBEDTLS_PLATFORM_NV_SEED_READ_MACRO and MBEDTLS_PLATFORM_STD_NV_SEED_READ cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO) &&\
    ( defined(MBEDTLS_PLATFORM_STD_NV_SEED_WRITE) ||\
      defined(MBEDTLS_PLATFORM_NV_SEED_ALT) )
#error "MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO and MBEDTLS_PLATFORM_STD_NV_SEED_WRITE cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_C) &&                                    \
    !( ( ( defined(MBEDTLS_CTR_DRBG_C) || defined(MBEDTLS_HMAC_DRBG_C) ) && \
         defined(MBEDTLS_ENTROPY_C) ) ||                                \
       defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) )
#error "MBEDTLS_PSA_CRYPTO_C defined, but not all prerequisites (missing RNG)"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_HAVE_SOFT_BLOCK_MODE) && \
    defined(PSA_HAVE_SOFT_BLOCK_CIPHER) && !defined(MBEDTLS_CIPHER_C)
#error "MBEDTLS_PSA_CRYPTO_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_SPM) && !defined(MBEDTLS_PSA_CRYPTO_C)
#error "MBEDTLS_PSA_CRYPTO_SPM defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_SE_C) &&    \
    ! ( defined(MBEDTLS_PSA_CRYPTO_C) && \
        defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) )
#error "MBEDTLS_PSA_CRYPTO_SE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
#if defined(MBEDTLS_DEPRECATED_REMOVED)
#error "MBEDTLS_PSA_CRYPTO_SE_C is deprecated and will be removed in a future version of Mbed TLS"
#elif defined(MBEDTLS_DEPRECATED_WARNING)
#warning "MBEDTLS_PSA_CRYPTO_SE_C is deprecated and will be removed in a future version of Mbed TLS"
#endif
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) &&            \
    ! defined(MBEDTLS_PSA_CRYPTO_C)
#error "MBEDTLS_PSA_CRYPTO_STORAGE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PSA_INJECT_ENTROPY) &&      \
    !( defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) && \
       defined(MBEDTLS_ENTROPY_NV_SEED) )
#error "MBEDTLS_PSA_INJECT_ENTROPY defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_PSA_INJECT_ENTROPY) &&              \
    !defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES)
#error "MBEDTLS_PSA_INJECT_ENTROPY is not compatible with actual entropy sources"
#endif

#if defined(MBEDTLS_PSA_INJECT_ENTROPY) &&              \
    defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
#error "MBEDTLS_PSA_INJECT_ENTROPY is not compatible with MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG"
#endif

#if defined(MBEDTLS_PSA_KEY_STORE_DYNAMIC) &&           \
    defined(MBEDTLS_PSA_STATIC_KEY_SLOTS)
#error "MBEDTLS_PSA_KEY_STORE_DYNAMIC and MBEDTLS_PSA_STATIC_KEY_SLOTS cannot be defined simultaneously"
#endif

#if defined(MBEDTLS_PSA_ITS_FILE_C) && \
    !defined(MBEDTLS_FS_IO)
#error "MBEDTLS_PSA_ITS_FILE_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_RSA_C) && ( !defined(MBEDTLS_BIGNUM_C) ||         \
    !defined(MBEDTLS_OID_C) )
#error "MBEDTLS_RSA_C defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_RSA_C) && ( !defined(MBEDTLS_PKCS1_V21) &&         \
    !defined(MBEDTLS_PKCS1_V15) )
#error "MBEDTLS_RSA_C defined, but none of the PKCS1 versions enabled"
#endif

#if defined(MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT) && \
    defined(MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY)
#error "Must only define one of MBEDTLS_SHA512_USE_A64_CRYPTO_*"
#endif

#if defined(MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT) || \
    defined(MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY)
#if !defined(MBEDTLS_SHA512_C)
#error "MBEDTLS_SHA512_USE_A64_CRYPTO_* defined without MBEDTLS_SHA512_C"
#endif

#endif /* MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT || MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY */

#if defined(MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY) && !defined(__aarch64__)
#error "MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY defined on non-Aarch64 system"
#endif

#if defined(MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT) && \
    defined(MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY)
#error "Must only define one of MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_*"
#endif

#if defined(MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT) || \
    defined(MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY)
#if !defined(MBEDTLS_SHA256_C)
#error "MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_* defined without MBEDTLS_SHA256_C"
#endif

#endif

#if defined(MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY) && !defined(MBEDTLS_ARCH_IS_ARMV8_A)
#error "MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY defined on non-Armv8-A system"
#endif

#if defined(MBEDTLS_THREADING_PTHREAD)
#if !defined(MBEDTLS_THREADING_C) || defined(MBEDTLS_THREADING_IMPL)
#error "MBEDTLS_THREADING_PTHREAD defined, but not all prerequisites"
#endif
#define MBEDTLS_THREADING_IMPL // undef at the end of this paragraph
#endif
#if defined(MBEDTLS_THREADING_ALT)
#if !defined(MBEDTLS_THREADING_C) || defined(MBEDTLS_THREADING_IMPL)
#error "MBEDTLS_THREADING_ALT defined, but not all prerequisites"
#endif
#define MBEDTLS_THREADING_IMPL // undef at the end of this paragraph
#endif
#if defined(MBEDTLS_THREADING_C) && !defined(MBEDTLS_THREADING_IMPL)
#error "MBEDTLS_THREADING_C defined, single threading implementation required"
#endif
#undef MBEDTLS_THREADING_IMPL // temporary macro defined above

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_PSA_CRYPTO_CLIENT)
#error "MBEDTLS_USE_PSA_CRYPTO defined, but not all prerequisites"
#endif

#if defined(MBEDTLS_HAVE_INT32) && defined(MBEDTLS_HAVE_INT64)
#error "MBEDTLS_HAVE_INT32 and MBEDTLS_HAVE_INT64 cannot be defined simultaneously"
#endif /* MBEDTLS_HAVE_INT32 && MBEDTLS_HAVE_INT64 */

#if ( defined(MBEDTLS_HAVE_INT32) || defined(MBEDTLS_HAVE_INT64) ) && \
    defined(MBEDTLS_HAVE_ASM)
#error "MBEDTLS_HAVE_INT32/MBEDTLS_HAVE_INT64 and MBEDTLS_HAVE_ASM cannot be defined simultaneously"
#endif /* (MBEDTLS_HAVE_INT32 || MBEDTLS_HAVE_INT64) && MBEDTLS_HAVE_ASM */

/*
 * Avoid warning from -pedantic. This is a convenient place for this
 * workaround since this is included by every single file before the
 * #if defined(MBEDTLS_xxx_C) that results in empty translation units.
 */
typedef int mbedtls_iso_c_forbids_empty_translation_units;

/* *INDENT-ON* */
#endif /* TF_PSA_CRYPTO_CHECK_CONFIG_H */
