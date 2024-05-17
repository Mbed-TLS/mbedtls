/**
 * \file psa/crypto_adjust_config_dependencies.h
 * \brief Adjust PSA configuration by resolving some dependencies.
 *
 * See docs/proposed/psa-conditional-inclusion-c.md.
 * If a cryptographic mechanism A depends on a cryptographic mechanism B and
 * A is enabled then enable B.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_ADJUST_CONFIG_DEPENDENCIES_H
#define PSA_CRYPTO_ADJUST_CONFIG_DEPENDENCIES_H

#if (defined(PSA_WANT_ALG_TLS12_PRF) && \
    !defined(MBEDTLS_PSA_ACCEL_ALG_TLS12_PRF)) || \
    (defined(PSA_WANT_ALG_TLS12_PSK_TO_MS) && \
    !defined(MBEDTLS_PSA_ACCEL_ALG_TLS12_PSK_TO_MS)) || \
    (defined(PSA_WANT_ALG_HKDF) && \
    !defined(MBEDTLS_PSA_ACCEL_ALG_HKDF)) || \
    (defined(PSA_WANT_ALG_HKDF_EXTRACT) && \
    !defined(MBEDTLS_PSA_ACCEL_ALG_HKDF_EXTRACT)) || \
    (defined(PSA_WANT_ALG_HKDF_EXPAND) && \
    !defined(MBEDTLS_PSA_ACCEL_ALG_HKDF_EXPAND)) || \
    (defined(PSA_WANT_ALG_PBKDF2_HMAC) && \
    !defined(MBEDTLS_PSA_ACCEL_ALG_PBKDF2_HMAC))
#define PSA_WANT_ALG_HMAC 1
#define PSA_WANT_KEY_TYPE_HMAC 1
#endif

#if (defined(PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128) && \
    !defined(MBEDTLS_PSA_ACCEL_ALG_PBKDF2_AES_CMAC_PRF_128))
#define PSA_WANT_KEY_TYPE_AES 1
#define PSA_WANT_ALG_CMAC 1
#endif

#endif /* PSA_CRYPTO_ADJUST_CONFIG_DEPENDENCIES_H */
