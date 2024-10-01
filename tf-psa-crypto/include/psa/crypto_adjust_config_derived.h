/**
 * \file psa/crypto_adjust_config_derived.h
 * \brief Adjust PSA configuration by defining internal symbols
 *
 * This is an internal header. Do not include it directly.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_ADJUST_CONFIG_DERIVED_H
#define PSA_CRYPTO_ADJUST_CONFIG_DERIVED_H

#if !defined(MBEDTLS_CONFIG_FILES_READ)
#error "Do not include psa/crypto_adjust_*.h manually! This can lead to problems, " \
    "up to and including runtime errors such as buffer overflows. " \
    "If you're trying to fix a complaint from check_config.h, just remove " \
    "it from your configuration file: since Mbed TLS 3.0, it is included " \
    "automatically at the right point."
#endif /* */

#if defined(PSA_WANT_ALG_ECDSA) || defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
#define PSA_HAVE_ALG_SOME_ECDSA
#endif

#if defined(PSA_HAVE_ALG_SOME_ECDSA) && defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
#define PSA_HAVE_ALG_ECDSA_SIGN
#endif

#if defined(PSA_HAVE_ALG_SOME_ECDSA) && defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
#define PSA_HAVE_ALG_ECDSA_VERIFY
#endif

#if defined(PSA_WANT_ALG_JPAKE)
#define PSA_WANT_ALG_SOME_PAKE 1
#endif

#endif /* PSA_CRYPTO_ADJUST_CONFIG_DERIVED_H */
