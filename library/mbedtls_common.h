/**
 * \file mbedtls_common.h
 *
 * \brief Utility macros for internal use in the library
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_MBEDTLS_COMMON_H
#define MBEDTLS_MBEDTLS_COMMON_H

/* Before including any system header, declare some macros to tell system
 * headers what we expect of them.
 *
 * Do this before including any header from TF-PSA-Crypto, since the
 * convention is first-come-first-served (so that users can
 * override some macros on the command line, and individual users can
 * override some macros before including the common header).
 */
#include "mbedtls_platform_requirements.h"

/* Mbed TLS requires TF-PSA-Crypto internals. */
#include "tf_psa_crypto_common.h"

#endif /* MBEDTLS_MBEDTLS_COMMON_H */
