/*
 *  Test the debug facility in SSL unit tests.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/* Not needed directly by this program, but needed by internal headers
 * included by test helper headers. */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <mbedtls/build_info.h>
#include <mbedtls/platform.h>

#if !defined(MBEDTLS_DEBUG_C) ||                         \
    !defined(MBEDTLS_SSL_CLI_C) ||                       \
    !defined(MBEDTLS_SSL_SRV_C) ||                       \
    !defined(MBEDTLS_SSL_PROTO_TLS1_2) ||                \
    !defined(PSA_WANT_ALG_ECDSA) ||                      \
    !defined(PSA_WANT_ALG_ECDH) ||                       \
    !defined(PSA_WANT_ECC_SECP_R1_256) ||                \
    !defined(PSA_WANT_ALG_SHA_256) ||                    \
    !defined(PSA_WANT_ALG_CHACHA20_POLY1305) ||          \
    !defined(MBEDTLS_PSA_CRYPTO_C)
int main(void)
{
    mbedtls_printf("This program is unusable in this configuration.\n");
    mbedtls_exit(0);
}
#else

#include <stdlib.h>
#include <mbedtls/debug.h>
#include <test/ssl_helpers.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        mbedtls_printf("Usage: ssl_unit_test_debug THRESHOLD\n");
        mbedtls_exit(2);
    }
    int threshold = atoi(argv[1]);

    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);
    options.client_min_version = MBEDTLS_SSL_VERSION_TLS1_2;
    options.client_max_version = MBEDTLS_SSL_VERSION_TLS1_2;
    options.expected_negotiated_version = MBEDTLS_SSL_VERSION_TLS1_2;

    if (threshold >= 0) {
        mbedtls_test_ssl_debug_stdout_threshold = threshold;
    }

    mbedtls_test_ssl_perform_handshake(&options);

    mbedtls_test_free_handshake_options(&options);
    mbedtls_exit(0);
}

#endif /* configuration allows running this program */
