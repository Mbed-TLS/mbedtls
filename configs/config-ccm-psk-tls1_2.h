/*
 * Minimal configuration for TLS 1.2 with PSK and AES-CCM ciphersuites
 * Distinguishing features:
 * - no bignum, no PK, no X509
 * - fully modern and secure (provided the pre-shared keys have high entropy)
 * - very low record overhead if using the CCM-8 suites
 * - optimized for low RAM usage
 *
 * See README.txt for usage instructions.
 */
#ifndef POLARSSL_CONFIG_H
#define POLARSSL_CONFIG_H

/* System support */
#define POLARSSL_HAVE_IPV6
#define POLARSSL_HAVE_TIME

/* PolarSSL feature support */
#define POLARSSL_KEY_EXCHANGE_PSK_ENABLED
#define POLARSSL_SSL_PROTO_TLS1_2

/* PolarSSL modules */
#define POLARSSL_AES_C
#define POLARSSL_CCM_C
#define POLARSSL_CIPHER_C
#define POLARSSL_CTR_DRBG_C
#define POLARSSL_ENTROPY_C
#define POLARSSL_MD_C
#define POLARSSL_NET_C
#define POLARSSL_SHA256_C
#define POLARSSL_SSL_CLI_C
#define POLARSSL_SSL_SRV_C
#define POLARSSL_SSL_TLS_C

/* Save RAM at the expense of ROM */
#define POLARSSL_AES_ROM_TABLES

/*
 * You should adjust this to the exact number of sources you're using: default
 * is the "platform_entrpy_poll" source, but you may want to add other ones
 */
#define ENTROPY_MAX_SOURCES 1

/*
 * Save RAM at the expense of interoperability: do this only if you control
 * both ends of the connection!  (See coments in "polarssl/ssl.h".)
 */
#define SSL_MAX_CONTENT_LEN             512

#include "check_config.h"

#endif /* POLARSSL_CONFIG_H */
