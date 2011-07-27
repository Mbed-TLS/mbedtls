/**
 * \file config.h
 *
 * \brief Configuration options (set of defines)
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * This set of compile-time options may be used to enable
 * or disable features selectively, and reduce the global
 * memory footprint.
 */
#ifndef POLARSSL_CONFIG_H
#define POLARSSL_CONFIG_H

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

/**
 * \name SECTION: System support
 *
 * This section sets system specific settings.
 * \{
 */

/**
 * \def POLARSSL_HAVE_INT8
 *
 * The system uses 8-bit wide native integers.
 *
 * Uncomment if native integers are 8-bit wide.
#define POLARSSL_HAVE_INT8
 */

/**
 * \def POLARSSL_HAVE_INT16
 *
 * The system uses 16-bit wide native integers.
 *
 * Uncomment if native integers are 16-bit wide.
#define POLARSSL_HAVE_INT16
 */

/**
 * \def POLARSSL_HAVE_LONGLONG
 *
 * The compiler supports the use of long long.
 *
 * Uncomment if the compiler supports long long.
#define POLARSSL_HAVE_LONGLONG
 */

/**
 * \def POLARSSL_HAVE_ASM
 *
 * The compiler has support for asm()
 *
 * Uncomment to enable the use of assembly code.
 *
 * Requires support for asm() in compiler.
 *
 * Used in:
 *      library/timing.c
 *      library/padlock.c
 *      include/polarssl/bn_mul.h
 *
 */
#define POLARSSL_HAVE_ASM

/**
 * \def POLARSSL_HAVE_SSE2
 *
 * CPI supports SSE2 instruction set.
 *
 * Uncomment if the CPU supports SSE2 (IA-32 specific).
 *
#define POLARSSL_HAVE_SSE2
 */
/* \} name */

/**
 * \name SECTION: PolarSSL feature support
 *
 * This section sets support for features that are or are not needed
 * within the modules that are enabled.
 * \{
 */

/**
 * \def POLARSSL_AES_ROM_TABLES
 *
 * Store the AES tables in ROM.
 *
 * Uncomment this macro to store the AES tables in ROM.
 *
#define POLARSSL_AES_ROM_TABLES
 */

/**
 * \def POLARSSL_CIPHER_MODE_CFB
 *
 * Enable Cipher Feedback mode (CFB) for symmetric ciphers.
 */
#define POLARSSL_CIPHER_MODE_CFB

/**
 * \def POLARSSL_CIPHER_MODE_CTR
 *
 * Enable Counter Block Cipher mode (CTR) for symmetric ciphers.
 */
#define POLARSSL_CIPHER_MODE_CTR

/**
 * \def POLARSSL_DEBUG_MSG
 *
 * Requires: POLARSSL_DEBUG_C
 *
 * Enable all SSL/TLS debugging messages.
 */
#define POLARSSL_DEBUG_MSG

/**
 * \def POLARSSL_GENPRIME
 *
 * Requires: POLARSSL_BIGNUM_C, POLARSSL_RSA_C
 *
 * Enable the RSA prime-number generation code.
 */
#define POLARSSL_GENPRIME

/**
 * \def POLARSSL_FS_IO
 *
 * Enable functions that use the filesystem.
 */
#define POLARSSL_FS_IO

/**
 * \def POLARSSL_PKCS1_V21
 *
 * Requires: POLARSSL_MD_C, POLARSSL_RSA_C
 *
 * Enable support for PKCS#1 v2.1 encoding.
 * This enables support for RSAES-OAEP and RSASSA-PSS operations.
 */
#define POLARSSL_PKCS1_V21

/**
 * \def POLARSSL_RSA_NO_CRT
 *
 * Do not use the Chinese Remainder Theorem for the RSA private operation.
 *
 * Uncomment this macro to disable the use of CRT in RSA.
 *
#define POLARSSL_RSA_NO_CRT
 */

/**
 * \def POLARSSL_SELF_TEST
 *
 * Enable the checkup functions (*_self_test).
 */
#define POLARSSL_SELF_TEST

/**
 * \def POLARSSL_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION
 *
 * If set, the X509 parser will not break-off when parsing an X509 certificate
 * and encountering an unknown critical extension.
 *
 * Uncomment to prevent an error.
 *
#define POLARSSL_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION
 */
/* \} name */

/**
 * \name SECTION: PolarSSL modules
 *
 * This section enables or disables entire modules in PolarSSL
 * \{
 */

/**
 * \def POLARSSL_AES_C
 *
 * Enable the AES block cipher.
 *
 * Module:  library/aes.c
 * Caller:  library/ssl_tls.c
 *          library/pem.c
 *
 * This module enables the following ciphersuites:
 *      SSL_RSA_AES_128_SHA
 *      SSL_RSA_AES_256_SHA
 *      SSL_EDH_RSA_AES_256_SHA
 */
#define POLARSSL_AES_C

/**
 * \def POLARSSL_ARC4_C
 *
 * Enable the ARCFOUR stream cipher.
 *
 * Module:  library/arc4.c
 * Caller:  library/ssl_tls.c
 *
 * This module enables the following ciphersuites:
 *      SSL_RSA_RC4_128_MD5
 *      SSL_RSA_RC4_128_SHA
 */
#define POLARSSL_ARC4_C

/**
 * \def POLARSSL_BASE64_C
 *
 * Enable the Base64 module.
 *
 * Module:  library/base64.c
 * Caller:  library/pem.c
 *
 * This module is required for PEM support (required by X.509).
 */
#define POLARSSL_BASE64_C

/**
 * \def POLARSSL_BIGNUM_C
 *
 * Enable the multo-precision integer library.
 *
 * Module:  library/bignum.c
 * Caller:  library/dhm.c
 *          library/rsa.c
 *          library/ssl_tls.c
 *          library/x509parse.c
 *
 * This module is required for RSA and DHM support.
 */
#define POLARSSL_BIGNUM_C

/**
 * \def POLARSSL_CAMELLIA_C
 *
 * Enable the Camellia block cipher.
 *
 * Module:  library/camellia.c
 * Caller:  library/ssl_tls.c
 *
 * This module enabled the following cipher suites:
 *      SSL_RSA_CAMELLIA_128_SHA
 *      SSL_RSA_CAMELLIA_256_SHA
 *      SSL_EDH_RSA_CAMELLIA_256_SHA
 */
#define POLARSSL_CAMELLIA_C

/**
 * \def POLARSSL_CERTS_C
 *
 * Enable the test certificates.
 *
 * Module:  library/certs.c
 * Caller:
 *
 * This module is used for testing (ssl_client/server).
 */
#define POLARSSL_CERTS_C

/**
 * \def POLARSSL_CIPHER_C
 *
 * Enable the generic cipher layer.
 *
 * Module:  library/cipher.c
 * Caller:
 *
 * Uncomment to enable generic cipher wrappers.
 */
#define POLARSSL_CIPHER_C

/**
 * \def POLARSSL_DEBUG_C
 *
 * Enable the debug functions.
 *
 * Module:  library/debug.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *          library/ssl_tls.c
 *
 * This module provides debugging functions.
 */
#define POLARSSL_DEBUG_C

/**
 * \def POLARSSL_DES_C
 *
 * Enable the DES block cipher.
 *
 * Module:  library/des.c
 * Caller:  library/ssl_tls.c
 *
 * This module enables the following ciphersuites:
 *      SSL_RSA_DES_168_SHA
 *      SSL_EDH_RSA_DES_168_SHA
 */
#define POLARSSL_DES_C

/**
 * \def POLARSSL_DHM_C
 *
 * Enable the Diffie-Hellman-Merkle key exchange.
 *
 * Module:  library/dhm.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *
 * This module enables the following ciphersuites:
 *      SSL_EDH_RSA_DES_168_SHA
 *      SSL_EDH_RSA_AES_256_SHA
 *      SSL_EDH_RSA_CAMELLIA_256_SHA
 */
#define POLARSSL_DHM_C

/**
 * \def POLARSSL_ERROR_C
 *
 * Enable error code to error string conversion.
 *
 * Module:  library/error.c
 * Caller:
 *
 * This module enables err_strerror().
 */
#define POLARSSL_ERROR_C

/**
 * \def POLARSSL_HAVEGE_C
 *
 * Enable the HAVEGE random generator.
 *
 * Module:  library/havege.c
 * Caller:
 *
 * Requires: POLARSSL_TIMING_C
 *
 * This module enables the HAVEGE random number generator.
 */
#define POLARSSL_HAVEGE_C

/**
 * \def POLARSSL_MD_C
 *
 * Enable the generic message digest layer.
 *
 * Module:  library/md.c
 * Caller:
 *
 * Uncomment to enable generic message digest wrappers.
 */
#define POLARSSL_MD_C

/**
 * \def POLARSSL_MD2_C
 *
 * Enable the MD2 hash algorithm
 *
 * Module:  library/md2.c
 * Caller:  library/x509parse.c
 *
 * Uncomment to enable support for (rare) MD2-signed X.509 certs.
 *
#define POLARSSL_MD2_C
 */

/**
 * \def POLARSSL_MD4_C
 *
 * Enable the MD4 hash algorithm
 *
 * Module:  library/md4.c
 * Caller:  library/x509parse.c
 *
 * Uncomment to enable support for (rare) MD4-signed X.509 certs.
 *
#define POLARSSL_MD4_C
 */

/**
 * \def POLARSSL_MD5_C
 *
 * Enable the MD5 hash algorithm
 *
 * Module:  library/md5.c
 * Caller:  library/ssl_tls.c
 *          library/x509parse.c
 *
 * This module is required for SSL/TLS and X.509.
 */
#define POLARSSL_MD5_C

/**
 * \def POLARSSL_NET_C
 *
 * Enable the TCP/IP networking routines.
 *
 * Module:  library/net.c
 * Caller:
 *
 * This module provides TCP/IP networking routines.
 */
#define POLARSSL_NET_C

/**
 * \def POLARSSL_PADLOCK_C
 *
 * Enable VIA Padlock support on x86.
 *
 * Module:  library/padlock.c
 * Caller:  library/aes.c
 *
 * This modules adds support for the VIA PadLock on x86.
 */
#define POLARSSL_PADLOCK_C

/**
 * \def POLARSSL_PEM_C
 *
 * Enable PEM decoding
 *
 * Module:  library/pem.c
 * Caller:  library/x509parse.c
 *
 * Requires: POLARSSL_BASE64_C
 *
 * This modules adds support for decoding PEM files.
 */
#define POLARSSL_PEM_C

/**
 * \def POLARSSL_PKCS11_C
 *
 * Enable support for PKCS#11 smartcard support.
 *
 * Module:  library/ssl_srv.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *
 * Requires: POLARSSL_SSL_TLS_C
 *
 * This module is required for SSL/TLS PKCS #11 smartcard support.
 * Requires the presence of the PKCS#11 helper library (libpkcs11-helper)
#define POLARSSL_PKCS11_C
 */

/**
 * \def POLARSSL_RSA_C
 *
 * Enable the RSA public-key cryptosystem.
 *
 * Module:  library/rsa.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *          library/ssl_tls.c
 *          library/x509.c
 *
 * Requires: POLARSSL_BIGNUM_C
 *
 * This module is required for SSL/TLS and MD5-signed certificates.
 */
#define POLARSSL_RSA_C

/**
 * \def POLARSSL_SHA1_C
 *
 * Enable the SHA1 cryptographic hash algorithm.
 *
 * Module:  library/sha1.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *          library/ssl_tls.c
 *          library/x509parse.c
 *
 * This module is required for SSL/TLS and SHA1-signed certificates.
 */
#define POLARSSL_SHA1_C

/**
 * \def POLARSSL_SHA2_C
 *
 * Enable the SHA-224 and SHA-256 cryptographic hash algorithms.
 *
 * Module:  library/sha2.c
 * Caller:  library/md_wrap.c
 *          library/x509parse.c
 *
 * This module adds support for SHA-224 and SHA-256.
 */
#define POLARSSL_SHA2_C

/**
 * \def POLARSSL_SHA4_C
 *
 * Enable the SHA-384 and SHA-512 cryptographic hash algorithms.
 *
 * Module:  library/sha4.c
 * Caller:  library/md_wrap.c
 *          library/x509parse.c
 *
 * This module adds support for SHA-384 and SHA-512.
 */
#define POLARSSL_SHA4_C

/**
 * \def POLARSSL_SSL_CLI_C
 *
 * Enable the SSL/TLS client code.
 *
 * Module:  library/ssl_cli.c
 * Caller:
 *
 * Requires: POLARSSL_SSL_TLS_C
 *
 * This module is required for SSL/TLS client support.
 */
#define POLARSSL_SSL_CLI_C

/*
 * \def POLARSSL_SSL_SRV_C
 *
 * Enable the SSL/TLS server code.
 *
 * Module:  library/ssl_srv.c
 * Caller:
 *
 * Requires: POLARSSL_SSL_TLS_C
 *
 * This module is required for SSL/TLS server support.
 */
#define POLARSSL_SSL_SRV_C

/**
 * \def POLARSSL_SSL_TLS_C
 *
 * Enable the generic SSL/TLS code.
 *
 * Module:  library/ssl_tls.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *
 * Requires: POLARSSL_MD5_C, POLARSSL_SHA1_C, POLARSSL_X509_PARSE_C
 *
 * This module is required for SSL/TLS.
 */
#define POLARSSL_SSL_TLS_C

/**
 * \def POLARSSL_TIMING_C
 *
 * Enable the portable timing interface.
 *
 * Module:  library/timing.c
 * Caller:  library/havege.c
 *
 * This module is used by the HAVEGE random number generator.
 */
#define POLARSSL_TIMING_C

/**
 * \def POLARSSL_VERSION_C
 *
 * Enable run-time version information.
 *
 * Module:  library/version.c
 *
 * This module provides run-time version information.
 */
#define POLARSSL_VERSION_C

/**
 * \def POLARSSL_X509_PARSE_C
 *
 * Enable X.509 certificate parsing.
 *
 * Module:  library/x509parse.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *          library/ssl_tls.c
 *
 * Requires: POLARSSL_BIGNUM_C, POLARSSL_RSA_C
 *
 * This module is required for X.509 certificate parsing.
 */
#define POLARSSL_X509_PARSE_C

/**
 * \def POLARSSL_XTEA_C
 *
 * Enable the XTEA block cipher.
 *
 * Module:  library/xtea.c
 * Caller:
 */
#define POLARSSL_XTEA_C
/* \} name */

#endif /* config.h */
