/**
 * @file
 * X.509 module documentation file.
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
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
 */

/**
 * @addtogroup x509_module X.509 module
 *
 * The X.509 module provides X.509 support which includes:
 * - X.509 certificate (CRT) reading (see \c x509parse_crt() and
 *   \c x509parse_crtfile()).
 * - X.509 certificate revocation list (CRL) reading (see \c x509parse_crl()
 *   and\c x509parse_crlfile()).
 * - X.509 (RSA and ECC) private key reading (see \c x509parse_key() and
 *   \c x509parse_keyfile()).
 * - X.509 certificate signature verification (see \c x509parse_verify())
 * - X.509 certificate writing and certificate request writing (see
 *   \c mbedtls_x509write_crt_der() and \c mbedtls_x509write_csr_der()).
 *
 * This module can be used to build a certificate authority (CA) chain and
 * verify its signature. It is also used to generate Certificate Signing
 * Requests and X509 certificates just as a CA would do.
 */
