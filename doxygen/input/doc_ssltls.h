/**
 * @file
 * SSL/TLS communication module documentation file.
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
 * @addtogroup ssltls_communication_module SSL/TLS communication module
 *
 * The SSL/TLS communication module provides the means to create an SSL/TLS
 * communication channel.
 *
 * The basic provisions are:
 * - initialise an SSL/TLS context (see \c mbedtls_ssl_init()).
 * - perform an SSL/TLS handshake (see \c mbedtls_ssl_handshake()).
 * - read/write (see \c mbedtls_ssl_read() and \c mbedtls_ssl_write()).
 * - notify a peer that connection is being closed (see \c mbedtls_ssl_close_notify()).
 *
 * Many aspects of such a channel are set through parameters and callback
 * functions:
 * - the endpoint role: client or server.
 * - the authentication mode. Should verification take place.
 * - the Host-to-host communication channel. A TCP/IP module is provided.
 * - the random number generator (RNG).
 * - the ciphers to use for encryption/decryption.
 * - session control functions.
 * - X.509 parameters for certificate-handling and key exchange.
 *
 * This module can be used to create an SSL/TLS server and client and to provide a basic
 * framework to setup and communicate through an SSL/TLS communication channel.\n
 * Note that you need to provide for several aspects yourself as mentioned above.
 */
