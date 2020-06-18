/**
 * \file doc_x509.h
 *
 * \brief X.509 module documentation file.
 */
/*
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 *  This file is provided under the Apache License 2.0, or the
 *  GNU General Public License v2.0 or later.
 *
 *  **********
 *  Apache License 2.0:
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
 *
 *  **********
 *
 *  **********
 *  GNU General Public License v2.0 or later:
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
 *  **********
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/**
 * @addtogroup x509_module X.509 module
 *
 * The X.509 module provides X.509 support for reading, writing and verification
 * of certificates.
 * In summary:
 *   - X.509 certificate (CRT) reading (see \c mbedtls_x509_crt_parse(),
 *     \c mbedtls_x509_crt_parse_der(), \c mbedtls_x509_crt_parse_file()).
 *   - X.509 certificate revocation list (CRL) reading (see
 *     \c mbedtls_x509_crl_parse(), \c mbedtls_x509_crl_parse_der(),
 *     and \c mbedtls_x509_crl_parse_file()).
 *   - X.509 certificate signature verification (see \c
 *     mbedtls_x509_crt_verify() and \c mbedtls_x509_crt_verify_with_profile().
 *   - X.509 certificate writing and certificate request writing (see
 *     \c mbedtls_x509write_crt_der() and \c mbedtls_x509write_csr_der()).
 *
 * This module can be used to build a certificate authority (CA) chain and
 * verify its signature. It is also used to generate Certificate Signing
 * Requests and X.509 certificates just as a CA would do.
 */
