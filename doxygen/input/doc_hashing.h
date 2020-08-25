/**
 * \file doc_hashing.h
 *
 * \brief Hashing module documentation file.
 */
/*
 *
 *  Copyright The Mbed TLS Contributors
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
 */

/**
 * @addtogroup hashing_module Hashing module
 *
 * The Message Digest (MD) or Hashing module provides one-way hashing
 * functions. Such functions can be used for creating a hash message
 * authentication code (HMAC) when sending a message. Such a HMAC can be used
 * in combination with a private key for authentication, which is a message
 * integrity control.
 *
 * All hash algorithms can be accessed via the generic MD layer (see
 * \c mbedtls_md_setup())
 *
 * The following hashing-algorithms are provided:
 * - MD2, MD4, MD5 128-bit one-way hash functions by Ron Rivest.
 * - SHA-1, SHA-256, SHA-384/512 160-bit or more one-way hash functions by
 *   NIST and NSA.
 *
 * This module provides one-way hashing which can be used for authentication.
 */
