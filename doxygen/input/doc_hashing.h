/**
 * @file
 * Hashing module documentation file.
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
 * @addtogroup hashing_module Hashing module
 *
 * The Hashing module provides one-way hashing functions. Such functions can be
 * used for creating a hash message authentication code (HMAC) when sending a
 * message. Such a HMAC can be used in combination with a private key
 * for authentication, which is a message integrity control.
 *
 * All hash algorithms can be accessed via the generic MD layer (see
 * \c md_setup())
 *
 * The following hashing-algorithms are provided:
 * - MD2, MD4, MD5 128-bit one-way hash functions by Ron Rivest.
 * - SHA-1, SHA-256, SHA-384/512 160-bit or more one-way hash functions by
 *   NIST and NSA.
 *
 * This module provides one-way hashing which can be used for authentication.
 */
