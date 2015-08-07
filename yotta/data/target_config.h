/*
 *  Temporary target-specific config.h for entropy collection
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

#if defined(TARGET_LIKE_MBED)
#define MBEDTLS_NO_PLATFORM_ENTROPY
#undef MBEDTLS_HAVE_TIME_DATE
#undef MBEDTLS_FS_IO
#endif

/*
 * WARNING: this is a temporary hack!
 * 2. This should be in a separete yotta module which would be a target
 * dependency of mbedtls (see IOTSSL-313)
 */
#if defined(TARGET_LIKE_CORTEX_M4)
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#endif
