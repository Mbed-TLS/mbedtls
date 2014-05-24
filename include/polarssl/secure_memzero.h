/**
 * \file secure_memzero.h
 *
 * \brief Securely memset memory to zero.
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
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
 */
#ifndef POLARSSL_SECURE_MEMZERO_H
#define POLARSSL_SECURE_MEMZERO_H

#include <string.h>

#if defined(_MSC_VER) && !defined(inline)
#define inline _inline
#else
#if defined(__ARMCC_VERSION) && !defined(inline)
#define inline __inline
#endif /* __ARMCC_VERSION */
#endif /*_MSC_VER */

#ifdef __cplusplus
extern "C" {
#endif

static inline void *secure_memzero(void *v, size_t n)
{
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--)
        *p++ = 0;
    return v;
}

#ifdef __cplusplus
}
#endif

#endif /* secure_memzero.h */
