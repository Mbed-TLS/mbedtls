/**
 * \file polarssl_printf.h
 *
 * \brief printf relocation layer
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
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
#ifndef POLARSSL_PRINTF_H
#define POLARSSL_PRINTF_H

#include "config.h"

#ifdef POLARSSL_PRINTF

#include <stdio.h>

#define POLARSSL_STDPRINTF  printf  /**< Default printf to use */
#define POLARSSL_STDFPRINTF fprintf /**< Default fprintf to use */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The function pointer for printf and fprintf
 */
extern int ( *polarssl_printf )  ( const char *fmt, ... );
extern int ( *polarssl_fprintf ) ( FILE *file, const char *fmt, ... );

/**
 * \brief   Set your own printf implementation function pointer
 *
 * \param printf_func   the printf function implementation
 * \param fprintf_func  the fprintf function implementation
 *
 * \return              0 if successful
 */
int printf_set_own( int ( *printf_func ) ( const char *fmt, ... ),
                    int ( *fprintf_func ) ( FILE *file, const char *fmt, ... ) );

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_PRINTF */
#endif /* polarssl_printf.h */
