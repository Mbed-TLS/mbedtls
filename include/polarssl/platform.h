/**
 * \file platform.h
 *
 * \brief PolarSSL Platform abstraction layer
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
#ifndef POLARSSL_PLATFORM_H
#define POLARSSL_PLATFORM_H

#include "config.h"

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(POLARSSL_CONFIG_OPTIONS)
#include <stdlib.h>
#define POLARSSL_PLATFORM_STD_PRINTF   printf /**< Default printf to use  */
#define POLARSSL_PLATFORM_STD_FPRINTF fprintf /**< Default fprintf to use */
#define POLARSSL_PLATFORM_STD_MALLOC   malloc /**< Default allocator to use */
#define POLARSSL_PLATFORM_STD_FREE       free /**< Default free to use */
#endif /* POLARSSL_CONFIG_OPTIONS */

/*
 * The function pointers for malloc and free
 */
#if defined(POLARSSL_PLATFORM_MEMORY)
extern void * (*polarssl_malloc)( size_t len );
extern void (*polarssl_free)( void *ptr );

/**
 * \brief   Set your own memory implementation function pointers
 *
 * \param malloc_func   the malloc function implementation
 * \param free_func     the free function implementation
 *
 * \return              0 if successful
 */
int platform_set_malloc_free( void * (*malloc_func)( size_t ),
                              void (*free_func)( void * ) );
#else
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

/*
 * The function pointers for printf
 */
#if defined(POLARSSL_PLATFORM_PRINTF_ALT)
extern int (*polarssl_printf)( const char *format, ... );

/**
 * \brief   Set your own printf function pointer
 *
 * \param printf_func   the printf function implementation
 *
 * \return              0
 */
int platform_set_printf( int (*printf_func)( const char *, ... ) );
#else
#define polarssl_printf     printf
#endif

/*
 * The function pointers for fprintf
 */
#if defined(POLARSSL_PLATFORM_FPRINTF_ALT)
extern int (*polarssl_fprintf)( FILE *stream, const char *format, ... );

int platform_set_fprintf( int (*fprintf_func)( FILE *stream, const char *,
                                               ... ) );
#else
#define polarssl_fprintf    fprintf
#endif

#ifdef __cplusplus
}
#endif

#endif /* platform.h */
