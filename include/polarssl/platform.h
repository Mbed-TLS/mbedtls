/**
 * \file platform.h
 *
 * \brief mbed TLS Platform abstraction layer
 *
 *  Copyright (C) 2006-2014, ARM Limited, All Rights Reserved
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
#ifndef POLARSSL_PLATFORM_H
#define POLARSSL_PLATFORM_H

#if !defined(POLARSSL_CONFIG_FILE)
#include "config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

/* Temporary compatibility hack for to keep MEMORY_C working */
#if defined(POLARSSL_MEMORY_C) && !defined(POLARSSL_PLATFORM_MEMORY)
#define POLARSSL_PLATFORM_MEMORY
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(POLARSSL_PLATFORM_NO_STD_FUNCTIONS)
#include <stdio.h>
#include <stdlib.h>
#if !defined(POLARSSL_PLATFORM_STD_SNPRINTF)
#define POLARSSL_PLATFORM_STD_SNPRINTF   snprintf /**< Default snprintf to use  */
#endif
#if !defined(POLARSSL_PLATFORM_STD_PRINTF)
#define POLARSSL_PLATFORM_STD_PRINTF   printf /**< Default printf to use  */
#endif
#if !defined(POLARSSL_PLATFORM_STD_FPRINTF)
#define POLARSSL_PLATFORM_STD_FPRINTF fprintf /**< Default fprintf to use */
#endif
#if !defined(POLARSSL_PLATFORM_STD_MALLOC)
#define POLARSSL_PLATFORM_STD_MALLOC   malloc /**< Default allocator to use */
#endif
#if !defined(POLARSSL_PLATFORM_STD_FREE)
#define POLARSSL_PLATFORM_STD_FREE       free /**< Default free to use */
#endif
#if !defined(POLARSSL_PLATFORM_STD_EXIT)
#define POLARSSL_PLATFORM_STD_EXIT      exit /**< Default free to use */
#endif
#else /* POLARSSL_PLATFORM_NO_STD_FUNCTIONS */
#if defined(POLARSSL_PLATFORM_STD_MEM_HDR)
#include POLARSSL_PLATFORM_STD_MEM_HDR
#endif
#endif /* POLARSSL_PLATFORM_NO_STD_FUNCTIONS */

/* \} name SECTION: Module settings */

/*
 * The function pointers for malloc and free
 */
#if defined(POLARSSL_PLATFORM_MEMORY)
#if defined(POLARSSL_PLATFORM_FREE_MACRO) && \
    defined(POLARSSL_PLATFORM_MALLOC_MACRO)
#define polarssl_free       POLARSSL_PLATFORM_FREE_MACRO
#define polarssl_malloc     POLARSSL_PLATFORM_MALLOC_MACRO
#else
/* For size_t */
#include <stddef.h>
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
#endif /* POLARSSL_PLATFORM_FREE_MACRO && POLARSSL_PLATFORM_MALLOC_MACRO */
#else /* !POLARSSL_PLATFORM_MEMORY */
#define polarssl_free       free
#define polarssl_malloc     malloc
#endif /* POLARSSL_PLATFORM_MEMORY && !POLARSSL_PLATFORM_{FREE,MALLOC}_MACRO */

/*
 * The function pointers for fprintf
 */
#if defined(POLARSSL_PLATFORM_FPRINTF_ALT)
/* We need FILE * */
#include <stdio.h>
extern int (*polarssl_fprintf)( FILE *stream, const char *format, ... );

/**
 * \brief   Set your own fprintf function pointer
 *
 * \param fprintf_func   the fprintf function implementation
 *
 * \return              0
 */
int platform_set_fprintf( int (*fprintf_func)( FILE *stream, const char *,
                                               ... ) );
#else
#if defined(POLARSSL_PLATFORM_FPRINTF_MACRO)
#define polarssl_fprintf    POLARSSL_PLATFORM_FPRINTF_MACRO
#else
#define polarssl_fprintf    fprintf
#endif /* POLARSSL_PLATFORM_FPRINTF_MACRO */
#endif /* POLARSSL_PLATFORM_FPRINTF_ALT */

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
#else /* !POLARSSL_PLATFORM_PRINTF_ALT */
#if defined(POLARSSL_PLATFORM_PRINTF_MACRO)
#define polarssl_printf     POLARSSL_PLATFORM_PRINTF_MACRO
#else
#define polarssl_printf     printf
#endif /* POLARSSL_PLATFORM_PRINTF_MACRO */
#endif /* POLARSSL_PLATFORM_PRINTF_ALT */

/*
 * The function pointers for snprintf
 */
#if defined(POLARSSL_PLATFORM_SNPRINTF_ALT)
extern int (*polarssl_snprintf)( char * s, size_t n, const char * format, ... );

/**
 * \brief   Set your own snprintf function pointer
 *
 * \param snprintf_func   the snprintf function implementation
 *
 * \return              0
 */
int platform_set_snprintf( int (*snprintf_func)( char * s, size_t n,
                                                 const char * format, ... ) );
#else /* POLARSSL_PLATFORM_SNPRINTF_ALT */
#if defined(POLARSSL_PLATFORM_SNPRINTF_MACRO)
#define polarssl_snprintf   POLARSSL_PLATFORM_SNPRINTF_MACRO
#else
#define polarssl_snprintf   snprintf
#endif /* POLARSSL_PLATFORM_SNPRINTF_MACRO */
#endif /* POLARSSL_PLATFORM_SNPRINTF_ALT */

/*
 * The function pointers for exit
 */
#if defined(POLARSSL_PLATFORM_EXIT_ALT)
extern void (*polarssl_exit)( int status );

/**
 * \brief   Set your own exit function pointer
 *
 * \param exit_func   the exit function implementation
 *
 * \return              0
 */
int platform_set_exit( void (*exit_func)( int status ) );
#else
#if defined(POLARSSL_PLATFORM_EXIT_MACRO)
#define polarssl_exit   POLARSSL_PLATFORM_EXIT_MACRO
#else
#define polarssl_exit   exit
#endif /* POLARSSL_PLATFORM_EXIT_MACRO */
#endif /* POLARSSL_PLATFORM_EXIT_ALT */

#ifdef __cplusplus
}
#endif

#endif /* platform.h */
