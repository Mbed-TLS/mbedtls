/**
 * \file platform.h
 *
 * \brief mbed TLS Platform abstraction layer
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_PLATFORM_H
#define MBEDTLS_PLATFORM_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
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

#if !defined(MBEDTLS_PLATFORM_NO_STD_FUNCTIONS)
#include <stdio.h>
#include <stdlib.h>
#if !defined(MBEDTLS_PLATFORM_STD_SNPRINTF)
#define MBEDTLS_PLATFORM_STD_SNPRINTF   snprintf /**< Default snprintf to use  */
#endif
#if !defined(MBEDTLS_PLATFORM_STD_PRINTF)
#define MBEDTLS_PLATFORM_STD_PRINTF   printf /**< Default printf to use  */
#endif
#if !defined(MBEDTLS_PLATFORM_STD_FPRINTF)
#define MBEDTLS_PLATFORM_STD_FPRINTF fprintf /**< Default fprintf to use */
#endif
#if !defined(MBEDTLS_PLATFORM_STD_MALLOC)
#define MBEDTLS_PLATFORM_STD_MALLOC   malloc /**< Default allocator to use */
#endif
#if !defined(MBEDTLS_PLATFORM_STD_FREE)
#define MBEDTLS_PLATFORM_STD_FREE       free /**< Default free to use */
#endif
#if !defined(MBEDTLS_PLATFORM_STD_EXIT)
#define MBEDTLS_PLATFORM_STD_EXIT      exit /**< Default free to use */
#endif
#else /* MBEDTLS_PLATFORM_NO_STD_FUNCTIONS */
#if defined(MBEDTLS_PLATFORM_STD_MEM_HDR)
#include MBEDTLS_PLATFORM_STD_MEM_HDR
#endif
#endif /* MBEDTLS_PLATFORM_NO_STD_FUNCTIONS */

/* \} name SECTION: Module settings */

/*
 * The function pointers for malloc and free
 */
#if defined(MBEDTLS_PLATFORM_MEMORY)
#if defined(MBEDTLS_PLATFORM_FREE_MACRO) && \
    defined(MBEDTLS_PLATFORM_MALLOC_MACRO)
#define mbedtls_free       MBEDTLS_PLATFORM_FREE_MACRO
#define mbedtls_malloc     MBEDTLS_PLATFORM_MALLOC_MACRO
#else
extern void * (*mbedtls_malloc)( size_t len );
extern void (*mbedtls_free)( void *ptr );

/**
 * \brief   Set your own memory implementation function pointers
 *
 * \param malloc_func   the malloc function implementation
 * \param free_func     the free function implementation
 *
 * \return              0 if successful
 */
int mbedtls_platform_set_malloc_free( void * (*malloc_func)( size_t ),
                              void (*free_func)( void * ) );
#endif /* MBEDTLS_PLATFORM_FREE_MACRO && MBEDTLS_PLATFORM_MALLOC_MACRO */
#else /* !MBEDTLS_PLATFORM_MEMORY */
#define mbedtls_free       free
#define mbedtls_malloc     malloc
#endif /* MBEDTLS_PLATFORM_MEMORY && !MBEDTLS_PLATFORM_{FREE,MALLOC}_MACRO */

/*
 * The function pointers for fprintf
 */
#if defined(MBEDTLS_PLATFORM_FPRINTF_ALT)
extern int (*mbedtls_fprintf)( FILE *stream, const char *format, ... );

/**
 * \brief   Set your own fprintf function pointer
 *
 * \param fprintf_func   the fprintf function implementation
 *
 * \return              0
 */
int mbedtls_platform_set_fprintf( int (*fprintf_func)( FILE *stream, const char *,
                                               ... ) );
#else
#if defined(MBEDTLS_PLATFORM_FPRINTF_MACRO)
#define mbedtls_fprintf    MBEDTLS_PLATFORM_FPRINTF_MACRO
#else
#define mbedtls_fprintf    fprintf
#endif /* MBEDTLS_PLATFORM_FPRINTF_MACRO */
#endif /* MBEDTLS_PLATFORM_FPRINTF_ALT */

/*
 * The function pointers for printf
 */
#if defined(MBEDTLS_PLATFORM_PRINTF_ALT)
extern int (*mbedtls_printf)( const char *format, ... );

/**
 * \brief   Set your own printf function pointer
 *
 * \param printf_func   the printf function implementation
 *
 * \return              0
 */
int mbedtls_platform_set_printf( int (*printf_func)( const char *, ... ) );
#else /* !MBEDTLS_PLATFORM_PRINTF_ALT */
#if defined(MBEDTLS_PLATFORM_PRINTF_MACRO)
#define mbedtls_printf     MBEDTLS_PLATFORM_PRINTF_MACRO
#else
#define mbedtls_printf     printf
#endif /* MBEDTLS_PLATFORM_PRINTF_MACRO */
#endif /* MBEDTLS_PLATFORM_PRINTF_ALT */

/*
 * The function pointers for snprintf
 */
#if defined(MBEDTLS_PLATFORM_SNPRINTF_ALT)
extern int (*mbedtls_snprintf)( char * s, size_t n, const char * format, ... );

/**
 * \brief   Set your own snprintf function pointer
 *
 * \param snprintf_func   the snprintf function implementation
 *
 * \return              0
 */
int mbedtls_platform_set_snprintf( int (*snprintf_func)( char * s, size_t n,
                                                 const char * format, ... ) );
#else /* MBEDTLS_PLATFORM_SNPRINTF_ALT */
#if defined(MBEDTLS_PLATFORM_SNPRINTF_MACRO)
#define mbedtls_snprintf   MBEDTLS_PLATFORM_SNPRINTF_MACRO
#else
#define mbedtls_snprintf   snprintf
#endif /* MBEDTLS_PLATFORM_SNPRINTF_MACRO */
#endif /* MBEDTLS_PLATFORM_SNPRINTF_ALT */

/*
 * The function pointers for exit
 */
#if defined(MBEDTLS_PLATFORM_EXIT_ALT)
extern void (*mbedtls_exit)( int status );

/**
 * \brief   Set your own exit function pointer
 *
 * \param exit_func   the exit function implementation
 *
 * \return              0
 */
int mbedtls_platform_set_exit( void (*exit_func)( int status ) );
#else
#if defined(MBEDTLS_PLATFORM_EXIT_MACRO)
#define mbedtls_exit   MBEDTLS_PLATFORM_EXIT_MACRO
#else
#define mbedtls_exit   exit
#endif /* MBEDTLS_PLATFORM_EXIT_MACRO */
#endif /* MBEDTLS_PLATFORM_EXIT_ALT */

#ifdef __cplusplus
}
#endif

#endif /* platform.h */
