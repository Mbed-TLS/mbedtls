/**
 * \file memory.h
 *
 * \brief Memory allocation layer
 *
 * \deprecated Use the platform layer instead
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
#ifndef POLARSSL_MEMORY_H
#define POLARSSL_MEMORY_H

#if !defined(POLARSSL_CONFIG_FILE)
#include "config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include <stdlib.h>

#include "platform.h"
#include "memory_buffer_alloc.h"

#if ! defined(POLARSSL_DEPRECATED_REMOVED)
#if defined(POLARSSL_DEPRECATED_WARNING)
#define DEPRECATED    __attribute__((deprecated))
#else
#define DEPRECATED
#endif
/**
 * \brief   Set malloc() / free() callback
 *
 * \deprecated Use platform_set_malloc_free instead
 */
int memory_set_own( void * (*malloc_func)( size_t ),
                    void (*free_func)( void * ) ) DEPRECATED;
int memory_set_own( void * (*malloc_func)( size_t ),
                    void (*free_func)( void * ) )
{
    return platform_set_malloc_free( malloc_func, free_func );
}
#undef DEPRECATED
#endif /* POLARSSL_DEPRECATED_REMOVED */


#endif /* memory.h */
