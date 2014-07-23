/**
 * \file ssl_cookie.h
 *
 * \brief DTLS cookie callbacks implementation
 *
 *  Copyright (C) 2014, Brainspark B.V.
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
#ifndef POLARSSL_SSL_COOKIE_H
#define POLARSSL_SSL_COOKIE_H

#include "ssl.h"

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */
#ifndef POLARSSL_SSL_COOKIE_TIMEOUT
#define POLARSSL_SSL_COOKIE_TIMEOUT     60 /**< Default expiration delay of DTLS cookies, in seconds if HAVE_TIME, or in number of cookies issued */
#endif

/* \} name SECTION: Module settings */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Context for the default cookie functions.
 */
typedef struct
{
    md_context_t    hmac_ctx;   /*!< context for the HMAC portion   */
#if !defined(POLARSSL_HAVE_TIME)
    unsigned long   serial;     /*!< serial number for expiration   */
#endif
    unsigned long   timeout;    /*!< timeout delay, in seconds if HAVE_TIME,
                                     or in number of tickets issued */

} ssl_cookie_ctx;

/**
 * \brief          Initialize cookie context
 */
void ssl_cookie_init( ssl_cookie_ctx *ctx );

/**
 * \brief          Setup cookie context (generate keys)
 */
int ssl_cookie_setup( ssl_cookie_ctx *ctx,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

/**
 * \brief          Set expiration delay for cookies
 *                 (Default POLARSSL_SSL_COOKIE_TIMEOUT)
 *
 * \param ctx      Cookie contex
 * \param delay    Delay, in seconds if HAVE_TIME, or in number of cookies
 *                 issued in the meantime.
 *                 0 to disable expiration (NOT recommended)
 */
void ssl_cookie_set_timeout( ssl_cookie_ctx *ctx, unsigned long delay );

/**
 * \brief          Free cookie context
 */
void ssl_cookie_free( ssl_cookie_ctx *ctx );

/**
 * \brief          Generate cookie, see \c ssl_cookie_write_t
 */
ssl_cookie_write_t ssl_cookie_write;

/**
 * \brief          Verify cookie, see \c ssl_cookie_write_t
 */
ssl_cookie_check_t ssl_cookie_check;

#ifdef __cplusplus
}
#endif

#endif /* ssl_cookie.h */
