/*
 *  Debugging routines
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_DEBUG_C)

#include "mbedtls/debug.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#if defined(_MSC_VER) && !defined(EFIX64) && !defined(EFI32)
#if !defined  snprintf
#define  snprintf  _snprintf
#endif

#if !defined vsnprintf
#define vsnprintf _vsnprintf
#endif
#endif /* _MSC_VER */

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_snprintf snprintf
#endif

static int debug_log_mode = MBEDTLS_DEBUG_DFL_MODE;
static int debug_threshold = 0;

void mbedtls_debug_set_log_mode( int log_mode )
{
    debug_log_mode = log_mode;
}

void mbedtls_debug_set_threshold( int threshold )
{
    debug_threshold = threshold;
}

char *mbedtls_debug_fmt( const char *format, ... )
{
    va_list argp;
    static char str[512];
    int maxlen = sizeof( str ) - 1;

    va_start( argp, format );
    vsnprintf( str, maxlen, format, argp );
    va_end( argp );

    str[maxlen] = '\0';
    return( str );
}

void mbedtls_debug_print_msg( const mbedtls_ssl_context *ssl, int level,
                      const char *file, int line, const char *text )
{
    char str[512];
    int maxlen = sizeof( str ) - 1;

    if( ssl->conf == NULL || ssl->conf->f_dbg == NULL || level > debug_threshold )
        return;

    if( debug_log_mode == MBEDTLS_DEBUG_LOG_RAW )
    {
        ssl->conf->f_dbg( ssl->conf->p_dbg, level, text );
        return;
    }

    mbedtls_snprintf( str, maxlen, "%s(%04d): %s\n", file, line, text );
    str[maxlen] = '\0';
    ssl->conf->f_dbg( ssl->conf->p_dbg, level, str );
}

void mbedtls_debug_print_ret( const mbedtls_ssl_context *ssl, int level,
                      const char *file, int line,
                      const char *text, int ret )
{
    char str[512];
    int maxlen = sizeof( str ) - 1;
    size_t idx = 0;

    if( ssl->conf == NULL || ssl->conf->f_dbg == NULL || level > debug_threshold )
        return;

    /*
     * With non-blocking I/O and examples that just retry immediately,
     * the logs would be quickly flooded with WANT_READ, so ignore that.
     * Don't ignore WANT_WRITE however, since is is usually rare.
     */
    if( ret == MBEDTLS_ERR_SSL_WANT_READ )
        return;

    if( debug_log_mode == MBEDTLS_DEBUG_LOG_FULL )
        idx = mbedtls_snprintf( str, maxlen, "%s(%04d): ", file, line );

    mbedtls_snprintf( str + idx, maxlen - idx, "%s() returned %d (-0x%04x)\n",
              text, ret, -ret );

    str[maxlen] = '\0';
    ssl->conf->f_dbg( ssl->conf->p_dbg, level, str );
}

void mbedtls_debug_print_buf( const mbedtls_ssl_context *ssl, int level,
                      const char *file, int line, const char *text,
                      const unsigned char *buf, size_t len )
{
    char str[512];
    char txt[17];
    size_t i, maxlen = sizeof( str ) - 1, idx = 0;

    if( ssl->conf == NULL || ssl->conf->f_dbg == NULL || level > debug_threshold )
        return;

    if( debug_log_mode == MBEDTLS_DEBUG_LOG_FULL )
        idx = mbedtls_snprintf( str, maxlen, "%s(%04d): ", file, line );

    mbedtls_snprintf( str + idx, maxlen - idx, "dumping '%s' (%u bytes)\n",
              text, (unsigned int) len );

    str[maxlen] = '\0';
    ssl->conf->f_dbg( ssl->conf->p_dbg, level, str );

    idx = 0;
    memset( txt, 0, sizeof( txt ) );
    for( i = 0; i < len; i++ )
    {
        if( i >= 4096 )
            break;

        if( i % 16 == 0 )
        {
            if( i > 0 )
            {
                mbedtls_snprintf( str + idx, maxlen - idx, "  %s\n", txt );
                ssl->conf->f_dbg( ssl->conf->p_dbg, level, str );

                idx = 0;
                memset( txt, 0, sizeof( txt ) );
            }

            if( debug_log_mode == MBEDTLS_DEBUG_LOG_FULL )
                idx = mbedtls_snprintf( str, maxlen, "%s(%04d): ", file, line );

            idx += mbedtls_snprintf( str + idx, maxlen - idx, "%04x: ",
                             (unsigned int) i );

        }

        idx += mbedtls_snprintf( str + idx, maxlen - idx, " %02x",
                         (unsigned int) buf[i] );
        txt[i % 16] = ( buf[i] > 31 && buf[i] < 127 ) ? buf[i] : '.' ;
    }

    if( len > 0 )
    {
        for( /* i = i */; i % 16 != 0; i++ )
            idx += mbedtls_snprintf( str + idx, maxlen - idx, "   " );

        mbedtls_snprintf( str + idx, maxlen - idx, "  %s\n", txt );
        ssl->conf->f_dbg( ssl->conf->p_dbg, level, str );
    }
}

#if defined(MBEDTLS_ECP_C)
void mbedtls_debug_print_ecp( const mbedtls_ssl_context *ssl, int level,
                      const char *file, int line,
                      const char *text, const mbedtls_ecp_point *X )
{
    char str[512];
    int maxlen = sizeof( str ) - 1;

    if( ssl->conf == NULL || ssl->conf->f_dbg == NULL || level > debug_threshold )
        return;

    mbedtls_snprintf( str, maxlen, "%s(X)", text );
    str[maxlen] = '\0';
    mbedtls_debug_print_mpi( ssl, level, file, line, str, &X->X );

    mbedtls_snprintf( str, maxlen, "%s(Y)", text );
    str[maxlen] = '\0';
    mbedtls_debug_print_mpi( ssl, level, file, line, str, &X->Y );
}
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_BIGNUM_C)
void mbedtls_debug_print_mpi( const mbedtls_ssl_context *ssl, int level,
                      const char *file, int line,
                      const char *text, const mbedtls_mpi *X )
{
    char str[512];
    int j, k, maxlen = sizeof( str ) - 1, zeros = 1;
    size_t i, n, idx = 0;

    if( ssl->conf == NULL || ssl->conf->f_dbg == NULL || X == NULL || level > debug_threshold )
        return;

    for( n = X->n - 1; n > 0; n-- )
        if( X->p[n] != 0 )
            break;

    for( j = ( sizeof(mbedtls_mpi_uint) << 3 ) - 1; j >= 0; j-- )
        if( ( ( X->p[n] >> j ) & 1 ) != 0 )
            break;

    if( debug_log_mode == MBEDTLS_DEBUG_LOG_FULL )
        idx = mbedtls_snprintf( str, maxlen, "%s(%04d): ", file, line );

    mbedtls_snprintf( str + idx, maxlen - idx, "value of '%s' (%d bits) is:\n",
              text, (int) ( ( n * ( sizeof(mbedtls_mpi_uint) << 3 ) ) + j + 1 ) );

    str[maxlen] = '\0';
    ssl->conf->f_dbg( ssl->conf->p_dbg, level, str );

    idx = 0;
    for( i = n + 1, j = 0; i > 0; i-- )
    {
        if( zeros && X->p[i - 1] == 0 )
            continue;

        for( k = sizeof( mbedtls_mpi_uint ) - 1; k >= 0; k-- )
        {
            if( zeros && ( ( X->p[i - 1] >> ( k << 3 ) ) & 0xFF ) == 0 )
                continue;
            else
                zeros = 0;

            if( j % 16 == 0 )
            {
                if( j > 0 )
                {
                    mbedtls_snprintf( str + idx, maxlen - idx, "\n" );
                    ssl->conf->f_dbg( ssl->conf->p_dbg, level, str );
                    idx = 0;
                }

                if( debug_log_mode == MBEDTLS_DEBUG_LOG_FULL )
                    idx = mbedtls_snprintf( str, maxlen, "%s(%04d): ", file, line );
            }

            idx += mbedtls_snprintf( str + idx, maxlen - idx, " %02x", (unsigned int)
                             ( X->p[i - 1] >> ( k << 3 ) ) & 0xFF );

            j++;
        }

    }

    if( zeros == 1 )
    {
        if( debug_log_mode == MBEDTLS_DEBUG_LOG_FULL )
        {
            idx = mbedtls_snprintf( str, maxlen, "%s(%04d): ", file, line );

        }
        idx += mbedtls_snprintf( str + idx, maxlen - idx, " 00" );
    }

    mbedtls_snprintf( str + idx, maxlen - idx, "\n" );
    ssl->conf->f_dbg( ssl->conf->p_dbg, level, str );
}
#endif /* MBEDTLS_BIGNUM_C */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
static void debug_print_pk( const mbedtls_ssl_context *ssl, int level,
                            const char *file, int line,
                            const char *text, const mbedtls_pk_context *pk )
{
    size_t i;
    mbedtls_pk_debug_item items[MBEDTLS_PK_DEBUG_MAX_ITEMS];
    char name[16];

    memset( items, 0, sizeof( items ) );

    if( mbedtls_pk_debug( pk, items ) != 0 )
    {
        mbedtls_debug_print_msg( ssl, level, file, line, "invalid PK context" );
        return;
    }

    for( i = 0; i < MBEDTLS_PK_DEBUG_MAX_ITEMS; i++ )
    {
        if( items[i].type == MBEDTLS_PK_DEBUG_NONE )
            return;

        mbedtls_snprintf( name, sizeof( name ), "%s%s", text, items[i].name );
        name[sizeof( name ) - 1] = '\0';

        if( items[i].type == MBEDTLS_PK_DEBUG_MPI )
            mbedtls_debug_print_mpi( ssl, level, file, line, name, items[i].value );
        else
#if defined(MBEDTLS_ECP_C)
        if( items[i].type == MBEDTLS_PK_DEBUG_ECP )
            mbedtls_debug_print_ecp( ssl, level, file, line, name, items[i].value );
        else
#endif
            mbedtls_debug_print_msg( ssl, level, file, line, "should not happen" );
    }
}

void mbedtls_debug_print_crt( const mbedtls_ssl_context *ssl, int level,
                      const char *file, int line,
                      const char *text, const mbedtls_x509_crt *crt )
{
    char str[1024], prefix[64];
    int i = 0, maxlen = sizeof( prefix ) - 1, idx = 0;

    if( ssl->conf == NULL || ssl->conf->f_dbg == NULL || crt == NULL || level > debug_threshold )
        return;

    if( debug_log_mode == MBEDTLS_DEBUG_LOG_FULL )
    {
        mbedtls_snprintf( prefix, maxlen, "%s(%04d): ", file, line );
        prefix[maxlen] = '\0';
    }
    else
        prefix[0] = '\0';

    maxlen = sizeof( str ) - 1;

    while( crt != NULL )
    {
        char buf[1024];
        mbedtls_x509_crt_info( buf, sizeof( buf ) - 1, prefix, crt );

        if( debug_log_mode == MBEDTLS_DEBUG_LOG_FULL )
            idx = mbedtls_snprintf( str, maxlen, "%s(%04d): ", file, line );

        mbedtls_snprintf( str + idx, maxlen - idx, "%s #%d:\n%s",
                  text, ++i, buf );

        str[maxlen] = '\0';
        ssl->conf->f_dbg( ssl->conf->p_dbg, level, str );

        debug_print_pk( ssl, level, file, line, "crt->", &crt->pk );

        crt = crt->next;
    }
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#endif /* MBEDTLS_DEBUG_C */
