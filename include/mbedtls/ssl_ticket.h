/**
 * \file ssl_ticket.h
 *
 * \brief TLS server ticket callbacks implementation
 *
 *  Copyright (C) 2015, ARM Limited, All Rights Reserved
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
#ifndef MBEDTLS_SSL_TICKET_H
#define MBEDTLS_SSL_TICKET_H

#include "ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Temporary, WIP */
int mbedtls_ssl_ticket_write( void *p_ticket,
                              const mbedtls_ssl_session *session,
                              unsigned char *start,
                              const unsigned char *end,
                              size_t *tlen,
                              uint32_t *ticket_lifetime );

/* Temporary, WIP */
int mbedtls_ssl_ticket_parse( void *p_ticket,
                              mbedtls_ssl_session *session,
                              unsigned char *buf,
                              size_t len );

#ifdef __cplusplus
}
#endif

#endif /* ssl_ticket.h */
