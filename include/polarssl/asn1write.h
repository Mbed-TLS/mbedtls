/**
 * \file asn1write.h
 *
 * \brief ASN.1 buffer writing functionality
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
#ifndef POLARSSL_ASN1_WRITE_H
#define POLARSSL_ASN1_WRITE_H

#include "asn1.h"

#define ASN1_CHK_ADD(g, f) if( ( ret = f ) < 0 ) return( ret ); else g += ret

#ifdef __cplusplus
extern "C" {
#endif

int asn1_write_len( unsigned char **p, unsigned char *start, size_t len );
int asn1_write_tag( unsigned char **p, unsigned char *start, unsigned char tag );
#if defined(POLARSSL_BIGNUM_C)
int asn1_write_mpi( unsigned char **p, unsigned char *start, mpi *X );
#endif
int asn1_write_null( unsigned char **p, unsigned char *start );
int asn1_write_oid( unsigned char **p, unsigned char *start, const char *oid );
int asn1_write_algorithm_identifier( unsigned char **p, unsigned char *start, const char *algorithm_oid );
int asn1_write_int( unsigned char **p, unsigned char *start, int val );
int asn1_write_printable_string( unsigned char **p, unsigned char *start,
                                 char *text );
int asn1_write_ia5_string( unsigned char **p, unsigned char *start,
                                 char *text );

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_ASN1_WRITE_H */
