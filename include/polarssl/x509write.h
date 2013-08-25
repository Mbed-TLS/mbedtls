/**
 * \file x509write.h
 *
 * \brief X509 buffer writing functionality
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
#ifndef POLARSSL_X509_WRITE_H
#define POLARSSL_X509_WRITE_H

#include "config.h"

#include "rsa.h"

#define POLARSSL_ERR_X509WRITE_UNKNOWN_OID                -0x5F80  /**< Requested OID is unknown. */
#define POLARSSL_ERR_X509WRITE_BAD_INPUT_DATA             -0x5F00  /**< Failed to allocate memory. */
#define POLARSSL_ERR_X509WRITE_MALLOC_FAILED              -0x5E80  /**< Failed to allocate memory. */


#ifdef __cplusplus
extern "C" {
#endif

typedef struct _x509_req_name
{
    char oid[128];
    char name[128];

    struct _x509_req_name *next;
}
x509_req_name;

typedef struct _x509_csr
{
    rsa_context *rsa;
    x509_req_name *subject;
    md_type_t md_alg;
}
x509_csr;

void x509write_csr_init( x509_csr *ctx );
int x509write_csr_set_subject_name( x509_csr *ctx, char *subject_name );
void x509write_csr_set_rsa_key( x509_csr *ctx, rsa_context *rsa );
void x509write_csr_set_md_alg( x509_csr *ctx, md_type_t md_alg );
void x509write_csr_free( x509_csr *ctx );

int x509write_pubkey_der( rsa_context *rsa, unsigned char *buf, size_t size );
int x509write_key_der( rsa_context *rsa, unsigned char *buf, size_t size );
int x509write_csr_der( x509_csr *ctx, unsigned char *buf, size_t size );

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_X509_WRITE_H */
