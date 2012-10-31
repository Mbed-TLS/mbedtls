/**
 * \file ecp.h
 *
 * \brief Elliptic curves over GF(p)
 *
 *  Copyright (C) 2012, Brainspark B.V.
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
#ifndef POLARSSL_ECP_H
#define POLARSSL_ECP_H

#include "bignum.h"

/*
 * ECP Error codes
 */

/**
 * \brief           ECP point structure (affine coordinates)
 */
typedef struct
{
    mpi X;      /*!<  the point's X coordinate  */
    mpi Y;      /*!<  the point's Y coordinate  */
}
ecp_point;

/**
 * \brief           ECP group structure
 *
 * The curves we consider are defined by y^2 = x^3 - 3x + b mod p,
 * and a generator for a large subgroup is fixed.
 */
typedef struct
{
    mpi P;              /*!<  prime modulus of the base field   */
    mpi B;              /*!<  constant term in the equation     */
    ecp_point G;        /*!<  generator of the subgroup used    */
    mpi N;              /*!<  the order of G                    */
    unsigned char h;    /*!<  the cofactor of the subgroup      */
}
ecp_group;

/**
 * RFC 5114 defines a number of standardized ECP groups for use with TLS.
 *
 * These also are the NIST-recommended ECP groups, are the random ECP groups
 * recommended by SECG, and include the two groups used by NSA Suite B.
 *
 * \warning This library does not support validation of arbitrary domain
 * parameters. Therefore, only well-known domain parameters from trusted
 * sources (such as the ones below) should be used.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           Addition: R = P + Q
 *
 * \param grp       ECP group
 * \param R         Destination point
 * \param P         Left-hand point
 * \param Q         Right-hand point
 *
 * \return          0 if successful, or an POLARSSL_ERR_ECP_XXX error code
 */
int ecp_add( const ecp_group *grp, ecp_point *R,
             const ecp_point *P, const ecp_point *Q );

/**
 * \brief           Duplication: R = 2 P
 *
 * \param grp       ECP group
 * \param R         Destination point
 * \param P         Point to double
 *
 * \return          0 if successful, or an POLARSSL_ERR_ECP_XXX error code
 */
int ecp_double( const ecp_group *grp, ecp_point *R,
                const ecp_point *P );

/**
 * \brief           Multiplication by an integer: R = m * P
 *
 * \param grp       ECP group
 * \param R         Destination point
 * \param m         Integer by which to multiply
 * \param P         Point to multiply
 *
 * \return          0 if successful, or an POLARSSL_ERR_ECP_XXX error code
 */
int ecp_multiply( const ecp_group *grp, ecp_point *R,
                  const mpi *m, const ecp_point *P );

/**
 * \brief           Free the components of a point
 */
void ecp_point_free( ecp_point *pt );

/**
 * \brief           Free the components of an ECP group
 */
void ecp_group_free( ecp_group *grp );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int ecp_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif
