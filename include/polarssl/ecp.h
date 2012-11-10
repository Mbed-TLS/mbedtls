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
 * ECP error codes
 *
 * (Only one error code available...)
 */
#define POLARSSL_ERR_ECP_GENERIC    -0x007E  /**<  Generic ECP error */

/**
 * \brief           ECP point structure (affine coordinates)
 *
 * Note: if the point is zero, X and Y are irrelevant and should be freed.
 */
typedef struct
{
    char is_zero;   /*!<  true if point at infinity */
    mpi X;          /*!<  the point's X coordinate  */
    mpi Y;          /*!<  the point's Y coordinate  */
}
ecp_point;

/**
 * \brief           ECP group structure
 *
 * The curves we consider are defined by y^2 = x^3 - 3x + b mod p,
 * and a generator for a large subgroup is fixed.
 *
 * modp may be NULL; pbits will not be used in this case.
 */
typedef struct
{
    mpi P;              /*!<  prime modulus of the base field   */
    mpi B;              /*!<  constant term in the equation     */
    ecp_point G;        /*!<  generator of the subgroup used    */
    mpi N;              /*!<  the order of G                    */
    int (*modp)(mpi *); /*!<  function for fast reduction mod P */
    unsigned pbits;     /*!<  number of bits in P               */
}
ecp_group;

/**
 * RFC 5114 defines a number of standardized ECP groups for use with TLS.
 *
 * These also are the NIST-recommended ECP groups, are the random ECP groups
 * recommended by SECG, and include the two groups used by NSA Suite B.
 * There are known as secpLLLr1 with LLL = 192, 224, 256, 384, 521.
 *
 * \warning This library does not support validation of arbitrary domain
 * parameters. Therefore, only well-known domain parameters from trusted
 * sources (such as the ones below) should be used. See ecp_use_known_dp().
 */
#define POLARSSL_ECP_DP_SECP192R1   0
#define POLARSSL_ECP_DP_SECP224R1   1
#define POLARSSL_ECP_DP_SECP256R1   2
#define POLARSSL_ECP_DP_SECP384R1   3
#define POLARSSL_ECP_DP_SECP521R1   4

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           Initialize a point (as zero)
 */
void ecp_point_init( ecp_point *pt );

/**
 * \brief           Initialize a group (to something meaningless)
 */
void ecp_group_init( ecp_group *grp );

/**
 * \brief           Free the components of a point
 */
void ecp_point_free( ecp_point *pt );

/**
 * \brief           Free the components of an ECP group
 */
void ecp_group_free( ecp_group *grp );

/**
 * \brief           Set a point to zero
 */
void ecp_set_zero( ecp_point *pt );

/**
 * \brief           Copy the contents of point Q into P
 *
 * \param P         Destination point
 * \param Q         Source point
 *
 * \return          0 if successful,
 *                  POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int ecp_copy( ecp_point *P, const ecp_point *Q );

/**
 * \brief           Import a non-zero point from two ASCII strings
 *
 * \param P         Destination point
 * \param radix     Input numeric base
 * \param x         First affine coordinate as a null-terminated string
 * \param y         Second affine coordinate as a null-terminated string
 *
 * \return          0 if successful, or a POLARSSL_ERR_MPI_XXX error code
 */
int ecp_point_read_string( ecp_point *P, int radix,
                           const char *x, const char *y );

/**
 * \brief           Import an ECP group from null-terminated ASCII strings
 *
 * \param grp       Destination group
 * \param radix     Input numeric base
 * \param p         Prime modulus of the base field
 * \param b         Constant term in the equation
 * \param gx        The generator's X coordinate
 * \param gy        The generator's Y coordinate
 * \param n         The generator's order
 *
 * \return          0 if successful, or a POLARSSL_ERR_MPI_XXX error code
 */
int ecp_group_read_string( ecp_group *grp, int radix,
                           const char *p, const char *b,
                           const char *gx, const char *gy, const char *n);

/**
 * \brief           Set a group using well-known domain parameters
 *
 * \param grp       Destination group
 * \param index     Index in the list of well-known domain parameters
 *
 * \return          O if successul,
 *                  POLARSSL_ERR_MPI_XXX if initialization failed
 *                  POLARSSL_ERR_ECP_GENERIC if index is out of range
 *
 * \note            Index should be a POLARSSL_ECP_DP_XXX macro.
 */
int ecp_use_known_dp( ecp_group *grp, size_t index );

/**
 * \brief           Addition: R = P + Q
 *
 * \param grp       ECP group
 * \param R         Destination point
 * \param P         Left-hand point
 * \param Q         Right-hand point
 *
 * \return          0 if successful,
 *                  POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int ecp_add( const ecp_group *grp, ecp_point *R,
             const ecp_point *P, const ecp_point *Q );

/**
 * \brief           Multiplication by an integer: R = m * P
 *
 * \param grp       ECP group
 * \param R         Destination point
 * \param m         Integer by which to multiply
 * \param P         Point to multiply
 *
 * \return          0 if successful,
 *                  POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int ecp_mul( const ecp_group *grp, ecp_point *R,
             const mpi *m, const ecp_point *P );

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
