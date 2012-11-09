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
 * sources (such as the ones below) should be used.
 */
#define POLARSSL_ECP_DP_SECP192R1   0
#define POLARSSL_ECP_DP_SECP224R1   1
#define POLARSSL_ECP_DP_SECP256R1   2
#define POLARSSL_ECP_DP_SECP384R1   3
#define POLARSSL_ECP_DP_SECP521R1   4

#define POLARSSL_ECP_SECP192R1_P \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"
#define POLARSSL_ECP_SECP192R1_B \
    "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1"
#define POLARSSL_ECP_SECP192R1_GX \
    "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"
#define POLARSSL_ECP_SECP192R1_GY \
    "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"
#define POLARSSL_ECP_SECP192R1_N \
    "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"

#define POLARSSL_ECP_SECP224R1_P \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001"
#define POLARSSL_ECP_SECP224R1_B \
    "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4"
#define POLARSSL_ECP_SECP224R1_GX \
    "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
#define POLARSSL_ECP_SECP224R1_GY \
    "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"
#define POLARSSL_ECP_SECP224R1_N \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"

#define POLARSSL_ECP_SECP256R1_P \
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
#define POLARSSL_ECP_SECP256R1_B \
    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
#define POLARSSL_ECP_SECP256R1_GX \
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
#define POLARSSL_ECP_SECP256R1_GY \
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
#define POLARSSL_ECP_SECP256R1_N \
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"

#define POLARSSL_ECP_SECP384R1_P \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
    "FFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"
#define POLARSSL_ECP_SECP384R1_B \
    "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE814112" \
    "0314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"
#define POLARSSL_ECP_SECP384R1_GX \
    "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B98" \
    "59F741E082542A385502F25DBF55296C3A545E3872760AB7"
#define POLARSSL_ECP_SECP384R1_GY \
    "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147C" \
    "E9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"
#define POLARSSL_ECP_SECP384R1_N \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
    "C7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"

#define POLARSSL_ECP_SECP521R1_P \
    "000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
#define POLARSSL_ECP_SECP521R1_B \
    "00000051953EB9618E1C9A1F929A21A0B68540EEA2DA725B" \
    "99B315F3B8B489918EF109E156193951EC7E937B1652C0BD" \
    "3BB1BF073573DF883D2C34F1EF451FD46B503F00"
#define POLARSSL_ECP_SECP521R1_GX \
    "000000C6858E06B70404E9CD9E3ECB662395B4429C648139" \
    "053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127" \
    "A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
#define POLARSSL_ECP_SECP521R1_GY \
    "0000011839296A789A3BC0045C8A5FB42C7D1BD998F54449" \
    "579B446817AFBD17273E662C97EE72995EF42640C550B901" \
    "3FAD0761353C7086A272C24088BE94769FD16650"
#define POLARSSL_ECP_SECP521R1_N \
    "000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
    "FFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148" \
    "F709A5D03BB5C9B8899C47AEBB6FB71E91386409"

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
