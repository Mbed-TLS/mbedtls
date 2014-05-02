/**
 * \file ccm.h
 *
 * \brief Counter with CBC-MAC (CCM) for 128-bit block ciphers
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
#ifndef POLARSSL_CCM_H
#define POLARSSL_CCM_H

#include "cipher.h"

#define POLARSSL_ERR_CCM_BAD_INPUT      -0x000D /**< Bad input parameters to function. */
#define POLARSSL_ERR_CCM_AUTH_FAILED    -0x000F /**< Authenticated decryption failed. */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(POLARSSL_SELF_TEST) && defined(POLARSSL_AES_C)
/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int ccm_self_test( int verbose );
#endif /* POLARSSL_SELF_TEST && POLARSSL_AES_C */

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_CGM_H */
