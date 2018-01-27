/**
 * \file dhm.h
 *
 * \brief Diffie-Hellman-Merkle key exchange.
 *
 * <em>RFC-3526: More Modular Exponential (MODP) Diffie-Hellman groups for 
 * Internet Key Exchange (IKE)</em> defines a number of standardized 
 * Diffie-Hellman groups for IKE. 
 *
 * <em>RFC-5114: Additional Diffie-Hellman Groups for Use with IETF 
 * Standards</em> defines a number of standardized Diffie-Hellman 
 * groups that can be used. 
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */
 
#ifndef MBEDTLS_DHM_H
#define MBEDTLS_DHM_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#include "bignum.h"
#if !defined(MBEDTLS_DHM_ALT)

/*
 * DHM Error codes
 */
#define MBEDTLS_ERR_DHM_BAD_INPUT_DATA                    -0x3080  /**< Bad input parameters. */
#define MBEDTLS_ERR_DHM_READ_PARAMS_FAILED                -0x3100  /**< Reading of the DHM parameters failed. */
#define MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED                -0x3180  /**< Making of the DHM parameters failed. */
#define MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED                -0x3200  /**< Reading of the public values failed. */
#define MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED                -0x3280  /**< Making of the public value failed. */
#define MBEDTLS_ERR_DHM_CALC_SECRET_FAILED                -0x3300  /**< Calculation of the DHM secret failed. */
#define MBEDTLS_ERR_DHM_INVALID_FORMAT                    -0x3380  /**< The ASN.1 data is not formatted correctly. */
#define MBEDTLS_ERR_DHM_ALLOC_FAILED                      -0x3400  /**< Allocation of memory failed. */
#define MBEDTLS_ERR_DHM_FILE_IO_ERROR                     -0x3480  /**< Read or write of file failed. */


 /* The following lists the source of the above groups in the standards:
 * - RFC-3526 section 3: 2048-bit MODP Group
 * - RFC-3526 section 4: 3072-bit MODP Group
 * - RFC-3526 section 5: 4096-bit MODP Group
 * - RFC-5114 section 2.2: 2048-bit MODP Group with 224-bit Prime Order Subgroup
 * .
 */
 
 
 /** 
 * The hexadecimal string representation of the prime defining the 2048-bit  
 * group, as defined in <em>RFC-3526: More Modular Exponential (MODP) 
 * Diffie-Hellman groups for Internet Key Exchange (IKE)</em>.
 */
#define MBEDTLS_DHM_RFC3526_MODP_2048_P               \
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
/** 
 * The chosen generator of the 2048-bit Group, as defined in <em>RFC-3526: 
 * More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key
 * Exchange (IKE)</em>.
 */
#define MBEDTLS_DHM_RFC3526_MODP_2048_G          "02"

/** 
 * The hexadecimal value of the 3072-bit group, as defined in 
 * <em>RFC-3526: More Modular Exponential (MODP) Diffie-Hellman groups
 * for Internet Key Exchange (IKE)</em>.
 */
#define MBEDTLS_DHM_RFC3526_MODP_3072_P               \
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" \
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" \
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" \
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" \
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" \
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

/** 
 * The generator of the 3072-bit MODP Group, as defined in 
 * <em>RFC-3526: More Modular Exponential (MODP) Diffie-Hellman
 * groups for Internet Key Exchange (IKE)</em>.
 */
#define MBEDTLS_DHM_RFC3526_MODP_3072_G          "02"

/** 
 * The hexadecimal value of the 4096-bit MODP Group, as defined 
 * in <em>RFC-3526: More Modular Exponential (MODP) Diffie-Hellman 
 * groups for Internet Key Exchange (IKE)</em>.
 */
#define MBEDTLS_DHM_RFC3526_MODP_4096_P                \
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" \
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" \
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" \
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" \
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" \
    "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" \
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" \
    "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" \
    "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" \
    "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" \
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" \
    "FFFFFFFFFFFFFFFF"

/** 
 * The generator of the 4096-bit MODP Group, as defined in 
 * <em>RFC-3526: More Modular Exponential (MODP) Diffie-Hellman 
 * groups for Internet Key Exchange (IKE)</em>.
 */
#define MBEDTLS_DHM_RFC3526_MODP_4096_G          "02"

/** 
 * The hexadecimal value of the 2048-bit MODP Group with 224-bit Prime Order 
 * Subgroup, as defined in <em>RFC-5114: Additional Diffie-Hellman Groups for 
 * Use with IETF Standards</em>.
 */
#define MBEDTLS_DHM_RFC5114_MODP_2048_P               \
    "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1" \
    "B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15" \
    "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212" \
    "9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207" \
    "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708" \
    "B3BF8A317091883681286130BC8985DB1602E714415D9330" \
    "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D" \
    "CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8" \
    "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763" \
    "C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71" \
    "CF9DE5384E71B81C0AC4DFFE0C10E64F"

/** 
 * The generator of the 2048-bit MODP Group with 224-bit Prime Order Subgroup,
 * as defined in <em>RFC-5114: Additional Diffie-Hellman Groups for Use with 
 * IETF Standards</em>.
 */
#define MBEDTLS_DHM_RFC5114_MODP_2048_G              \
    "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF"\
    "74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA"\
    "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7"\
    "C17669101999024AF4D027275AC1348BB8A762D0521BC98A"\
    "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE"\
    "F180EB34118E98D119529A45D6F834566E3025E316A330EF"\
    "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB"\
    "10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381"\
    "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269"\
    "EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179"\
    "81BC087F2A7065B384B890D3191F2BFA"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          The DHM context structure.
 */
typedef struct
{
    size_t len;         /*!<  The size of \p in Bytes. */
    mbedtls_mpi P;      /*!<  The prime modulus. */
    mbedtls_mpi G;      /*!<  The generator. */
    mbedtls_mpi X;      /*!<  The secret value. */
    mbedtls_mpi GX;     /*!<  Our public key = \c G^X mod \c P. */
    mbedtls_mpi GY;     /*!<  The public key of the peer = \c G^Y mod \c P. */
    mbedtls_mpi K;      /*!<  The shared secret = \c GY^X mod \c P. */
    mbedtls_mpi RP;     /*!<  The cached = \c R^2 mod \c P. */
    mbedtls_mpi Vi;     /*!<  The blinding value. */
    mbedtls_mpi Vf;     /*!<  The unblinding value. */
    mbedtls_mpi pX;     /*!<  The previous \c X. */
}
mbedtls_dhm_context;

/**
 * \brief          This function initializes the DHM context.
 *
 * \param ctx      The DHM context to initialize.
 */
void mbedtls_dhm_init( mbedtls_dhm_context *ctx );

/**
 * \brief          This function parses the ServerKeyExchange parameters.
 *
 * \param ctx      The DHM context.
 * \param p        The start of the input buffer.
 * \param end      The end of the input buffer.
 *
 * \return         \c 0 on success, or an \c MBEDTLS_ERR_DHM_XXX error code 
 *                 on failure.
 */
int mbedtls_dhm_read_params( mbedtls_dhm_context *ctx,
                     unsigned char **p,
                     const unsigned char *end );

/**
 * \brief          This function sets up and writes the ServerKeyExchange 
 *                 parameters.
 *
 * \param ctx      The DHM context.
 * \param x_size   The private value size in Bytes.
 * \param olen     The number of characters written.
 * \param output   The destination buffer.
 * \param f_rng    The RNG function.
 * \param p_rng    The RNG parameter.
 *
 * \note           This function assumes that the value and generator of 
 *                 \p ctx have already been properly set. For example,
 *                 using mbedtls_mpi_read_string() or mbedtls_mpi_read_binary().
 *
 * \return         \c 0 on success, or an \c MBEDTLS_ERR_DHM_XXX error code 
 *                 on failure.
 */
int mbedtls_dhm_make_params( mbedtls_dhm_context *ctx, int x_size,
                     unsigned char *output, size_t *olen,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief          This function imports the public value G^Y of the peer.
 *
 * \param ctx      The DHM context.
 * \param input    The input buffer.
 * \param ilen     The size of the input buffer.
 *
 * \return         \c 0 on success, or an \c MBEDTLS_ERR_DHM_XXX error code 
 *                 on failure.
 */
int mbedtls_dhm_read_public( mbedtls_dhm_context *ctx,
                     const unsigned char *input, size_t ilen );

/**
 * \brief          This function creates its own private value \c X and 
 *                 exports \c G^X.
 *
 * \param ctx      The DHM context.
 * \param x_size   The private value size in Bytes.
 * \param output   The destination buffer.
 * \param olen     The length of the destination buffer. Must be at least 
                   equal to ctx->len (the size of \c P).
 * \param f_rng    The RNG function.
 * \param p_rng    The RNG parameter.
 *
 * \return         \c 0 on success, or an \c MBEDTLS_ERR_DHM_XXX error code 
 *                 on failure.
 */
int mbedtls_dhm_make_public( mbedtls_dhm_context *ctx, int x_size,
                     unsigned char *output, size_t olen,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief               This function derives and exports the shared secret 
 *                      \c (G^Y)^X mod \c P.
 *
 * \param ctx           The DHM context.
 * \param output        The destination buffer.
 * \param output_size   The size of the destination buffer.
 * \param olen          On exit, holds the actual number of Bytes written.
 * \param f_rng         The RNG function, for blinding purposes.
 * \param p_rng         The RNG parameter.
 *
 * \return         \c 0 on success, or an \c MBEDTLS_ERR_DHM_XXX error code
 *                 on failure.
 *
 * \note           If non-NULL, \p f_rng is used to blind the input as
 *                 a countermeasure against timing attacks. Blinding is used 
 *                 only if the secret value \p X is re-used and omitted 
 *                 otherwise. Therefore, we recommend always passing a 
 *                 non-NULL \p f_rng argument.
 */
int mbedtls_dhm_calc_secret( mbedtls_dhm_context *ctx,
                     unsigned char *output, size_t output_size, size_t *olen,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief          This function frees and clears the components of a DHM key.
 *
 * \param ctx      The DHM context to free and clear.
 */
void mbedtls_dhm_free( mbedtls_dhm_context *ctx );

#if defined(MBEDTLS_ASN1_PARSE_C)
/** \ingroup x509_module */
/**
 * \brief             This function parses DHM parameters in PEM or DER format.
 *
 * \param dhm         The DHM context to initialize.
 * \param dhmin       The input buffer.
 * \param dhminlen    The size of the buffer, including the terminating null
 *                    Byte for PEM data.
 *
 * \return            \c 0 on success, or a specific DHM or PEM error code 
 *                    on failure.
 */
int mbedtls_dhm_parse_dhm( mbedtls_dhm_context *dhm, const unsigned char *dhmin,
                   size_t dhminlen );

#if defined(MBEDTLS_FS_IO)
/** \ingroup x509_module */
/**
 * \brief          This function loads and parses DHM parameters from a file.
 *
 * \param dhm      The DHM context to load the parameters to.
 * \param path     The filename to read the DHM parameters from.
 *
 * \return         \c 0 on success, or a specific DHM or PEM error code
 *                 on failure.
 */
int mbedtls_dhm_parse_dhmfile( mbedtls_dhm_context *dhm, const char *path );
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_ASN1_PARSE_C */

#ifdef __cplusplus
}
#endif

#else /* MBEDTLS_DHM_ALT */
#include "dhm_alt.h"
#endif /* MBEDTLS_DHM_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          The DMH checkup routine.
 *
 * \return         \c 0 on success, or \c 1 on failure.
 */
int mbedtls_dhm_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* dhm.h */
