/**
 * \file rsa.h
 *
 * \brief The RSA public-key cryptosystem
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_RSA_H
#define MBEDTLS_RSA_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "bignum.h"
#include "md.h"

#if defined(MBEDTLS_THREADING_C)
#include "threading.h"
#endif

/*
 * RSA Error codes
 */
#define MBEDTLS_ERR_RSA_BAD_INPUT_DATA                    -0x4080  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_RSA_INVALID_PADDING                   -0x4100  /**< Input data contains invalid padding and is rejected. */
#define MBEDTLS_ERR_RSA_KEY_GEN_FAILED                    -0x4180  /**< Something failed during generation of a key. */
#define MBEDTLS_ERR_RSA_KEY_CHECK_FAILED                  -0x4200  /**< Key failed to pass the library's validity check. */
#define MBEDTLS_ERR_RSA_PUBLIC_FAILED                     -0x4280  /**< The public key operation failed. */
#define MBEDTLS_ERR_RSA_PRIVATE_FAILED                    -0x4300  /**< The private key operation failed. */
#define MBEDTLS_ERR_RSA_VERIFY_FAILED                     -0x4380  /**< The PKCS#1 verification failed. */
#define MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE                  -0x4400  /**< The output buffer for decryption is not large enough. */
#define MBEDTLS_ERR_RSA_RNG_FAILED                        -0x4480  /**< The random generator failed to generate non-zeros. */
#define MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION             -0x4500  /**< The implementation doesn't offer the requested operation, e.g. because of security violations or lack of functionality */

/*
 * RSA constants
 */
#define MBEDTLS_RSA_PUBLIC      0
#define MBEDTLS_RSA_PRIVATE     1

#define MBEDTLS_RSA_PKCS_V15    0
#define MBEDTLS_RSA_PKCS_V21    1

#define MBEDTLS_RSA_SIGN        1
#define MBEDTLS_RSA_CRYPT       2

#define MBEDTLS_RSA_SALT_LEN_ANY    -1

/*
 * The above constants may be used even if the RSA module is compile out,
 * eg for alternative (PKCS#11) RSA implemenations in the PK layers.
 */

#if !defined(MBEDTLS_RSA_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief   RSA context structure
 *
 * \note    Direct manipulation of the members of this structure
 *          is deprecated and will no longer be supported starting
 *          from the next major release. All manipulation should instead
 *          be done through the public interface functions.
 *
 */
typedef struct
{
    int ver;                    /*!<  always 0          */
    size_t len;                 /*!<  size(N) in chars  */

    mbedtls_mpi N;                      /*!<  public modulus    */
    mbedtls_mpi E;                      /*!<  public exponent   */

    mbedtls_mpi D;                      /*!<  private exponent  */
    mbedtls_mpi P;                      /*!<  1st prime factor  */
    mbedtls_mpi Q;                      /*!<  2nd prime factor  */

    mbedtls_mpi DP;                     /*!<  D % (P - 1)       */
    mbedtls_mpi DQ;                     /*!<  D % (Q - 1)       */
    mbedtls_mpi QP;                     /*!<  1 / (Q % P)       */

    mbedtls_mpi RN;                     /*!<  cached R^2 mod N  */

    mbedtls_mpi RP;                     /*!<  cached R^2 mod P  */
    mbedtls_mpi RQ;                     /*!<  cached R^2 mod Q  */

    mbedtls_mpi Vi;                     /*!<  cached blinding value     */
    mbedtls_mpi Vf;                     /*!<  cached un-blinding value  */

    int padding;                /*!<  \c MBEDTLS_RSA_PKCS_V15 for 1.5 padding and
                                      \c MBEDTLS_RSA_PKCS_v21 for OAEP/PSS */
    int hash_id;                /*!<  Hash identifier of mbedtls_md_type_t as
                                      specified in the mbedtls_md.h header file
                                      for the EME-OAEP and EMSA-PSS
                                      encoding                          */
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t mutex;    /*!<  Thread-safety mutex       */
#endif
}
mbedtls_rsa_context;

/**
 * \brief          Initialize an RSA context
 *
 *                 Note: Set padding to \c MBEDTLS_RSA_PKCS_V21 for the RSAES-OAEP
 *                 encryption scheme and the RSASSA-PSS signature scheme.
 *
 * \param ctx      RSA context to be initialized
 * \param padding  \c MBEDTLS_RSA_PKCS_V15 or \c MBEDTLS_RSA_PKCS_V21
 * \param hash_id  \c MBEDTLS_RSA_PKCS_V21 hash identifier
 *
 * \note           The hash_id parameter is actually ignored
 *                 when using \c MBEDTLS_RSA_PKCS_V15 padding.
 *
 * \note           Choice of padding mode is strictly enforced for private key
 *                 operations, since there might be security concerns in
 *                 mixing padding modes. For public key operations it's merely
 *                 a default value, which can be overriden by calling specific
 *                 rsa_rsaes_xxx or rsa_rsassa_xxx functions.
 *
 * \note           The chosen hash is always used for OEAP encryption.
 *                 For PSS signatures, it's always used for making signatures,
 *                 but can be overriden (and always is, if set to
 *                 \c MBEDTLS_MD_NONE) for verifying them.
 */
void mbedtls_rsa_init( mbedtls_rsa_context *ctx,
                       int padding,
                       int hash_id);

/**
 * \brief          Import a set of core parameters into an RSA context
 *
 * \param ctx      Initialized RSA context to store parameters
 * \param N        RSA modulus, or NULL
 * \param P        First prime factor of N, or NULL
 * \param Q        Second prime factor of N, or NULL
 * \param D        Private exponent, or NULL
 * \param E        Public exponent, or NULL
 *
 * \note           This function can be called multiple times for successive
 *                 imports if the parameters are not simultaneously present.
 *                 Any sequence of calls to this function should be followed
 *                 by a call to \c mbedtls_rsa_complete which will check
 *                 and complete the provided information to a ready-for-use
 *                 public or private RSA key.
 *
 * \note           See the documentation of \c mbedtls_rsa_complete for more
 *                 information on which parameters are necessary to setup
 *                 a private or public RSA key.
 *
 * \note           The imported parameters are copied and need not be preserved
 *                 for the lifetime of the RSA context being set up.
 *
 * \return         0 if successful, non-zero error code on failure.
 */
int mbedtls_rsa_import( mbedtls_rsa_context *ctx,
                        const mbedtls_mpi *N,
                        const mbedtls_mpi *P, const mbedtls_mpi *Q,
                        const mbedtls_mpi *D, const mbedtls_mpi *E );

/**
 * \brief          Import core RSA parameters in raw big-endian
 *                 binary format into an RSA context
 *
 * \param ctx      Initialized RSA context to store parameters
 * \param N        RSA modulus, or NULL
 * \param N_len    Byte length of N, ignored if N == NULL
 * \param P        First prime factor of N, or NULL
 * \param P_len    Byte length of P, ignored if P == NULL
 * \param Q        Second prime factor of N, or NULL
 * \param Q_len    Byte length of Q, ignored if Q == NULL
 * \param D        Private exponent, or NULL
 * \param D_len    Byte length of D, ignored if D == NULL
 * \param E        Public exponent, or NULL
 * \param E_len    Byte length of E, ignored if E == NULL
 *
 * \note           This function can be called multiple times for successive
 *                 imports if the parameters are not simultaneously present.
 *                 Any sequence of calls to this function should be followed
 *                 by a call to \c mbedtls_rsa_complete which will check
 *                 and complete the provided information to a ready-for-use
 *                 public or private RSA key.
 *
 * \note           See the documentation of \c mbedtls_rsa_complete for more
 *                 information on which parameters are necessary to setup
 *                 a private or public RSA key.
 *
 * \note           The imported parameters are copied and need not be preserved
 *                 for the lifetime of the RSA context being set up.
 *
 * \return         0 if successful, non-zero error code on failure.
 */
int mbedtls_rsa_import_raw( mbedtls_rsa_context *ctx,
                            unsigned char const *N, size_t N_len,
                            unsigned char const *P, size_t P_len,
                            unsigned char const *Q, size_t Q_len,
                            unsigned char const *D, size_t D_len,
                            unsigned char const *E, size_t E_len );

/**
 * \brief          Attempt to complete an RSA context from
 *                 a set of imported core parameters.
 *
 * \param ctx      Initialized RSA context to store parameters
 *
 * \note
 *                 - To setup an RSA public key, precisely N and E
 *                   must have been imported.
 *
 *                 - To setup an RSA private key, enough information must be
 *                   present for the other parameters to be derivable.
 *
 *                   The default implementation supports the following:
 *                     - Derive P, Q from N, D, E
 *                     - Derive N, D from P, Q, E.
 *
 *                 - Alternative implementations need not support these
 *                   and may return \c MBEDTLS_ERR_RSA_BAD_INPUT_DATA instead.
 *
 * \return
 *                 - 0 if successful. In this case, it is guaranteed
 *                   that the RSA context can be used for RSA operations
 *                   without the risk of failure or crash.
 *                 - \c MBEDTLS_ERR_RSA_BAD_INPUT_DATA if the attempted
 *                   derivations failed.
 *
 * \warning        This function need not perform consistency checks
 *                 for the imported parameters! In particular, parameters that
 *                 are not needed by the implementation may be silently discarded
 *                 and left unchecked. For the purpose of checking the consistency
 *                 of the key material, see \c mbedtls_rsa_check_privkey.
 *
 */
int mbedtls_rsa_complete( mbedtls_rsa_context *ctx );

/**
 * \brief          Export core parameters of an RSA key
 *
 * \param ctx      Initialized RSA context
 * \param N        MPI to hold the RSA modulus, or NULL
 * \param P        MPI to hold the first prime factor of N, or NULL
 * \param Q        MPI to hold the second prime factor of N, or NULL
 * \param D        MPI to hold the private exponent, or NULL
 * \param E        MPI to hold the public exponent, or NULL
 *
 * \return
 *                 - 0 if successful. In this case, the non-NULL buffers
 *                   pointed to by N, P, Q, D, E are fully written, with
 *                   additional unused space filled leading by 0-bytes.
 *                 - Non-zero return code otherwise. In particular, if
 *                   exporting the requested parameters
 *                   cannot be done because of a lack of functionality
 *                   or because of security policies, the error code
 *                   \c MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION is returned.
 *                   In this case, the RSA context stays intact and can
 *                   be continued to be used.
 *
 * \note           Reasons for returning \c MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION
 *                 would be the following: Firstly, it might be that an
 *                 alternative RSA implementation is in use which stores
 *                 the key externally, and which either cannot or should not
 *                 export it into RAM. Alternatively, an implementation
 *                 (regardless of SW or HW) might not support deducing e.g.
 *                 P, Q from N, D, E if the former are not part of the
 *                 implementation.
 *
 */
int mbedtls_rsa_export( const mbedtls_rsa_context *ctx,
                        mbedtls_mpi *N, mbedtls_mpi *P, mbedtls_mpi *Q,
                        mbedtls_mpi *D, mbedtls_mpi *E );

/**
 * \brief          Export core parameters of an RSA key
 *                 in raw big-endian binary format
 *
 * \param ctx      Initialized RSA context
 * \param N        Byte array to store the RSA modulus, or NULL
 * \param N_len    Size of buffer for modulus
 * \param P        Byte array to hold the first prime factor of N, or NULL
 * \param P_len    Size of buffer for first prime factor
 * \param Q        Byte array to hold the second prime factor of N, or NULL
 * \param Q_len    Size of buffer for second prime factor
 * \param D        Byte array to hold the private exponent, or NULL
 * \param D_len    Size of buffer for private exponent
 * \param E        Byte array to hold the public exponent, or NULL
 * \param E_len    Size of buffer for public exponent
 *
 * \note           The length fields are ignored if the corresponding
 *                 buffer pointers are NULL.
 *
 * \return
 *                 - 0 if successful. In this case, the non-NULL buffers
 *                   pointed to by N, P, Q, D, E are fully written, with
 *                   additional unused space filled leading by 0-bytes.
 *                 - Non-zero return code otherwise. In particular, if
 *                   exporting the requested parameters
 *                   cannot be done because of a lack of functionality
 *                   or because of security policies, the error code
 *                   \c MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION is returned.
 *                   In this case, the RSA context stays intact and can
 *                   be continued to be used.
 *
 * \note           Reasons for returning \c MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION
 *                 would be the following: Firstly, it might be that an
 *                 alternative RSA implementation is in use which stores
 *                 the key externally, and which either cannot or should not
 *                 export it into RAM. Alternatively, an implementation
 *                 (regardless of SW or HW) might not support deducing e.g.
 *                 P, Q from N, D, E if the former are not part of the
 *                 implementation.
 *
 *
 */
int mbedtls_rsa_export_raw( const mbedtls_rsa_context *ctx,
                            unsigned char *N, size_t N_len,
                            unsigned char *P, size_t P_len,
                            unsigned char *Q, size_t Q_len,
                            unsigned char *D, size_t D_len,
                            unsigned char *E, size_t E_len );

/**
 * \brief          Export CRT parameters of a private RSA key
 *
 * \param ctx      Initialized RSA context
 * \param DP       MPI to hold D modulo P-1, or NULL
 * \param DQ       MPI to hold D modulo Q-1, or NULL
 * \param QP       MPI to hold modular inverse of Q modulo P, or NULL
 *
 * \return         0 if successful, non-zero error code otherwise.
 *
 * \note           Alternative RSA implementations not using CRT-parameters
 *                 internally can implement this function using based on
 *                 \c mbedtls_rsa_deduce_opt.
 *
 */
int mbedtls_rsa_export_crt( const mbedtls_rsa_context *ctx,
                            mbedtls_mpi *DP, mbedtls_mpi *DQ, mbedtls_mpi *QP );

/**
 * \brief          Set padding for an already initialized RSA context
 *                 See \c mbedtls_rsa_init() for details.
 *
 * \param ctx      RSA context to be set
 * \param padding  \c MBEDTLS_RSA_PKCS_V15 or \c MBEDTLS_RSA_PKCS_V21
 * \param hash_id  \c MBEDTLS_RSA_PKCS_V21 hash identifier
 */
void mbedtls_rsa_set_padding( mbedtls_rsa_context *ctx, int padding,
                              int hash_id);

/**
 * \brief          Get length of RSA modulus in bytes
 *
 * \param ctx      Initialized RSA context
 *
 * \return         Length of RSA modulus, in bytes.
 *
 */
size_t mbedtls_rsa_get_len( const mbedtls_rsa_context *ctx );

/**
 * \brief          Generate an RSA keypair
 *
 * \param ctx      RSA context that will hold the key
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 * \param nbits    size of the public key in bits
 * \param exponent public exponent (e.g., 65537)
 *
 * \note           mbedtls_rsa_init() must be called beforehand to setup
 *                 the RSA context.
 *
 * \return         0 if successful, or an \c MBEDTLS_ERR_RSA_XXX error code
 */
int mbedtls_rsa_gen_key( mbedtls_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         unsigned int nbits, int exponent );

/**
 * \brief          Check if a context contains (at least) an RSA public key
 *
 * \param ctx      RSA context to be checked
 *
 * \return         0 if successful, or an \c MBEDTLS_ERR_RSA_XXX error code.
 *                 On success, it is guaranteed that enough information is
 *                 present to perform an RSA public key operation
 *                 \c mbedtls_rsa_public.
 *
 */
int mbedtls_rsa_check_pubkey( const mbedtls_rsa_context *ctx );

/**
 * \brief      Check if a context contains an RSA private key
 *             and perform basic consistency checks.
 *
 * \param ctx  RSA context to be checked
 *
 * \return     0 if successful, or an \c MBEDTLS_ERR_RSA_XXX error code.
 *
 * \note       The consistency checks performed by this function not only
 *             ensure that \c mbedtls_rsa_private can be called successfully
 *             on the given context, but that the various parameters are
 *             mutually consistent with high probability, in the sense that
 *             \c mbedtls_rsa_public and \c mbedtls_rsa_private are inverses.
 *
 * \warning    This function should catch accidental misconfigurations
 *             like swapping of parameters, but it cannot establish full
 *             trust in neither the quality nor the consistency of the key
 *             material that was used to setup the given RSA context:
 *             - Regarding consistency, note (see \c mbedtls_rsa_complete)
 *               that imported parameters irrelevant for the implementation
 *               might be silently dropped, in which case the present
 *               function doesn't have access to and hence cannot check them.
 *               If you want to check the consistency of the entire
 *               content of, say, an PKCS1-encoded RSA private key, you
 *               should use \c mbedtls_rsa_validate_params before setting
 *               up the RSA context.
 *               Further, if the implementation performs empirical checks,
 *               these checks will substantiate but not guarantee consistency.
 *             - Regarding quality, this function is not expected to perform
 *               extended quality assessments like checking that the prime
 *               factors are safe. Further, it is the user's responsibility to
 *               ensure trustworthiness of the source of his RSA parameters,
 *               a question going beyond what's effectively checkable
 *               by the library.
 *
 */
int mbedtls_rsa_check_privkey( const mbedtls_rsa_context *ctx );

/**
 * \brief          Check a public-private RSA key pair.
 *                 Check each of the contexts, and make sure they match.
 *
 * \param pub      RSA context holding the public key
 * \param prv      RSA context holding the private key
 *
 * \return         0 if successful, or an \c MBEDTLS_ERR_RSA_XXX error code
 */
int mbedtls_rsa_check_pub_priv( const mbedtls_rsa_context *pub,
                                const mbedtls_rsa_context *prv );

/**
 * \brief          Do an RSA public key operation
 *
 * \param ctx      RSA context
 * \param input    input buffer
 * \param output   output buffer
 *
 * \return         0 if successful, or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           This function does NOT take care of message
 *                 padding. Also, be sure to set input[0] = 0 or ensure that
 *                 input is smaller than N.
 *
 * \note           The input and output buffers must be large
 *                 enough (eg. 128 bytes if RSA-1024 is used).
 */
int mbedtls_rsa_public( mbedtls_rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output );

/**
 * \brief          Do an RSA private key operation
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for blinding)
 * \param p_rng    RNG parameter
 * \param input    input buffer
 * \param output   output buffer
 *
 * \return         0 if successful, or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The input and output buffers must be large
 *                 enough (eg. 128 bytes if RSA-1024 is used).
 */
int mbedtls_rsa_private( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output );

/**
 * \brief          Generic wrapper to perform a PKCS#1 encryption using the
 *                 mode from the context. Add the message padding, then do an
 *                 RSA operation.
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for padding and PKCS#1 v2.1 encoding
 *                               and \c MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     \c MBEDTLS_RSA_PUBLIC or \c MBEDTLS_RSA_PRIVATE
 * \param ilen     contains the plaintext length
 * \param input    buffer holding the data to be encrypted
 * \param output   buffer that will hold the ciphertext
 *
 * \deprecated     It is deprecated and discouraged to call this function
 *                 in mode MBEDTLS_RSA_PRIVATE. Future versions of the libary
 *                 are likely to remove the mode argument and have it implicitly
 *                 set to MBEDTLS_RSA_PUBLIC.
 *
 * \note           Alternative implementations of RSA need not support
 *                 mode being set to MBEDTLS_RSA_PRIVATE and may instead
 *                 return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION.
 *
 * \return         0 if successful, or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int mbedtls_rsa_pkcs1_encrypt( mbedtls_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       int mode, size_t ilen,
                       const unsigned char *input,
                       unsigned char *output );

/**
 * \brief          Perform a PKCS#1 v1.5 encryption (RSAES-PKCS1-v1_5-ENCRYPT)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for padding and \c MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     \c MBEDTLS_RSA_PUBLIC or \c MBEDTLS_RSA_PRIVATE
 * \param ilen     contains the plaintext length
 * \param input    buffer holding the data to be encrypted
 * \param output   buffer that will hold the ciphertext
 *
 * \deprecated     It is deprecated and discouraged to call this function
 *                 in mode MBEDTLS_RSA_PRIVATE. Future versions of the libary
 *                 are likely to remove the mode argument and have it implicitly
 *                 set to MBEDTLS_RSA_PUBLIC.
 *
 * \note           Alternative implementations of RSA need not support
 *                 mode being set to MBEDTLS_RSA_PRIVATE and may instead
 *                 return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION.
 *
 * \return         0 if successful, or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int mbedtls_rsa_rsaes_pkcs1_v15_encrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t ilen,
                                 const unsigned char *input,
                                 unsigned char *output );

/**
 * \brief          Perform a PKCS#1 v2.1 OAEP encryption (RSAES-OAEP-ENCRYPT)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for padding and PKCS#1 v2.1 encoding
 *                               and \c MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     \c MBEDTLS_RSA_PUBLIC or \c MBEDTLS_RSA_PRIVATE
 * \param label    buffer holding the custom label to use
 * \param label_len contains the label length
 * \param ilen     contains the plaintext length
 * \param input    buffer holding the data to be encrypted
 * \param output   buffer that will hold the ciphertext
 *
 * \deprecated     It is deprecated and discouraged to call this function
 *                 in mode MBEDTLS_RSA_PRIVATE. Future versions of the libary
 *                 are likely to remove the mode argument and have it implicitly
 *                 set to MBEDTLS_RSA_PUBLIC.
 *
 * \note           Alternative implementations of RSA need not support
 *                 mode being set to MBEDTLS_RSA_PRIVATE and may instead
 *                 return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION.
 *
 * \return         0 if successful, or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int mbedtls_rsa_rsaes_oaep_encrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t ilen,
                            const unsigned char *input,
                            unsigned char *output );

/**
 * \brief          Generic wrapper to perform a PKCS#1 decryption using the
 *                 mode from the context. Do an RSA operation, then remove
 *                 the message padding
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Only needed for \c MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     \c MBEDTLS_RSA_PUBLIC or \c MBEDTLS_RSA_PRIVATE
 * \param olen     will contain the plaintext length
 * \param input    buffer holding the encrypted data
 * \param output   buffer that will hold the plaintext
 * \param output_max_len    maximum length of the output buffer
 *
 * \deprecated     It is deprecated and discouraged to call this function
 *                 in mode MBEDTLS_RSA_PUBLIC. Future versions of the libary
 *                 are likely to remove the mode argument and have it implicitly
 *                 set to MBEDTLS_RSA_PRIVATE.
 *
 * \note           Alternative implementations of RSA need not support
 *                 mode being set to MBEDTLS_RSA_PUBLIC and may instead
 *                 return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION.
 *
 * \return         0 if successful, or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The output buffer length \c output_max_len should be
 *                 as large as the size \c ctx->len of \c ctx->N (eg. 128 bytes
 *                 if RSA-1024 is used) to be able to hold an arbitrary
 *                 decrypted message. If it is not large enough to hold
 *                 the decryption of the particular ciphertext provided,
 *                 the function will return \c MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE.
 *
 * \note           The input buffer must be as large as the size
 *                 of \c ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int mbedtls_rsa_pkcs1_decrypt( mbedtls_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       int mode, size_t *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t output_max_len );

/**
 * \brief          Perform a PKCS#1 v1.5 decryption (RSAES-PKCS1-v1_5-DECRYPT)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Only needed for \c MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     \c MBEDTLS_RSA_PUBLIC or \c MBEDTLS_RSA_PRIVATE
 * \param olen     will contain the plaintext length
 * \param input    buffer holding the encrypted data
 * \param output   buffer that will hold the plaintext
 * \param output_max_len    maximum length of the output buffer
 *
 * \deprecated     It is deprecated and discouraged to call this function
 *                 in mode MBEDTLS_RSA_PUBLIC. Future versions of the libary
 *                 are likely to remove the mode argument and have it implicitly
 *                 set to MBEDTLS_RSA_PRIVATE.
 *
 * \note           Alternative implementations of RSA need not support
 *                 mode being set to MBEDTLS_RSA_PUBLIC and may instead
 *                 return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION.
 *
 * \return         0 if successful, or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The output buffer length \c output_max_len should be
 *                 as large as the size \c ctx->len of \c ctx->N (eg. 128 bytes
 *                 if RSA-1024 is used) to be able to hold an arbitrary
 *                 decrypted message. If it is not large enough to hold
 *                 the decryption of the particular ciphertext provided,
 *                 the function will return \c MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE.
 *
 * \note           The input buffer must be as large as the size
 *                 of \c ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int mbedtls_rsa_rsaes_pkcs1_v15_decrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t *olen,
                                 const unsigned char *input,
                                 unsigned char *output,
                                 size_t output_max_len );

/**
 * \brief          Perform a PKCS#1 v2.1 OAEP decryption (RSAES-OAEP-DECRYPT)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Only needed for \c MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     \c MBEDTLS_RSA_PUBLIC or \c MBEDTLS_RSA_PRIVATE
 * \param label    buffer holding the custom label to use
 * \param label_len contains the label length
 * \param olen     will contain the plaintext length
 * \param input    buffer holding the encrypted data
 * \param output   buffer that will hold the plaintext
 * \param output_max_len    maximum length of the output buffer
 *
 * \deprecated     It is deprecated and discouraged to call this function
 *                 in mode MBEDTLS_RSA_PUBLIC. Future versions of the libary
 *                 are likely to remove the mode argument and have it implicitly
 *                 set to MBEDTLS_RSA_PRIVATE.
 *
 * \note           Alternative implementations of RSA need not support
 *                 mode being set to MBEDTLS_RSA_PUBLIC and may instead
 *                 return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION.
 *
 * \return         0 if successful, or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The output buffer length \c output_max_len should be
 *                 as large as the size \c ctx->len of \c ctx->N (eg. 128 bytes
 *                 if RSA-1024 is used) to be able to hold an arbitrary
 *                 decrypted message. If it is not large enough to hold
 *                 the decryption of the particular ciphertext provided,
 *                 the function will return \c MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE.
 *
 * \note           The input buffer must be as large as the size
 *                 of \c ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 */
int mbedtls_rsa_rsaes_oaep_decrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t *olen,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t output_max_len );

/**
 * \brief          Encode a hash into a DigestInfo structure as specified
 *                 by PKCS#1 (RFC 8017, EMSA-PKCS1-v1_5-ENCODE step 2).
 *                 Note: function works backwards in data buffer.
 *
 * \param p        Reference to the current position pointer
 * \param start    Start of the buffer (for bounds checking)
 * \param md_alg   Digest algorithm
 * \param hash     Hash value
 * \param hashlen  Length of the hash, or 0 to calculate it from \c md_alg
 *
 * \note           This function writes from right to left: the start of the
 *                 written data is the value of \c *p on exit, and the end of
 *                 the written data is the value of \c *p on entry.
 *
 * \note           If \c md_alg is \c MBEDTLS_MD_NONE, this function just
 *                 copies \c hashlen bytes to the left of \c *p.
 */
int mbedtls_rsa_emsa_pkcs1_v15_encode_digestinfo( unsigned char **p,
                                                  unsigned char *start,
                                                  mbedtls_md_type_t md_alg,
                                                  const unsigned char *hash,
                                                  size_t hashlen );

/** Maximum size of the output of
 * mbedtls_rsa_emsa_pkcs1_v15_encode_digestinfo()  */
#define MBEDTLS_RSA_PKCS1_DIGESTINFO_MAX_SIZE   \
    ( MBEDTLS_MD_MAX_SIZE +                     \
      MBEDTLS_MD_OID_MAX_SIZE +                 \
      10 /*additional encoding bytes*/ )
/**
 * \brief          Generic wrapper to perform a PKCS#1 signature using the
 *                 mode from the context. Do a private RSA operation to sign
 *                 a message digest
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for PKCS#1 v2.1 encoding and for
 *                               \c MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     \c MBEDTLS_RSA_PUBLIC or \c MBEDTLS_RSA_PRIVATE
 * \param md_alg   a \c MBEDTLS_MD_XXX (use \c MBEDTLS_MD_NONE for
 *                 signing raw data)
 * \param hashlen  message digest length (for \c MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer that will hold the ciphertext
 *
 * \deprecated     It is deprecated and discouraged to call this function
 *                 in mode MBEDTLS_RSA_PUBLIC. Future versions of the libary
 *                 are likely to remove the mode argument and have it implicitly
 *                 set to MBEDTLS_RSA_PRIVATE.
 *
 * \note           Alternative implementations of RSA need not support
 *                 mode being set to MBEDTLS_RSA_PUBLIC and may instead
 *                 return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION.
 *
 * \return         0 if the signing operation was successful,
 *                 or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The \c sig buffer must be as large as the size
 *                 of \c ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           In case of PKCS#1 v2.1 encoding, see comments on
 *                 \c mbedtls_rsa_rsassa_pss_sign() for details on
 *                 \c md_alg and \c hash_id.
 */
int mbedtls_rsa_pkcs1_sign( mbedtls_rsa_context *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    int mode,
                    mbedtls_md_type_t md_alg,
                    unsigned int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v1.5 signature (RSASSA-PKCS1-v1_5-SIGN)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Only needed for \c MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     \c MBEDTLS_RSA_PUBLIC or \c MBEDTLS_RSA_PRIVATE
 * \param md_alg   a \c MBEDTLS_MD_XXX (use \c MBEDTLS_MD_NONE
 *                 for signing raw data)
 * \param hashlen  message digest length (for \c MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer that will hold the ciphertext
 *
 * \deprecated     It is deprecated and discouraged to call this function
 *                 in mode MBEDTLS_RSA_PUBLIC. Future versions of the libary
 *                 are likely to remove the mode argument and have it implicitly
 *                 set to MBEDTLS_RSA_PRIVATE.
 *
 * \note           Alternative implementations of RSA need not support
 *                 mode being set to MBEDTLS_RSA_PUBLIC and may instead
 *                 return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION.
 *
 * \return         0 if the signing operation was successful,
 *                 or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The \c sig buffer must be as large as the size
 *                 of \c ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int mbedtls_rsa_rsassa_pkcs1_v15_sign( mbedtls_rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               int mode,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v2.1 PSS signature (RSASSA-PSS-SIGN)
 *
 * \param ctx      RSA context
 * \param f_rng    RNG function (Needed for PKCS#1 v2.1 encoding and for
 *                               \c MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     \c MBEDTLS_RSA_PUBLIC or \c MBEDTLS_RSA_PRIVATE
 * \param md_alg   a \c MBEDTLS_MD_XXX (use \c MBEDTLS_MD_NONE
 *                 for signing raw data)
 * \param hashlen  message digest length (for \c MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer that will hold the ciphertext
 *
 * \deprecated     It is deprecated and discouraged to call this function
 *                 in mode MBEDTLS_RSA_PUBLIC. Future versions of the libary
 *                 are likely to remove the mode argument and have it implicitly
 *                 set to MBEDTLS_RSA_PRIVATE.
 *
 * \note           Alternative implementations of RSA need not support
 *                 mode being set to MBEDTLS_RSA_PUBLIC and may instead
 *                 return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION.
 *
 * \return         0 if the signing operation was successful,
 *                 or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The \c sig buffer must be as large as the size
 *                 of \c ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           The \c hash_id in the RSA context is the one used for the
 *                 encoding. \c md_alg in the function call is the type of hash
 *                 that is encoded. According to RFC 3447 it is advised to
 *                 keep both hashes the same.
 */
int mbedtls_rsa_rsassa_pss_sign( mbedtls_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         int mode,
                         mbedtls_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         unsigned char *sig );

/**
 * \brief          Generic wrapper to perform a PKCS#1 verification using the
 *                 mode from the context. Do a public RSA operation and check
 *                 the message digest
 *
 * \param ctx      points to an RSA public key
 * \param f_rng    RNG function (Only needed for \c MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     \c MBEDTLS_RSA_PUBLIC or \c MBEDTLS_RSA_PRIVATE
 * \param md_alg   a \c MBEDTLS_MD_XXX (use \c MBEDTLS_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for \c MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer holding the ciphertext
 *
 * \deprecated     It is deprecated and discouraged to call this function
 *                 in mode MBEDTLS_RSA_PRIVATE. Future versions of the libary
 *                 are likely to remove the mode argument and have it implicitly
 *                 set to MBEDTLS_RSA_PUBLIC.
 *
 * \note           Alternative implementations of RSA need not support
 *                 mode being set to MBEDTLS_RSA_PRIVATE and may instead
 *                 return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION.
 *
 * \return         0 if the verify operation was successful,
 *                 or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The \c sig buffer must be as large as the size
 *                 of \c ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           In case of PKCS#1 v2.1 encoding, see comments on
 *                 \c mbedtls_rsa_rsassa_pss_verify() about md_alg and hash_id.
 */
int mbedtls_rsa_pkcs1_verify( mbedtls_rsa_context *ctx,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng,
                      int mode,
                      mbedtls_md_type_t md_alg,
                      unsigned int hashlen,
                      const unsigned char *hash,
                      const unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v1.5 verification (RSASSA-PKCS1-v1_5-VERIFY)
 *
 * \param ctx      points to an RSA public key
 * \param f_rng    RNG function (Only needed for \c MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     \c MBEDTLS_RSA_PUBLIC or \c MBEDTLS_RSA_PRIVATE
 * \param md_alg   a \c MBEDTLS_MD_XXX (use \c MBEDTLS_MD_NONE
 *                 for signing raw data)
 * \param hashlen  message digest length (for \c MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer holding the ciphertext
 *
 * \deprecated     It is deprecated and discouraged to call this function
 *                 in mode MBEDTLS_RSA_PRIVATE. Future versions of the libary
 *                 are likely to remove the mode argument and have it implicitly
 *                 set to MBEDTLS_RSA_PUBLIC.
 *
 * \note           Alternative implementations of RSA need not support
 *                 mode being set to MBEDTLS_RSA_PRIVATE and may instead
 *                 return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION.
 *
 * \return         0 if the verify operation was successful,
 *                 or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The \c sig buffer must be as large as the size
 *                 of \c ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int mbedtls_rsa_rsassa_pkcs1_v15_verify( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode,
                                 mbedtls_md_type_t md_alg,
                                 unsigned int hashlen,
                                 const unsigned char *hash,
                                 const unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v2.1 PSS verification (RSASSA-PSS-VERIFY)
 *                 (This is the "simple" version.)
 *
 * \param ctx      points to an RSA public key
 * \param f_rng    RNG function (Only needed for \c MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     \c MBEDTLS_RSA_PUBLIC or \c MBEDTLS_RSA_PRIVATE
 * \param md_alg   a \c MBEDTLS_MD_XXX (use \c MBEDTLS_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for \c MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer holding the ciphertext
 *
 * \deprecated     It is deprecated and discouraged to call this function
 *                 in mode MBEDTLS_RSA_PRIVATE. Future versions of the libary
 *                 are likely to remove the mode argument and have it implicitly
 *                 set to MBEDTLS_RSA_PUBLIC.
 *
 * \note           Alternative implementations of RSA need not support
 *                 mode being set to MBEDTLS_RSA_PRIVATE and may instead
 *                 return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION.
 *
 * \return         0 if the verify operation was successful,
 *                 or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The \c sig buffer must be as large as the size
 *                 of \c ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           The \c hash_id in the RSA context is the one used for the
 *                 verification. \c md_alg in the function call is the type of
 *                 hash that is verified. According to RFC 3447 it is advised to
 *                 keep both hashes the same. If \c hash_id in the RSA context is
 *                 unset, the \c md_alg from the function call is used.
 */
int mbedtls_rsa_rsassa_pss_verify( mbedtls_rsa_context *ctx,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng,
                           int mode,
                           mbedtls_md_type_t md_alg,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           const unsigned char *sig );

/**
 * \brief          Perform a PKCS#1 v2.1 PSS verification (RSASSA-PSS-VERIFY)
 *                 (This is the version with "full" options.)
 *
 * \param ctx      points to an RSA public key
 * \param f_rng    RNG function (Only needed for \c MBEDTLS_RSA_PRIVATE)
 * \param p_rng    RNG parameter
 * \param mode     \c MBEDTLS_RSA_PUBLIC or \c MBEDTLS_RSA_PRIVATE
 * \param md_alg   a \c MBEDTLS_MD_XXX (use \c MBEDTLS_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for \c MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param mgf1_hash_id message digest used for mask generation
 * \param expected_salt_len Length of the salt used in padding, use
 *                 \c MBEDTLS_RSA_SALT_LEN_ANY to accept any salt length
 * \param sig      buffer holding the ciphertext
 *
 * \return         0 if the verify operation was successful,
 *                 or an \c MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The \c sig buffer must be as large as the size
 *                 of \c ctx->N (eg. 128 bytes if RSA-1024 is used).
 *
 * \note           The \c hash_id in the RSA context is ignored.
 */
int mbedtls_rsa_rsassa_pss_verify_ext( mbedtls_rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               int mode,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               mbedtls_md_type_t mgf1_hash_id,
                               int expected_salt_len,
                               const unsigned char *sig );

/**
 * \brief          Copy the components of an RSA context
 *
 * \param dst      Destination context
 * \param src      Source context
 *
 * \return         0 on success,
 *                 \c MBEDTLS_ERR_MPI_ALLOC_FAILED on memory allocation failure
 */
int mbedtls_rsa_copy( mbedtls_rsa_context *dst, const mbedtls_rsa_context *src );

/**
 * \brief          Free the components of an RSA key
 *
 * \param ctx      RSA Context to free
 */
void mbedtls_rsa_free( mbedtls_rsa_context *ctx );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_RSA_ALT */
#include "rsa_alt.h"
#endif /* MBEDTLS_RSA_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_rsa_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* rsa.h */
