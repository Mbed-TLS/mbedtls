/**
 * \file pkcs11_client.h
 *
 * \brief Generic wrapper for Cryptoki (PKCS#11) support
 *
 *  Copyright (C) 2017, ARM Limited, All Rights Reserved
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
#ifndef MBEDTLS_PKCS11_CLIENT_H
#define MBEDTLS_PKCS11_CLIENT_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PKCS11_CLIENT_C)

#include <pkcs11.h>

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_PKCS11_FLAG_TOKEN    ( (uint32_t) 0x80000000 )

#if defined(MBEDTLS_PK_C)

#define MBEDTLS_PK_FLAG_SENSITIVE    ( (uint32_t) 0x00000001 )
#define MBEDTLS_PK_FLAG_EXTRACTABLE  ( (uint32_t) 0x00000002 )
#define MBEDTLS_PK_FLAG_SIGN         ( (uint32_t) 0x00000010 )
#define MBEDTLS_PK_FLAG_VERIFY       ( (uint32_t) 0x00000020 )
#define MBEDTLS_PK_FLAG_DECRYPT      ( (uint32_t) 0x00000040 )
#define MBEDTLS_PK_FLAG_ENCRYPT      ( (uint32_t) 0x00000080 )

#include "pk.h"

/**
 * \brief               Set up a PK context for a key pair in a PKCS#11 token
 *
 * \param ctx           PK context to fill, which must have been initialized
 *                      with mbedtls_pk_init().
 * \param hSession      Cryptoki session.
 * \param hPublicKey    Cryptoki handle of the public key.
 * \param hPrivateKey   Cryptoki handle of the private key, or
 *                      CK_INVALID_HANDLE for a public key rather than a key
 *                      pair.
 *
 * \return              0 on success,
 *                      or MBEDTLS_ERR_PK_XXX error code.
 *
 * \note                The session and the key(s) must remain valid until the
 *                      PK context is closed with mbedtls_pk_free(). As an
 *                      exception, it's ok to call mbedtls_pk_free() itself
 *                      even if the Cryptoki handles have become invalid.
 */
int mbedtls_pk_setup_pkcs11( mbedtls_pk_context *ctx,
                             CK_SESSION_HANDLE hSession,
                             CK_OBJECT_HANDLE hPublicKey,
                             CK_OBJECT_HANDLE hPrivateKey );

/**
 * \brief               Import a transparent key into a PKCS#11 token
 *
 *                      This function imports a PK object containing a
 *                      public key or a private-public key pair into a
 *                      PKCS#11 token. 
 *
 * \param ctx           PK context, which must contain a transparent pk
 *                      object (type \c MBEDTLS_PK_RSA,
 *                      \c MBEDTLS_PK_RSASSA_PSS, \c MBEDTLS_PK_ECKEY or
 *                      \c MBEDTLS_PK_ECDSA).
 * \param flags         Mask of \c MBEDTLS_PKCS11_FLAG_XXX and
 *                      \c MBEDTLS_PK_FLAG_XXX, applying as follows:
 *                      - \c MBEDTLS_PKCS11_FLAG_TOKEN: PKCS#11 \c CKA_TOKEN
 *                        flag: if set, import as token object; if clear,
 *                        import as session object.
 *                      - \c MBEDTLS_PK_FLAG_EXTRACTABLE: PKCS#11
 *                        \c CKA_EXTRACTABLE flag: if set, the key will be
 *                        extractable at least in wrapped form; if clear,
 *                        the key will not be extractable at all.
 *                      - \c MBEDTLS_PK_FLAG_SENSITIVE: PKCS#11
 *                        \c CKA_SENSITIVE flag: if set, the key will be
 *                        not be extractable in plain form; if clear, the
 *                        key will be extractable at least in wrapped form.
 *                      - \c MBEDTLS_PK_FLAG_SIGN: if set, the private key
 *                        will be authorized for signing.
 *                      - \c MBEDTLS_PK_FLAG_VERIFY: if set, the public key
 *                        will be authorized for verification.
 *                      - \c MBEDTLS_PK_FLAG_DECRYPT: if set, the private key
 *                        will be authorized for signing.
 *                      - \c MBEDTLS_PK_FLAG_ENCRYPT: if set, the public key
 *                        will be authorized for encryption.
 *
 * \param hSession      Cryptoki session.
 * \param hPublicKey    If non-null, on output, Cryptoki handle of the public
 *                      key. If null, the public key is not imported.
 * \param hPrivateKey   If non-null, on output, Cryptoki handle of the private
 *                      key. If null, the private key is not imported.
 *
 * \return              0 on success,
 *                      or MBEDTLS_ERR_PK_XXX error code.
 *
 * \note                If \c hPrivateKey is non-null then \c ctx must contain
 *                      a full key pair. If \c hPrivateKey is null then \c ctx
 *                      may contain a full key pair or just a public key.
 *
 * \note                On failure, the values returned in \c hPublicKey and
 *                      \c hPrivateKey will normally be \c CK_HANDLE_INVALID.
 *                      One of them may be a valid handle in the unlikely case
 *                      where the creation of one key object succeeded but
 *                      the second one failed and destroying the first one
 *                      also failed, for example because the token was
 *                      disconnected.
 */
int mbedtls_pk_import_to_pkcs11( const mbedtls_pk_context *ctx,
                                 uint32_t flags,
                                 CK_SESSION_HANDLE hSession,
                                 CK_OBJECT_HANDLE *hPublicKey,
                                 CK_OBJECT_HANDLE *hPrivateKey );

#endif /* MBEDTLS_PK_C */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PKCS11_CLIENT_C */

#endif /* MBEDTLS_PKCS11_H */
