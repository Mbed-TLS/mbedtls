/*
 * Copyright 2019-2021 Stephen Farrell. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 *  Copyright The Mbed TLS Contributors
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
 *  This code is based on https://github.com/sftcd/happykey
 *  Special thanks goes to Stephen Farrell for his support and the permission
 *  to re-use the code in Mbed TLS. 
 * 
 */
 
#ifndef HPKE_H_INCLUDED
#define HPKE_H_INCLUDED

#include "mbedtls/build_info.h"

#include "psa/crypto.h"
#include <stdint.h>
#include <stdio.h>

/*
 * The HPKE modes
 */
#define HPKE_MODE_BASE              0 ///< Base mode 
#define HPKE_MODE_PSK               1 ///< Pre-shared key mode
#define HPKE_MODE_AUTH              2 ///< Authenticated mode
#define HPKE_MODE_PSKAUTH           3 ///< PSK+authenticated mode

/*
 * The (16bit) HPKE algorithn IDs
 */
#define HPKE_KEM_ID_RESERVED         0x0000 ///< not used
#define HPKE_KEM_ID_P256             0x0010 ///< NIST P-256
#define HPKE_KEM_ID_P384             0x0011 ///< NIST P-256
#define HPKE_KEM_ID_P521             0x0012 ///< NIST P-521
#define HPKE_KEM_ID_25519            0x0020 ///< Curve25519
#define HPKE_KEM_ID_448              0x0021 ///< Curve448

#define HPKE_KDF_ID_RESERVED         0x0000 ///< not used
#define HPKE_KDF_ID_HKDF_SHA256      0x0001 ///< HKDF-SHA256
#define HPKE_KDF_ID_HKDF_SHA384      0x0002 ///< HKDF-SHA512
#define HPKE_KDF_ID_HKDF_SHA512      0x0003 ///< HKDF-SHA512
#define HPKE_KDF_ID_MAX              0x0003 ///< HKDF-SHA512

#define HPKE_AEAD_ID_RESERVED        0x0000 ///< not used
#define HPKE_AEAD_ID_AES_GCM_128     0x0001 ///< AES-GCM-128
#define HPKE_AEAD_ID_AES_GCM_256     0x0002 ///< AES-GCM-256
#define HPKE_AEAD_ID_CHACHA_POLY1305 0x0003 ///< Chacha20-Poly1305
#define HPKE_AEAD_ID_MAX             0x0003 ///< Chacha20-Poly1305

/* strings for modes */
#define HPKE_MODESTR_BASE       "base"              ///< base mode (1), no sender auth
#define HPKE_MODESTR_PSK        "psk"               ///< psk mode (2)
#define HPKE_MODESTR_AUTH       "auth"              ///< auth (3), with a sender-key pair
#define HPKE_MODESTR_PSKAUTH    "pskauth"           ///< psk+sender-key pair (4)

/* strings for suites */
#define HPKE_KEMSTR_P256        "p256"              ///< KEM id 0x10
#define HPKE_KEMSTR_P384        "p384"              ///< KEM id 0x11
#define HPKE_KEMSTR_P521        "p521"              ///< KEM id 0x12
#define HPKE_KEMSTR_X25519      "x25519"            ///< KEM id 0x20
#define HPKE_KEMSTR_X448        "x448"              ///< KEM id 0x21
#define HPKE_KDFSTR_256         "hkdf-sha256"       ///< KDF id 1
#define HPKE_KDFSTR_384         "hkdf-sha384"       ///< KDF id 2
#define HPKE_KDFSTR_512         "hkdf-sha512"       ///< KDF id 3
#define HPKE_AEADSTR_AES128GCM  "aes128gcm"         ///< AEAD id 1
#define HPKE_AEADSTR_AES256GCM  "aes256gcm"         ///< AEAD id 2
#define HPKE_AEADSTR_CP         "chachapoly1305"    ///< AEAD id 3



/**
 *  \name HPKE Error codes
 *  \{
 */
#define MBEDTLS_ERR_HPKE_BAD_INPUT_DATA    -0x5F81  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_HPKE_INTERNAL_ERROR    -0x5F82  /**< Internal error. */
#define MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL  -0x5F83  /**< Buffer too small. */
/* \} name */


/*!
 * \brief ciphersuite combination
 */
typedef struct {
    uint16_t    kem_id; ///< Key Encryption Method id
    uint16_t    kdf_id; ///< Key Derivation Function id
    uint16_t    aead_id; ///< Authenticated Encryption with Associated Data id
} hpke_suite_t;

/*!
 * Two suite constants, use this like: 
 *
 *          hpke_suite_t myvar = HPKE_SUITE_DEFAULT;
 */
#define HPKE_SUITE_DEFAULT { HPKE_KEM_ID_P256, HPKE_KDF_ID_HKDF_SHA256, HPKE_AEAD_ID_AES_GCM_128 }
#define HPKE_SUITE_TURNITUPTO11 { HPKE_KEM_ID_448, HPKE_KDF_ID_HKDF_SHA512, HPKE_AEAD_ID_CHACHA_POLY1305 }


/*!
 * \brief  Map ascii to binary - utility macro used in >1 place 
 */
#define HPKE_A2B(__c__) (__c__>='0'&&__c__<='9'?(__c__-'0'):\
                        (__c__>='A'&&__c__<='F'?(__c__-'A'+10):\
                        (__c__>='a'&&__c__<='f'?(__c__-'a'+10):0)))

/*
 * \brief HPKE single-shot encryption function
 *
 * \param mode is the HPKE mode
 * \param suite is the ciphersuite to use
 * \param pskid is the pskid string fpr a PSK mode (can be NULL)
 * \param psklen is the psk length
 * \param psk is the psk 
 * \param publen is the length of the public key
 * \param pub is the encoded public key
 * \param privlen is the length of the private (authentication) key
 * \param priv is the encoded private (authentication) key
 * \param clearlen is the length of the cleartext
 * \param clear is the encoded cleartext
 * \param aadlen is the lenght of the additional data
 * \param aad is the encoded additional data
 * \param infolen is the lenght of the info data (can be zero)
 * \param info is the encoded info data (can be NULL)
 * \param senderpublen is the length of the input buffer for the sender's public key (length used on output)
 * \param senderpub is the input buffer for sender public key
 * \param cipherlen is the length of the input buffer for ciphertext (length used on output)
 * \param cipher is the input buffer for ciphertext
 * \return 1 for good (OpenSSL style), not-1 for error
 *
 * Oddity: we're passing an hpke_suit_t directly, but 48 bits is actually
 * smaller than a 64 bit pointer, so that's grand, if odd:-)
 */
int mbedtls_hpke_encrypt( unsigned int mode, hpke_suite_t suite,
                          char *pskid, size_t psklen, uint8_t *psk,
                          size_t pkR_len, uint8_t *pkR,
                          psa_key_handle_t skI_handle,
                          size_t clearlen, uint8_t *clear,
                          size_t aadlen, uint8_t *aad,
                          size_t infolen, uint8_t *info,
                          psa_key_handle_t ext_skE_handle,
                          size_t *pkE_len, uint8_t *pkE,
                          size_t *cipherlen, uint8_t *cipher );


#if defined(MBEDTLS_SSL_DEBUG_ALL)
/*!
 * \brief for odd/occasional debugging
 *
 * \param fout is a FILE * to use
 * \param msg is prepended to print
 * \param buf is the buffer to print
 * \param blen is the length of the buffer
 * \return 1 for success 
 */

int hpke_pbuf(FILE *fout, char *msg,unsigned char *buf,size_t blen);
#endif


/*
 * \brief HPKE single-shot decryption function
 * \param mode is the HPKE mode
 * \param suite is the ciphersuite to use
 * \param pskid is the pskid string fpr a PSK mode (can be NULL)
 * \param psklen is the psk length
 * \param psk is the psk 
 * \param publen is the length of the public (authentication) key
 * \param pub is the encoded public (authentication) key
 * \param privlen is the length of the private key
 * \param priv is the encoded private key
 * \param evppriv is a pointer to an internal form of private key
 * \param enclen is the length of the peer's public value
 * \param enc is the peer's public value
 * \param cipherlen is the length of the ciphertext 
 * \param cipher is the ciphertext
 * \param aadlen is the lenght of the additional data
 * \param aad is the encoded additional data
 * \param infolen is the lenght of the info data (can be zero)
 * \param info is the encoded info data (can be NULL)
 * \param clearlen is the length of the input buffer for cleartext (octets used on output)
 * \param clear is the encoded cleartext
 * \return 1 for good (OpenSSL style), not-1 for error
 */

int mbedtls_hpke_decrypt( unsigned int mode, hpke_suite_t suite,
                          char *pskid, size_t psklen, unsigned char *psk,
                          size_t pkS_len, unsigned char *pkS,
                          psa_key_handle_t skR_handle,
                          size_t pkE_len, unsigned char *pkE,
                          size_t cipherlen, unsigned char *cipher,
                          size_t aadlen, unsigned char *aad,
                          size_t infolen, unsigned char *info,
                          size_t *clearlen, unsigned char *clear );

/**
 * \brief decode ascii hex to a binary buffer
 *
 * \param ahlen is the ascii hex string length
 * \param ah is the ascii hex string
 * \param blen is a pointer to the returned binary length
 * \param buf is a pointer to the internally allocated binary buffer
 * \return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_ah_decode(size_t ahlen, const char *ah, size_t *blen, unsigned char **buf);

/**
 * \brief check if a suite is supported locally
 *
 * \param suite is the suite to check
 * \return 1 for good/supported, not-1 otherwise
 */
int hpke_suite_check(hpke_suite_t suite);

/*
 * These are temporary and only needed for esni-draft-09
 * where we gotta call 'em from outside
 */


/*
 * 5869 modes for func below
 */
#define HPKE_5869_MODE_KEM  1 ///< Abide by HPKE section 4.1
#define HPKE_5869_MODE_FULL 2 ///< Abide by HPKE section 5.1


/*!
 * \brief map a strin to a HPKE suite
 *
 * \param str is the string value
 * \param suite is the resulting suite
 * \return 1 for success, otherwise failure
 */ 
int hpke_str2suite(char *str, hpke_suite_t *suite);


#define MBEDTLS_SSL_HPKE_LABEL_LIST                           \
    MBEDTLS_SSL_HPKE_LABEL( version       , "HPKE-v1" )       \
    MBEDTLS_SSL_HPKE_LABEL( kem           , "KEM" )           \
    MBEDTLS_SSL_HPKE_LABEL( hpke          , "HPKE" )          \
    MBEDTLS_SSL_HPKE_LABEL( eae_prk       , "eae_prk" )       \
    MBEDTLS_SSL_HPKE_LABEL( psk_id_hash   , "psk_id_hash" )   \
    MBEDTLS_SSL_HPKE_LABEL( info_hash     , "info_hash" )     \
    MBEDTLS_SSL_HPKE_LABEL( shared_secret , "shared_secret" ) \
    MBEDTLS_SSL_HPKE_LABEL( base_nonce    , "base_nonce" )    \
    MBEDTLS_SSL_HPKE_LABEL( exp           , "exp" )           \
    MBEDTLS_SSL_HPKE_LABEL( key           , "key" )           \
    MBEDTLS_SSL_HPKE_LABEL( psk_hash      , "psk_hash" )      \
    MBEDTLS_SSL_HPKE_LABEL( secret        , "secret" )

#define MBEDTLS_SSL_HPKE_LABEL( name, string )       \
    const char name    [ sizeof(string) - 1 ];

union mbedtls_ssl_hpke_labels_union
{
    MBEDTLS_SSL_HPKE_LABEL_LIST
};
struct mbedtls_ssl_hpke_labels_struct
{
    MBEDTLS_SSL_HPKE_LABEL_LIST
};
#undef MBEDTLS_SSL_HPKE_LABEL

extern const struct mbedtls_ssl_hpke_labels_struct mbedtls_ssl_hpke_labels;


#define MBEDTLS_SSL_HPKE_LBL_WITH_LEN( LABEL )  \
    mbedtls_ssl_hpke_labels.LABEL,              \
    sizeof(mbedtls_ssl_hpke_labels.LABEL)

#define MBEDTLS_SSL_HPKE_MAX_LABEL_LEN  \
    sizeof( union mbedtls_ssl_hpke_labels_union )

/**
 *  \brief  HPKE Extract
 *
 *  \param  suite        Ciphersuite
 *  \param  mode5869     Controls labelling specifics
 *  \param  salt         Salt
 *  \param  saltlen      Length of above
 *  \param  label        Label for separation
 *  \param  labellen     Length of above
 *  \param  zz           The initial key material (IKM)
 *  \param  zzlen        Length of above
 *  \param  secret       The result of extraction
 *  \param  secretlen    Bufsize on input, used size on output
 *
 *  \return 0 on success.
 *  \return #MBEDTLS_ERR_HKDF_BAD_INPUT_DATA when the parameters are invalid.
 *  \return An MBEDTLS_ERR_MD_* error for errors returned from the underlying
 *          MD layer.
 *  \return #MBEDTLS_ERR_HPKE_INTERNAL_ERROR for unexpected errors related to 
 *          HPKE processin
 *  \return #MBEDTLS_ERR_HPKE_BAD_INPUT_DATA when the parameters to the HPKE
 *          layer are invalid.
 *
 *  Note: Mode can be:
 * 
 * - HPKE_5869_MODE_KEM meaning to follow section 4.1
 *   where the suite_id is used as:
 *   concat("KEM", I2OSP(kem_id, 2))
 * 
 * - HPKE_5869_MODE_FULL meaning to follow section 5.1
 *   where the suite_id is used as:
 *   concat("HPKE",I2OSP(kem_id, 2),
 *          I2OSP(kdf_id, 2), I2OSP(aead_id, 2))
 */
int mbedtls_hpke_extract( const hpke_suite_t suite,
                          const size_t mode5869,
                          const unsigned char *salt, const size_t saltlen,
                          const char *label, const size_t labellen,
                          const unsigned char *ikm, const size_t ikmlen,
                          unsigned char *secret, size_t *secretlen );


/*!
 * \brief RFC5869 HKDF-Expand
 *
 * \param suite is the ciphersuite 
 * \param mode5869 - controls labelling specifics
 * \param prk - the initial pseudo-random key material 
 * \param prk - length of above
 * \param label - label to prepend to info
 * \param labellen - label to prepend to info
 * \param context - the info
 * \param contextlen - length of above
 * \param L - the length of the output desired 
 * \param out - the result of expansion (allocated by caller)
 * \param outlen - buf size on input
 * \return 1 for good otherwise bad
 */
int mbedtls_hpke_expand(const hpke_suite_t suite, const int mode5869, 
                const unsigned char *prk, const size_t prklen,
                const char *label, const size_t labellen,
                const unsigned char *info, const size_t infolen,
                const uint32_t L,
                unsigned char *out, size_t *outlen);

/*!
 * \brief ExtractAndExpand
 * \param suite is the ciphersuite 
 * \param mode5869 - controls labelling specifics
 * \param shared_secret - the initial DH shared secret
 * \param shared_secretlen - length of above
 * \param context - the info
 * \param contextlen - length of above
 * \param secret - the result of extract&expand
 * \param secretlen - buf size on input
 * \return 1 for good otherwise bad
 */
int mbedtls_hpke_extract_and_expand(hpke_suite_t suite, int mode5869,
                                    unsigned char *shared_secret , size_t shared_secretlen,
                                    unsigned char *context, size_t contextlen,
                                    unsigned char *secret, size_t *secretlen );

#endif

