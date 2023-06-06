/**
 * \file
 * MbedTLS-based HPKE implementation following draft-irtf-cfrg-hpke
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
#include "common.h"

#if defined(MBEDTLS_HPKE_C)

#include "mbedtls/md.h"
#include <stddef.h>
#include <string.h>
#include "mbedtls/error.h"

#include "mbedtls/hpke.h"
#include "mbedtls/hkdf.h"

#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#endif


#ifdef _MSC_VER
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

/*!
 * \brief info about an AEAD
 */
typedef struct {
    uint16_t            aead_id; ///< code point for aead alg
    size_t              taglen; ///< aead tag len
    size_t              Nk; ///< size of a key for this aead
    size_t              Nn; ///< length of a nonce for this aead
} hpke_aead_info_t;

/*!
 * \brief table of AEADs
 */
static hpke_aead_info_t hpke_aead_tab[]={
    { 0, 0, 0, 0 }, // this is needed to keep indexing correct
    { HPKE_AEAD_ID_AES_GCM_128, 16, 16, 12 },
    { HPKE_AEAD_ID_AES_GCM_256, 16, 32, 12 },
    { HPKE_AEAD_ID_CHACHA_POLY1305, 16, 32, 12 }
};

/*!
 * \brief info about a KEM
 */
typedef struct {
    uint16_t            kem_id; ///< code point for key encipherment method
    const char          *keytype; ///< string form of algorithm type "EC"/"X25519"/"X448"
    const char          *groupname; ///< string form of EC group needed for NIST curves "P-256"/"p-384"/"p-521"
    int                 groupid; ///< NID of KEM
    size_t              Nsecret; ///< size of secrets
    size_t              Nenc; ///< length of encapsulated key
    size_t              Npk; ///< length of public key
    size_t              Npriv; ///< length of raw private key
} hpke_kem_info_t;

/*!
 * \brief table of KEMs
 *
 * Ok we're wasting space here, but not much and it's ok
 */

#define NID_X9_62_prime256v1 1
#define NID_secp384r1 2 
#define NID_secp521r1 3
#define EVP_PKEY_X25519 4 
#define EVP_PKEY_X448 5 

hpke_kem_info_t hpke_kem_tab[]={
    { 0, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    { 1, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    { 2, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    { 3, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    { 4, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    { 5, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    { 6, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    { 7, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    { 8, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    { 9, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {10, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {11, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {12, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {13, NULL, NULL, 0, 0, 0, 0, 0}, // this is needed to keep indexing correct
    {14, NULL, NULL, 0, 0, 0, 0, 0}, // this is needed to keep indexing correct
    {15, NULL, NULL, 0, 0, 0, 0, 0}, // this is needed to keep indexing correct
    { HPKE_KEM_ID_P256, "EC", "P-256", NID_X9_62_prime256v1, 32, 65, 65, 32 }, // maybe "prime256v1" instead of P-256?
    { HPKE_KEM_ID_P384, "EC", "P-384", NID_secp384r1, 48, 97, 97, 48 },
    { HPKE_KEM_ID_P521, "EC", "P-521", NID_secp521r1, 64, 133, 133, 66 },
    {19, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {20, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {21, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {22, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {23, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {24, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {25, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {26, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {27, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {28, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {29, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {30, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {31, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
    {HPKE_KEM_ID_25519, "X25519", NULL, EVP_PKEY_X25519, 32, 32, 32, 32 },
    {HPKE_KEM_ID_448, "X448", NULL, EVP_PKEY_X448, 64, 56, 56, 56 },
    {34, NULL, NULL, 0, 0, 0, 0, 0 }, // this is needed to keep indexing correct
};


/*!
 * \brief info about a KDF
 */
typedef struct {
    uint16_t            kdf_id; //< code point for KDF
    size_t              Nh;     //< length of hash/extract output
} hpke_kdf_info_t;

/*!
 * \brief table of KDFs
 */
static hpke_kdf_info_t hpke_kdf_tab[]={
    { 0, 0 }, // this is needed to keep indexing correct
    { HPKE_KDF_ID_HKDF_SHA256, 32 },
    { HPKE_KDF_ID_HKDF_SHA384, 48 },
    { HPKE_KDF_ID_HKDF_SHA512, 64 }
};

/*
 * \brief string matching for suites
 */
#define HPKE_MSMATCH(inp,known) (strlen(inp)==strlen(known) && !strcasecmp(inp,known))


#define MBEDTLS_SSL_HPKE_LABEL( name, string )       \
    .name = string,

struct mbedtls_ssl_hpke_labels_struct const mbedtls_ssl_hpke_labels =
{
    /* This seems to work in C, despite the string literal being one
     * character too long due to the 0-termination. */
    MBEDTLS_SSL_HPKE_LABEL_LIST
};

#define MBEDTLS_SSL_HPKE_5869_MODE_KEM_MAX_LABEL_LEN                \
                     sizeof( mbedtls_ssl_hpke_labels.kem ) +        \
                     MBEDTLS_MD_MAX_SIZE +                          \
                     sizeof( mbedtls_ssl_hpke_labels.version ) +    \
                     2 // size of kem_id

#define MBEDTLS_SSL_HPKE_5869_MODE_FULL_MAX_LABEL_LEN               \
                     MBEDTLS_SSL_HPKE_MAX_LABEL_LEN +               \
                     MBEDTLS_MD_MAX_SIZE +                          \
                     sizeof( mbedtls_ssl_hpke_labels.version ) +    \
                     6 // size of kem_id,kdf_id,aead_id

#define MBEDTLS_SSL_HPKE_LABEL_LEN( label_len, info_len ) \
    (   MBEDTLS_SSL_HPKE_5869_MODE_FULL_MAX_LABEL_LEN  +  \
      + label_len                                         \
      + info_len )

#define SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN                      \
    SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN(                             \
                     sizeof(tls1_3_label_prefix) +                      \
                     MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN,     \
                     MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )

#undef MBEDTLS_SSL_HPKE_LABEL

int mbedtls_hpke_extract(
        const hpke_suite_t suite,
        const size_t mode5869,
        const unsigned char *salt, const size_t saltlen,
        const char *label, const size_t labellen,
        const unsigned char *ikm, const size_t ikmlen,
        unsigned char *secret, size_t *secretlen )
{
    int ret;
    const mbedtls_md_info_t *md;
    mbedtls_md_type_t md_type;
    unsigned char labeled_ikmbuf[ MBEDTLS_SSL_HPKE_5869_MODE_FULL_MAX_LABEL_LEN ];
    unsigned char *labeled_ikm = labeled_ikmbuf;
    size_t labeled_ikmlen = 0;
    size_t concat_offset = 0;

    if( ikmlen > MBEDTLS_MD_MAX_SIZE )
    {
        return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    concat_offset = 0;

    // Add version
    memcpy( labeled_ikm, MBEDTLS_SSL_HPKE_LBL_WITH_LEN( version ) );
    concat_offset += sizeof( mbedtls_ssl_hpke_labels.version );

    switch( mode5869 )
    {
        case HPKE_5869_MODE_KEM:
 
            // Add kem label
            memcpy( labeled_ikm + concat_offset, MBEDTLS_SSL_HPKE_LBL_WITH_LEN( kem ) );
            concat_offset += sizeof( mbedtls_ssl_hpke_labels.kem );
            
            // Add kem_id
            labeled_ikm[concat_offset] = (unsigned char)( suite.kem_id >> 8 );
            concat_offset += 1;
            labeled_ikm[concat_offset] = (unsigned char)( suite.kem_id );
            concat_offset += 1;
            break;
        case HPKE_5869_MODE_FULL:

            // Add hpke label
            memcpy( labeled_ikm + concat_offset, MBEDTLS_SSL_HPKE_LBL_WITH_LEN( hpke ) );
            concat_offset += sizeof( mbedtls_ssl_hpke_labels.hpke );

            // Add kem_id
            labeled_ikm[concat_offset] = (unsigned char)( suite.kem_id >> 8 );
            concat_offset += 1;
            labeled_ikm[concat_offset] = (unsigned char)( suite.kem_id );
            concat_offset += 1;
            
            // Add kdf_id
            labeled_ikm[concat_offset] = (unsigned char)( suite.kdf_id >> 8 );
            concat_offset += 1;
            labeled_ikm[concat_offset] = (unsigned char)( suite.kdf_id );
            concat_offset += 1;
            
            // Add aead_id
            labeled_ikm[concat_offset] = (unsigned char)( suite.aead_id >> 8 );
            concat_offset += 1;
            labeled_ikm[concat_offset] = (unsigned char)( suite.aead_id );
            concat_offset += 1;
            break;
        default:
            return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    // Add label
    memcpy( labeled_ikm + concat_offset, label, labellen );
    concat_offset += labellen;

    // Add ikm
    if( ikmlen > 0 )
    {
        memcpy( labeled_ikm + concat_offset, ikm, ikmlen );
        concat_offset += ikmlen;
    }

    labeled_ikmlen = concat_offset;

    switch( suite.kdf_id )
    {
    case HPKE_KDF_ID_HKDF_SHA256:
        md_type = MBEDTLS_MD_SHA256;
        break;
    case HPKE_KDF_ID_HKDF_SHA384:
        md_type = MBEDTLS_MD_SHA384;
        break;
    case HPKE_KDF_ID_HKDF_SHA512:
        md_type = MBEDTLS_MD_SHA512;
        break;
    default:
        return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    md = mbedtls_md_info_from_type( md_type );
    
    if( md == NULL )
    {
        ret = MBEDTLS_ERR_HPKE_INTERNAL_ERROR;
        goto exit;
    }

    *secretlen = mbedtls_md_get_size( md );
    
    /* HKDF-Extract takes a salt and input key material.*/
    ret = mbedtls_hkdf_extract( md,
                                salt, saltlen,
                                labeled_ikm, labeled_ikmlen,
                                secret );

    if( ret != 0 )
    {
        goto exit;
    }

exit:
    mbedtls_platform_zeroize( labeled_ikmbuf, sizeof( labeled_ikmbuf ) );

    return( ret );
}

int mbedtls_hpke_expand( const hpke_suite_t suite, const int mode5869,
                         const unsigned char *prk, const size_t prklen,
                         const char *label, const size_t labellen,
                         const unsigned char *info, const size_t infolen,
                         const uint32_t L,
                         unsigned char *out, size_t *outlen)
{
    const mbedtls_md_info_t *md;
    mbedtls_md_type_t md_type;
    int ret;
    unsigned char *p; // Pointer to temporary buffer
    size_t concat_offset=0;
    size_t loutlen;

    if( L > *outlen )
    {
        return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    // Allocate temporary buffer
    p = mbedtls_calloc( 1, MBEDTLS_SSL_HPKE_LABEL_LEN( labellen, infolen ) );

    if( p == NULL )
    {
        return( MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL );
    }

    // Add expected output length
    p[0] = (unsigned char)( L >> 8 );
    p[1] = (unsigned char)( L );
    concat_offset=2;

    // Add version label
    memcpy( p + concat_offset, MBEDTLS_SSL_HPKE_LBL_WITH_LEN( version ) );
    concat_offset += sizeof( mbedtls_ssl_hpke_labels.version );

    // Add suit_id label
    if( mode5869 == HPKE_5869_MODE_KEM )
    {
        memcpy( p + concat_offset, MBEDTLS_SSL_HPKE_LBL_WITH_LEN( kem ) );
        concat_offset += sizeof( mbedtls_ssl_hpke_labels.kem );
    } 
    else if( mode5869 == HPKE_5869_MODE_FULL )
    {
        memcpy( p + concat_offset, MBEDTLS_SSL_HPKE_LBL_WITH_LEN( hpke ) );
        concat_offset += sizeof( mbedtls_ssl_hpke_labels.hpke );
    }
    else
    {
        return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    // Add kem_id
    p[ concat_offset ] = (unsigned char)( suite.kem_id >> 8 );
    concat_offset += 1;
    p[ concat_offset ] = (unsigned char)( suite.kem_id );
    concat_offset += 1;

    switch( mode5869 )
    {
        case HPKE_5869_MODE_KEM:
            memcpy( p + concat_offset, label, labellen );
            concat_offset += labellen;

            memcpy( p + concat_offset, info, infolen );
            concat_offset += infolen;
            break;

        case HPKE_5869_MODE_FULL:
            // Add kdf_id
            p[ concat_offset] = (unsigned char)( suite.kdf_id >> 8 );
            concat_offset += 1;
            p[ concat_offset] = (unsigned char)( suite.kdf_id );
            concat_offset += 1;

            // Add aead_id
            p[ concat_offset ] = (unsigned char)( suite.aead_id >> 8 );
            concat_offset += 1;
            p[ concat_offset ] = (unsigned char)( suite.aead_id );
            concat_offset += 1;

            // Add label
            memcpy( p + concat_offset, label, labellen );
            concat_offset += labellen;

            // Add info
            memcpy( p + concat_offset, info, infolen );
            concat_offset += infolen;
            break;

        default:
            return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    switch( suite.kdf_id )
    {
    case HPKE_KDF_ID_HKDF_SHA256:
        md_type = MBEDTLS_MD_SHA256;
        break;
    case HPKE_KDF_ID_HKDF_SHA384:
        md_type = MBEDTLS_MD_SHA384;
        break;
    case HPKE_KDF_ID_HKDF_SHA512:
        md_type = MBEDTLS_MD_SHA512;
        break;
    default:
        return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    md = mbedtls_md_info_from_type( md_type );
    
    if( md == NULL )
    {
        ret = MBEDTLS_ERR_HPKE_INTERNAL_ERROR;
        goto exit;
    }

    loutlen = L;

    ret = mbedtls_hkdf_expand( md,
                               prk, prklen,
                               p, concat_offset,
                               out, loutlen );

    if( ret != 0 )
    {
        goto exit;
    }

    *outlen = loutlen;

exit:
    mbedtls_free( p );
    return( ret );
}

int mbedtls_hpke_extract_and_expand( hpke_suite_t suite,
                                     int mode5869,
                                     unsigned char *shared_secret , size_t shared_secretlen,
                                     unsigned char *context, size_t contextlen,
                                     unsigned char *secret, size_t *secretlen )
{
    int res;
    unsigned char eae_prkbuf[MBEDTLS_MD_MAX_SIZE];
    size_t eae_prklen = MBEDTLS_MD_MAX_SIZE;
    size_t lsecretlen;

    switch( suite.kem_id)
    {
        case HPKE_KEM_ID_P256:
            lsecretlen = 32;
            break;
        case HPKE_KEM_ID_P384:
            lsecretlen = 48;
            break;
        case HPKE_KEM_ID_P521:
            lsecretlen = 64;
            break;
        default:
            return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    res = mbedtls_hpke_extract( suite, mode5869,
                                (unsigned char *) "", 0,
                                MBEDTLS_SSL_HPKE_LBL_WITH_LEN( eae_prk ),
                                shared_secret, shared_secretlen,
                                eae_prkbuf, &eae_prklen );

    if( res != 0 )
    {
        goto exit;
    }

    res = mbedtls_hpke_expand( suite, mode5869,
                               eae_prkbuf, eae_prklen,
                               MBEDTLS_SSL_HPKE_LBL_WITH_LEN( shared_secret ),
                               context, contextlen,
                               lsecretlen,
                               secret, &lsecretlen );

    if( res != 0 )
    {
        goto exit;
    }

    *secretlen = lsecretlen;

exit:
    mbedtls_platform_zeroize( eae_prkbuf, MBEDTLS_MD_MAX_SIZE );

    return( res );
}


/*!
 * \brief map a string to a HPKE suite
 *
 * \param str is the string value
 * \param suite is the resulting suite
 * \return 1 for success, otherwise failure
 */

int hpke_str2suite(char *suitestr, hpke_suite_t *suite)
{
    int erv=0;
    uint16_t kem=0,kdf=0,aead=0;
    if (!suite) return(__LINE__);

    // See if it contains a mix of our strings and numbers
    char *st=strtok(suitestr,",");
    if (!st) { erv=__LINE__; return erv; }
    while (st!=NULL) {
        // check if string is known or number and if so handle appropriately
        if (kem==0) {
            if (HPKE_MSMATCH(st,HPKE_KEMSTR_P256)) kem=HPKE_KEM_ID_P256;
            if (HPKE_MSMATCH(st,HPKE_KEMSTR_P384)) kem=HPKE_KEM_ID_P384;
            if (HPKE_MSMATCH(st,HPKE_KEMSTR_P521)) kem=HPKE_KEM_ID_P521;
            if (HPKE_MSMATCH(st,HPKE_KEMSTR_X25519)) kem=HPKE_KEM_ID_25519;
            if (HPKE_MSMATCH(st,HPKE_KEMSTR_X448)) kem=HPKE_KEM_ID_448;
            if (HPKE_MSMATCH(st,"0x10")) kem=HPKE_KEM_ID_P256;
            if (HPKE_MSMATCH(st,"16")) kem=HPKE_KEM_ID_P256;
            if (HPKE_MSMATCH(st,"0x11")) kem=HPKE_KEM_ID_P384;
            if (HPKE_MSMATCH(st,"17")) kem=HPKE_KEM_ID_P384;
            if (HPKE_MSMATCH(st,"0x12")) kem=HPKE_KEM_ID_P521;
            if (HPKE_MSMATCH(st,"18")) kem=HPKE_KEM_ID_P521;
            if (HPKE_MSMATCH(st,"0x20")) kem=HPKE_KEM_ID_25519;
            if (HPKE_MSMATCH(st,"32")) kem=HPKE_KEM_ID_25519;
            if (HPKE_MSMATCH(st,"0x21")) kem=HPKE_KEM_ID_448;
            if (HPKE_MSMATCH(st,"33")) kem=HPKE_KEM_ID_448;
        } else if (kem!=0 && kdf==0) {
            if (HPKE_MSMATCH(st,HPKE_KDFSTR_256)) kdf=1;
            if (HPKE_MSMATCH(st,HPKE_KDFSTR_384)) kdf=2;
            if (HPKE_MSMATCH(st,HPKE_KDFSTR_512)) kdf=3;
            if (HPKE_MSMATCH(st,"1")) kdf=1;
            if (HPKE_MSMATCH(st,"2")) kdf=2;
            if (HPKE_MSMATCH(st,"3")) kdf=3;
        } else if (kem!=0 && kdf!=0 && aead==0) {
            if (HPKE_MSMATCH(st,HPKE_AEADSTR_AES128GCM)) aead=1;
            if (HPKE_MSMATCH(st,HPKE_AEADSTR_AES256GCM)) aead=2;
            if (HPKE_MSMATCH(st,HPKE_AEADSTR_CP)) aead=3;
            if (HPKE_MSMATCH(st,"1")) aead=1;
            if (HPKE_MSMATCH(st,"2")) aead=2;
            if (HPKE_MSMATCH(st,"3")) aead=3;
        }
        st=strtok(NULL,",");
    }
    if (kem==0||kdf==0||aead==0) { erv=__LINE__; return erv; }
    suite->kem_id=kem;
    suite->kdf_id=kdf;
    suite->aead_id=aead;
    return 1;
}

/*!
 * \brief decode ascii hex to a binary buffer
 *
 * \param ahlen is the ascii hex string length
 * \param ah is the ascii hex string
 * \param blen is a pointer to the returned binary length
 * \param buf is a pointer to the internally allocated binary buffer
 * \return 1 for good otherwise bad
 */
int hpke_ah_decode(size_t ahlen, const char *ah, size_t *blen, unsigned char **buf)
{
    size_t lblen=0;
    unsigned char *lbuf=NULL;
    if (ahlen <=0 || ah==NULL || blen==NULL || buf==NULL) {
        return 0;
    }
    if (ahlen%1) {
        return 0;
    }
    lblen=ahlen/2;
    lbuf=mbedtls_calloc(1, lblen);
    if (lbuf==NULL) {
        return 0;
    }
    size_t i=0;
    for (i=0;i!=lblen;i++) {
        lbuf[i]=HPKE_A2B(ah[2*i])*16+HPKE_A2B(ah[2*i+1]);
    }
    *blen=lblen;
    *buf=lbuf;
    return 1;
}


/*!
 * \brief Internal function for AEAD decryption
 *
 * \param suite is the ciphersuite 
 * \param key is the secret
 * \param keylen is the length of the secret
 * \param iv is the initialisation vector
 * \param ivlen is the length of the iv
 * \param aad is the additional authenticated data
 * \param aadlen is the length of the aad
 * \param cipher is obvious
 * \param cipherlen is the ciphertext length
 * \param plain is an output
 * \param plainlen is an input/output, better be big enough on input, exact on output
 * \return 0 for good otherwise bad
 */
static int hpke_aead_dec(
            hpke_suite_t suite,
            unsigned char *key, size_t keylen,
            unsigned char *iv, size_t ivlen,
            unsigned char *aad, size_t aadlen,
            unsigned char *cipher, size_t cipherlen,
            unsigned char *plain, size_t *plainlen)
{
    psa_key_attributes_t attr_ciphertext = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;
    psa_algorithm_t mode;
    size_t key_length;
    psa_key_handle_t key_handle = 0;
    psa_key_type_t key_type;

    /* Initialize the PSA */
    status = psa_crypto_init( );

    if( status != PSA_SUCCESS )
    {
        return( status );
    }

    /* Decrypt ciphertext using the Content Encryption Key (CEK). */
    if ( ( suite.aead_id == HPKE_AEAD_ID_AES_GCM_256 ) ||
         ( suite.aead_id == HPKE_AEAD_ID_AES_GCM_128 ) )
    {
        mode = PSA_ALG_GCM;
        key_type = PSA_KEY_TYPE_AES;
    }
    else if (suite.aead_id == HPKE_AEAD_ID_CHACHA_POLY1305 )
    {
        mode = PSA_ALG_CHACHA20_POLY1305; 
        key_type = PSA_KEY_TYPE_CHACHA20; 
    }
    else return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );

    // key length are in bits
    key_length = hpke_aead_tab[suite.aead_id].Nk * 8;

    if( key_length != keylen * 8 )
    {
        return( MBEDTLS_ERR_HPKE_INTERNAL_ERROR );
    }

    psa_set_key_usage_flags( &attr_ciphertext, PSA_KEY_USAGE_DECRYPT );
    psa_set_key_algorithm( &attr_ciphertext, mode );
    psa_set_key_type( &attr_ciphertext, key_type );
    psa_set_key_bits( &attr_ciphertext, key_length );

    status = psa_import_key( &attr_ciphertext, key, key_length / 8, &key_handle );

    if ( status != PSA_SUCCESS )
    {
        return( status );
    }

    status = psa_aead_decrypt( key_handle,       // key
                               mode,             // algorithm
                               iv,               // iv
                               ivlen,            // iv length
                               aad,              // additional data
                               aadlen,           // additional data length
                               cipher,           // ciphertext
                               cipherlen,        // ciphertext length
                               plain, *plainlen, // plaintext
                               plainlen );       // length of output

    if ( status != PSA_SUCCESS )
    {
        return( status );
    }

    psa_destroy_key( key_handle );
    return( 0 );
}

static int hpke_aead_enc(
            hpke_suite_t suite,
            unsigned char *key, size_t keylen,
            unsigned char *iv, size_t ivlen,
            unsigned char *aad, size_t aadlen,
            unsigned char *plain, size_t plainlen,
            unsigned char *cipher, size_t *cipherlen )
{
    psa_key_attributes_t attr_ciphertext = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;
    psa_algorithm_t mode;
    size_t key_length;
    psa_key_handle_t key_handle = 0;
    psa_key_type_t key_type;

    /* Initialize the PSA */
    status = psa_crypto_init( );

    if( status != PSA_SUCCESS )
    {
        return( status );
    }

    if ( ( suite.aead_id == HPKE_AEAD_ID_AES_GCM_256 ) ||
         ( suite.aead_id == HPKE_AEAD_ID_AES_GCM_128 ) )
    {
        mode = PSA_ALG_GCM;
        key_type = PSA_KEY_TYPE_AES;
    }
    else if (suite.aead_id == HPKE_AEAD_ID_CHACHA_POLY1305 )
    {
        mode = PSA_ALG_CHACHA20_POLY1305; 
        key_type = PSA_KEY_TYPE_CHACHA20; 
    }
    else return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );

    // key length are in bits
    key_length = hpke_aead_tab[suite.aead_id].Nk * 8;

    if( key_length != keylen * 8 )
    {
        return( MBEDTLS_ERR_HPKE_INTERNAL_ERROR );
    }

    psa_set_key_usage_flags( &attr_ciphertext, PSA_KEY_USAGE_ENCRYPT );
    psa_set_key_algorithm( &attr_ciphertext, mode );
    psa_set_key_type( &attr_ciphertext, key_type );
    psa_set_key_bits( &attr_ciphertext, key_length );

    status = psa_import_key( &attr_ciphertext, key, key_length / 8, &key_handle );

    if ( status != PSA_SUCCESS )
    {
        return( status );
    }

    status = psa_aead_encrypt( key_handle,       // key
                               mode,             // algorithm
                               iv,               // iv
                               ivlen,            // iv length
                               aad,              // additional data
                               aadlen,           // additional data length
                               plain, plainlen,  // plaintext
                               cipher,           // ciphertext
                               *cipherlen,       // ciphertext length
                               cipherlen );      // length of output

    if ( status != PSA_SUCCESS )
    {
        return( status );
    }

    psa_destroy_key( key_handle );
    return( 0 );
}

/*!
 * \brief run the KEM with two keys as per draft-05
 *
 * \param encrypting is 1 if we're encrypting, 0 for decrypting
 * \param suite is the ciphersuite 
 * key1 is the first key, for which we have the private value
 * \param key1enclen is the length of the encoded form of key1
 * \param key1en is the encoded form of key1
 * key2 is the peer's key
 * \param key2enclen is the length of the encoded form of key1
 * \param key2en is the encoded form of key1
 * akey is the authentication private key
 * \param apublen is the length of the encoded the authentication public key
 * \param apub is the encoded form of the authentication public key
 * \param ss is (a pointer to) the buffer for the shared secret result
 * \param sslen is the size of the buffer (octets-used on exit)
 * \return 0 for good
 */
 
static int hpke_do_kem( int encrypting,
                        hpke_suite_t suite,
                        psa_key_handle_t own_key_handle,
                        size_t own_public_key_len, uint8_t *own_public_key,
                        size_t peer_public_key_len, uint8_t *peer_public_key,
                        psa_key_handle_t apriv_handle,
                        size_t apublen, uint8_t *apub,
                        uint8_t **ss, size_t *sslen)
{
    int ret;
    psa_status_t status;

    // Buffer for DH-derived key
    size_t zzlen = 2 * PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE;
    unsigned char zz[ 2 * PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE ];
    size_t zzlen2;
    
    // Buffer for context
    size_t kem_contextlen = PSA_EXPORT_PUBLIC_KEY_MAX_SIZE * 3;
    unsigned char kem_context[ PSA_EXPORT_PUBLIC_KEY_MAX_SIZE * 3 ];

    /* Produce ECDH key */
    status = psa_raw_key_agreement( PSA_ALG_ECDH,          // algorithm
                                    own_key_handle,        // private key
                                    peer_public_key,       // peer public key
                                    peer_public_key_len,   // length of peer public key
                                    zz, sizeof( zz ),      // buffer to store derived key
                                    &zzlen );              // output size

    if( status != PSA_SUCCESS )
    {
        return( status );
    }

    kem_contextlen = own_public_key_len + peer_public_key_len;

    if( kem_contextlen >= ( PSA_EXPORT_PUBLIC_KEY_MAX_SIZE * 3 ) )
    {
        ret = MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL;
        goto error;
    }

    // Copy own public key and peer public key to context
    if( encrypting )
    {
        memcpy( kem_context, own_public_key, own_public_key_len );
        memcpy( kem_context + own_public_key_len, peer_public_key, peer_public_key_len );
    }
    else
    {
        memcpy( kem_context, peer_public_key, peer_public_key_len );
        memcpy( kem_context + peer_public_key_len, own_public_key, own_public_key_len );
    }

    // Append the public auth key (mypub) to context
    if( apublen != 0 )
    {
        if( ( kem_contextlen + apublen ) >= ( PSA_EXPORT_PUBLIC_KEY_MAX_SIZE * 3 ) )
        {
            ret = MBEDTLS_ERR_HPKE_BUFFER_TOO_SMALL;
            goto error;
        }
        
        memcpy( kem_context + kem_contextlen, apub, apublen );
        kem_contextlen += apublen;
    }
    
    // Authentication part
    if( apub != NULL )
    {
        // Run to get 2nd half of zz
        if( encrypting )
        {
            status = psa_raw_key_agreement(
                          PSA_ALG_ECDH,                   // algorithm
                          apriv_handle,                  // auth private key
                          peer_public_key,                // peer public key
                          peer_public_key_len,            // length of peer public key
                          zz+zzlen, sizeof( zz ) - zzlen, // buffer to store derived key
                          &zzlen2 );                      // output size
        }
        else
        {
            status = psa_raw_key_agreement(
                          PSA_ALG_ECDH,                   // algorithm
                          own_key_handle,                 // private key
                          apub,                           // peer public key
                          apublen,                        // length of peer public key
                          zz+zzlen, sizeof( zz ) - zzlen, // buffer to store derived key
                          &zzlen2 );                      // output size
        }

        if( status != PSA_SUCCESS )
        {
            return( status );
        }

        zzlen+=zzlen2;
    }

    ret = mbedtls_hpke_extract_and_expand( suite,
                                           HPKE_5869_MODE_KEM,
                                           zz, zzlen,
                                           kem_context, kem_contextlen,
                                           *ss, sslen );
    
    if( ret != 0 )
    {
        goto error;
    }

error:
    mbedtls_platform_zeroize( zz, zzlen );

    return( ret );
}

int mbedtls_hpke_decrypt( unsigned int mode, hpke_suite_t suite,
                          char *pskid, size_t psklen, unsigned char *psk,
                          size_t pkS_len, unsigned char *pkS,
                          psa_key_handle_t skR_handle,
                          size_t pkE_len, unsigned char *pkE,
                          size_t cipherlen, unsigned char *cipher,
                          size_t aadlen, unsigned char *aad,
                          size_t infolen, unsigned char *info,
                          size_t *clearlen, unsigned char *clear )
{
    // Buffer for shared secret
    uint8_t buffer[MBEDTLS_MD_MAX_SIZE];
    size_t shared_secretlen = MBEDTLS_MD_MAX_SIZE;
    uint8_t *shared_secret = buffer;

    // Buffer for context
    size_t ks_contextlen = MBEDTLS_MD_MAX_SIZE * 2 + 1;
    uint8_t ks_context[ MBEDTLS_MD_MAX_SIZE * 2 + 1 ]= { 0 };
    
    // Buffer for secret
    size_t secretlen = MBEDTLS_MD_MAX_SIZE;
    uint8_t secret[ MBEDTLS_MD_MAX_SIZE];

    // Buffer for nonce
    size_t  noncelen = MBEDTLS_MD_MAX_SIZE;
    uint8_t nonce[MBEDTLS_MD_MAX_SIZE];

    // Buffer for PSK hash
    size_t psk_hashlen = MBEDTLS_MD_MAX_SIZE;
    uint8_t psk_hash[MBEDTLS_MD_MAX_SIZE];

    // Buffer for key
    size_t keylen = MBEDTLS_MD_MAX_SIZE;
    uint8_t key[MBEDTLS_MD_MAX_SIZE];

    // Buffer for exporter
    size_t exporterlen = MBEDTLS_MD_MAX_SIZE;
    uint8_t exporter[MBEDTLS_MD_MAX_SIZE];

    // Buffer for pkR
    size_t pkR_len;
    uint8_t pkR[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];

    int ret;
    psa_status_t status;
    size_t halflen;
    size_t pskidlen;

    // Input check: mode
    switch( mode )
    {
        case HPKE_MODE_BASE:
        case HPKE_MODE_PSK:
        case HPKE_MODE_AUTH:
        case HPKE_MODE_PSKAUTH:
            break;
        default:
            return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    // Input check: psk
    if( (mode == HPKE_MODE_PSK || mode == HPKE_MODE_PSKAUTH )
        && ( pskid == NULL || psklen == 0 || psk == NULL ) )
    {
        return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    // Input check: suite
    ret = hpke_suite_check( suite );

    if( ret != 0 )
    {
        return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    // Input check: Is buffer for plaintext available
    if( clearlen == 0 || clear == NULL )
    {
        return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    // Input check: Is ciphertext provided
    if( cipher == NULL || cipherlen == 0 )
    {
        return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    // Input check: For AUTH mode is pkS provided
    if( mode == HPKE_MODE_AUTH &&
        ( pkS == NULL || pkS_len == 0 ) )
    {
        return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    // Input check: For PSK mode is PSK provided
    if( ( mode == HPKE_MODE_PSK || mode == HPKE_MODE_PSKAUTH ) &&
        ( psk == NULL || psklen == 0 || pskid == NULL ) )
    {
        return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }
    
    /* Export own public key */
     status = psa_export_public_key( skR_handle,
                                     pkR, sizeof( pkR ),
                                     &pkR_len );
    
     if( status != PSA_SUCCESS )
     {
        return( EXIT_FAILURE );
     }

    /* Run DH KEM to get shared secret */
    ret = hpke_do_kem( 0,                                   // 0 means decrypting
                       suite,                               // ciphersuite
                       skR_handle,                          // skR handle
                       pkR_len, pkR,                        // public key recipient (pkR)
                       pkE_len, pkE,                        // is the peer's key
                       0,                                   // authentication private key
                       pkS_len, pkS,                        // authentication public key
                       &shared_secret, &shared_secretlen ); // shared secret
                       
    if( ret != 0 )
    {
        return( MBEDTLS_ERR_HPKE_INTERNAL_ERROR );
    }

    /* Create context buffer */
    ks_context[0] = ( unsigned char ) ( mode % 256 );
    ks_contextlen--;
    halflen = ks_contextlen;
    pskidlen = 0;
    pskidlen = ( psk == NULL ? 0 : strlen( pskid ) );

    ret = mbedtls_hpke_extract( suite,                                        // ciphersuite
                                HPKE_5869_MODE_FULL,                          // mode
                                (unsigned char *) "", 0,                      // salt
                                MBEDTLS_SSL_HPKE_LBL_WITH_LEN( psk_id_hash ), // label
                                (unsigned char *) pskid, pskidlen,            // psk id
                                ks_context + 1, &halflen );

    if( ret != 0 )
    {
        goto error;
    }

    ks_contextlen -= halflen;

    ret = mbedtls_hpke_extract( suite,
                                HPKE_5869_MODE_FULL,
                                (unsigned char *) "", 0,
                                MBEDTLS_SSL_HPKE_LBL_WITH_LEN( info_hash ),
                                info, infolen,
                                ks_context + 1 + halflen, &ks_contextlen );
    
    if( ret != 0 )
    {
        goto error;
    }

    ks_contextlen += 1 + halflen;

    /* Extract secret */
    ret = mbedtls_hpke_extract( suite,
                                HPKE_5869_MODE_FULL,
                                (unsigned char *) "", 0,
                                MBEDTLS_SSL_HPKE_LBL_WITH_LEN( psk_hash ),
                                psk, psklen,
                                psk_hash, &psk_hashlen );
    
    if( ret != 0)
    {
        goto error;
    }

    secretlen = hpke_kdf_tab[suite.kdf_id].Nh;
    
    ret = mbedtls_hpke_extract( suite,
                                HPKE_5869_MODE_FULL,
                                shared_secret, shared_secretlen,
                                MBEDTLS_SSL_HPKE_LBL_WITH_LEN( secret ),
                                psk, psklen,
                                secret, &secretlen );
    
    if( ret != 0 )
    {
        goto error;
    }

    noncelen = hpke_aead_tab[suite.aead_id].Nn;

    ret = mbedtls_hpke_expand( suite,
                               HPKE_5869_MODE_FULL,
                               secret, secretlen,
                               MBEDTLS_SSL_HPKE_LBL_WITH_LEN( base_nonce ),
                               ks_context, ks_contextlen,
                               noncelen, nonce, &noncelen );
    
    if( ret != 0 )
    {
        goto error;
    }

    keylen = hpke_aead_tab[suite.aead_id].Nk;

    ret = mbedtls_hpke_expand( suite,
                               HPKE_5869_MODE_FULL,
                               secret, secretlen,
                               MBEDTLS_SSL_HPKE_LBL_WITH_LEN( key ),
                               ks_context, ks_contextlen,
                               keylen, key, &keylen );
    
    if( ret != 0 )
    {
        goto error;
    }

    exporterlen = hpke_kdf_tab[suite.kdf_id].Nh;

    ret = mbedtls_hpke_expand( suite,
                               HPKE_5869_MODE_FULL,
                               secret, secretlen,
                               MBEDTLS_SSL_HPKE_LBL_WITH_LEN( exp ),
                               ks_context, ks_contextlen,
                               exporterlen, exporter, &exporterlen );

    if( ret != 0 )
    {
        goto error;
    }

    noncelen = hpke_aead_tab[suite.aead_id].Nn;

    ret = mbedtls_hpke_expand( suite,
                               HPKE_5869_MODE_FULL,
                               secret, secretlen,
                               MBEDTLS_SSL_HPKE_LBL_WITH_LEN( base_nonce ),
                               ks_context, ks_contextlen,
                               noncelen, nonce, &noncelen );

    if( ret !=0 )
    {
        goto error;
    }

    /* Decrypt ciphertext */
    ret = hpke_aead_dec( suite,
                         key, keylen,
                         nonce, noncelen,
                         aad, aadlen,
                         cipher, cipherlen,
                         clear, clearlen );

    if( ret != 0 )
    {
        goto error;
    }

error:
    return( ret );
}

/**
 * \brief check if a suite is supported locally
 *
 * \param suite is the suite to check
 * \return 1 for good/supported, not-1 otherwise
 */

int hpke_suite_check( hpke_suite_t suite )
{
     int nkems;
     int nkdfs;
     int naeads;

    int kem_ok = 0;
    int kdf_ok = 0;
    int aead_ok = 0;

    int ind = 0;

    // Check KEM
    nkems= sizeof( hpke_kem_tab ) / sizeof( hpke_kem_info_t );

    for( ind = 0; ind != nkems; ind++ )
    {
        if( suite.kem_id == hpke_kem_tab[ ind ].kem_id )
        {
            kem_ok = 1;
            break;
        }
    }

    // Check KDF
    nkdfs = sizeof( hpke_kdf_tab ) / sizeof( hpke_kdf_info_t );

    for( ind = 0; ind != nkdfs; ind++ )
    {
        if( suite.kdf_id == hpke_kdf_tab[ ind ].kdf_id )
        {
            kdf_ok = 1;
            break;
        }
    }

    // Check AEAD
    naeads = sizeof( hpke_aead_tab ) / sizeof( hpke_aead_info_t );

    for( ind = 0; ind != naeads; ind++ )
    {
        if( suite.aead_id == hpke_aead_tab[ ind ].aead_id )
        {
            aead_ok = 1;
            break;
        }
    }

    if( kem_ok == 1 && kdf_ok == 1 && aead_ok ==1 )
    {
        return( 0 );
    }

    return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
}

/*!
 * \brief Internal HPKE single-shot encryption function
 * \param mode is the HPKE mode
 * \param suite is the ciphersuite to use
 * \param pskid is the pskid string fpr a PSK mode (can be NULL)
 * \param psklen is the psk length
 * \param psk is the psk 
 * \param publen is the length of the recipient public key
 * \param pub is the encoded recipient public key
 * \param privlen is the length of the private (authentication) key
 * \param priv is the encoded private (authentication) key
 * \param clearlen is the length of the cleartext
 * \param clear is the encoded cleartext
 * \param aadlen is the lenght of the additional data (can be zero)
 * \param aad is the encoded additional data (can be NULL)
 * \param infolen is the lenght of the info data (can be zero)
 * \param info is the encoded info data (can be NULL)
 * \param extsenderpublen is the length of the input buffer with the sender's public key 
 * \param extsenderpub is the input buffer for sender public key
 * \param extsenderpriv has the handle for the sender private key
 * \param senderpublen is the length of the input buffer for the sender's public key (length used on output)
 * \param senderpub is the input buffer for ciphertext
 * \param cipherlen is the length of the input buffer for ciphertext (length used on output)
 * \param cipher is the input buffer for ciphertext
 * \return 1 for good (OpenSSL style), not-1 for error
 */
static int hpke_enc_int( unsigned int mode, hpke_suite_t suite,
                         char *pskid, size_t psklen, unsigned char *psk,
                         size_t pkR_len, unsigned char *pkR,
                         psa_key_handle_t skS_handle,
                         size_t clearlen, unsigned char *clear,
                         size_t aadlen, unsigned char *aad,
                         size_t infolen, unsigned char *info,
                         psa_key_handle_t ext_pkE_handle,
                         size_t *pkE_len, unsigned char *pkE,
                         size_t *cipherlen, unsigned char *cipher )

{
    // FOR TEST PURPOSES ONLY
    size_t pkS_len = 0;
    uint8_t *pkS = NULL;

    // Buffer for context
    size_t ks_contextlen = MBEDTLS_MD_MAX_SIZE * 2 + 1;
    uint8_t ks_context[ MBEDTLS_MD_MAX_SIZE * 2 + 1 ] = { 0 };
    
    // Buffer for secret
    size_t secretlen = MBEDTLS_MD_MAX_SIZE;
    uint8_t secret[ MBEDTLS_MD_MAX_SIZE];

    // Buffer for nonce
    size_t  noncelen = MBEDTLS_MD_MAX_SIZE;
    uint8_t nonce[MBEDTLS_MD_MAX_SIZE];

    // Buffer for PSK hash
    size_t psk_hashlen = MBEDTLS_MD_MAX_SIZE;
    uint8_t psk_hash[MBEDTLS_MD_MAX_SIZE];

    // Buffer for key
    size_t keylen = MBEDTLS_MD_MAX_SIZE;
    uint8_t key[MBEDTLS_MD_MAX_SIZE];

    // Buffer for exporter
    size_t exporterlen = MBEDTLS_MD_MAX_SIZE;
    uint8_t exporter[MBEDTLS_MD_MAX_SIZE];

    // Buffer for pkE
    uint8_t pkE_tmp[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = { 0 };
    size_t pkE_tmp_len = PSA_EXPORT_PUBLIC_KEY_MAX_SIZE;

    // Buffer for secret
    uint8_t buffer[MBEDTLS_MD_MAX_SIZE];
    size_t shared_secretlen = MBEDTLS_MD_MAX_SIZE;
    uint8_t *shared_secret = buffer;
    size_t halflen=0;
    size_t pskidlen=0;

    psa_status_t status;
    psa_key_attributes_t skE_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t skE_handle = 0;
    size_t key_len;
    psa_key_type_t type;
    int ret;

    // Input check: mode
    switch( mode )
    {
        case HPKE_MODE_BASE:
        case HPKE_MODE_PSK:
        case HPKE_MODE_AUTH:
        case HPKE_MODE_PSKAUTH:
            break;
        default:
            return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    // Input check: psk
    if( (mode == HPKE_MODE_PSK || mode == HPKE_MODE_PSKAUTH )
        && ( pskid == NULL || psklen == 0 || psk == NULL ) )
    {
        return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    // Input check: suite
    ret = hpke_suite_check( suite );

    if( ret != 0 )
    {
        return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    switch( suite.kem_id )
    {
        case HPKE_KEM_ID_P256:
            key_len = 256;
            break;
        case HPKE_KEM_ID_P384:
            key_len = 384;
            break;
        case HPKE_KEM_ID_P521:
            key_len = 521;
            break;
        default:
            return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    switch( suite.kem_id )
    {
        case HPKE_KEM_ID_P256:
        case HPKE_KEM_ID_P384:
        case HPKE_KEM_ID_P521:
            type = PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 );
            break;
        case HPKE_KEM_ID_25519: // not implemented yet
        case HPKE_KEM_ID_448: // not implemented yet
        default:
            return( MBEDTLS_ERR_HPKE_BAD_INPUT_DATA );
    }

    if( ext_pkE_handle == 0 )
    {
        /* generate key pair: skE, pkE */
        psa_set_key_usage_flags( &skE_attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT );
        psa_set_key_algorithm( &skE_attributes, PSA_ALG_ECDH );
        psa_set_key_type( &skE_attributes, type );
        psa_set_key_bits( &skE_attributes, key_len );

        status = psa_generate_key( &skE_attributes, &skE_handle );

        if( status != PSA_SUCCESS )
        {
            return( EXIT_FAILURE );
        }
    }

    status = psa_export_public_key( (ext_pkE_handle == 0) ? skE_handle : ext_pkE_handle,
                                    (ext_pkE_handle == 0) ? pkE : pkE_tmp,
                                    (ext_pkE_handle == 0) ? *pkE_len : pkE_tmp_len,
                                    (ext_pkE_handle == 0) ? pkE_len : &pkE_tmp_len
                                  );

    if( status != PSA_SUCCESS )
    {
        return( EXIT_FAILURE );
    }

    /* Run DH KEM to get shared secret */
    ret = hpke_do_kem( 1,                                                     // 1 means encryption
                       suite,                                                 // ciphersuite
                       (ext_pkE_handle == 0) ? skE_handle : ext_pkE_handle,   // skE handle
                       (ext_pkE_handle == 0) ? *pkE_len : pkE_tmp_len,        // pkE length
                       (ext_pkE_handle == 0) ? pkE : pkE_tmp,                 // pkE
                       pkR_len, pkR,                                          // pkR
                       skS_handle,                                            // skS handle
                       pkS_len, pkS,                                          // pkS
                       &shared_secret, &shared_secretlen );                   // shared secret

    if( ret != 0 )
    {
        return( MBEDTLS_ERR_HPKE_INTERNAL_ERROR );
    }

    /* Create context buffer */
    ks_context[0] = (unsigned char) ( mode % 256 );
    ks_contextlen--;
    halflen = ks_contextlen;
    pskidlen = ( psk == NULL ? 0 : strlen( pskid ) );

    ret = mbedtls_hpke_extract( suite,                                        // ciphersuite
                                HPKE_5869_MODE_FULL,                          // mode
                                (unsigned char *) "", 0,                      // salt
                                MBEDTLS_SSL_HPKE_LBL_WITH_LEN( psk_id_hash ), // label
                                (unsigned char*) pskid, pskidlen,             // psk id
                                ks_context + 1, &halflen );

    if( ret != 0 )
    {
        goto error;
    }

    ks_contextlen -= halflen;

    ret = mbedtls_hpke_extract( suite,
                                HPKE_5869_MODE_FULL,
                                (unsigned char *) "", 0,
                                MBEDTLS_SSL_HPKE_LBL_WITH_LEN( info_hash ),
                                info, infolen,
                                ks_context + 1 + halflen, &ks_contextlen );

    if( ret != 0 )
    {
        goto error;
    }

    ks_contextlen += 1 + halflen;

    /* Extract secret */
    ret = mbedtls_hpke_extract( suite,
                                HPKE_5869_MODE_FULL,
                                (unsigned char *) "", 0,
                                MBEDTLS_SSL_HPKE_LBL_WITH_LEN( psk_hash ),
                                psk, psklen,
                                psk_hash, &psk_hashlen );

    if( ret != 0)
    {
        goto error;
    }

    secretlen = hpke_kdf_tab[suite.kdf_id].Nh;

    ret = mbedtls_hpke_extract( suite,
                                HPKE_5869_MODE_FULL,
                                shared_secret, shared_secretlen,
                                MBEDTLS_SSL_HPKE_LBL_WITH_LEN( secret ),
                                psk, psklen,
                                secret, &secretlen );

    if( ret != 0 )
    {
        goto error;
    }

    noncelen = hpke_aead_tab[suite.aead_id].Nn;

    ret = mbedtls_hpke_expand( suite,
                               HPKE_5869_MODE_FULL,
                               secret, secretlen,
                               MBEDTLS_SSL_HPKE_LBL_WITH_LEN( base_nonce ),
                               ks_context, ks_contextlen,
                               noncelen, nonce, &noncelen );

    if( ret != 0 )
    {
        goto error;
    }

    keylen = hpke_aead_tab[suite.aead_id].Nk;

    ret = mbedtls_hpke_expand( suite,
                               HPKE_5869_MODE_FULL,
                               secret, secretlen,
                               MBEDTLS_SSL_HPKE_LBL_WITH_LEN( key ),
                               ks_context, ks_contextlen,
                               keylen, key, &keylen );

    if( ret != 0 )
    {
        goto error;
    }

    exporterlen = hpke_kdf_tab[suite.kdf_id].Nh;

    ret = mbedtls_hpke_expand( suite,
                               HPKE_5869_MODE_FULL,
                               secret, secretlen,
                               MBEDTLS_SSL_HPKE_LBL_WITH_LEN( exp ),
                               ks_context, ks_contextlen,
                               exporterlen, exporter, &exporterlen );

    if( ret != 0 )
    {
        goto error;
    }

    /* step 5. call the AEAD */
    ret = hpke_aead_enc( suite,
                         key, keylen,
                         nonce, noncelen,
                         aad, aadlen,
                         clear, clearlen,
                         cipher, cipherlen );

    if( ret != 0 )
    {
        goto error;
    }

error:
    return( ret );
}

int mbedtls_hpke_encrypt( unsigned int mode, hpke_suite_t suite,
                          char *pskid, size_t psklen, uint8_t *psk,
                          size_t pkR_len, uint8_t *pkR,
                          psa_key_handle_t skI_handle,
                          size_t clearlen, uint8_t *clear,
                          size_t aadlen, uint8_t *aad,
                          size_t infolen, uint8_t *info,
                          psa_key_handle_t ext_skE_handle,
                          size_t *pkE_len, uint8_t *pkE,
                          size_t *cipherlen, uint8_t *cipher )
{
    return hpke_enc_int( mode,                // HPKE mode
                         suite,               // ciphersuite
                         pskid, psklen, psk,  // PSK for authentication
                         pkR_len, pkR,        // pkR
                         skI_handle,          // skI handle
                         clearlen, clear,     // plaintext
                         aadlen, aad,         // Additional data
                         infolen, info,       // Info
                         ext_skE_handle,      // skE handle
                         pkE_len, pkE,        // pkE
                         cipherlen, cipher ); // ciphertext
}

#endif /* MBEDTLS_HPKE_C */
