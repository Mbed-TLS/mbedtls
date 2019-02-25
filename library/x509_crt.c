/*
 *  X.509 certificate parsing and verification
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
/*
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 *  http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *
 *  [SIRO] https://cabforum.org/wp-content/uploads/Chunghwatelecom201503cabforumV4.pdf
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)

#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#include "mbedtls/psa_util.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_free       free
#define mbedtls_calloc    calloc
#define mbedtls_snprintf   snprintf
#endif

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)
#include <windows.h>
#else
#include <time.h>
#endif

#if defined(MBEDTLS_FS_IO)
#include <stdio.h>
#if !defined(_WIN32) || defined(EFIX64) || defined(EFI32)
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#endif /* !_WIN32 || EFIX64 || EFI32 */
#endif

static int x509_crt_parse_frame( unsigned char *start,
                                 unsigned char *end,
                                 mbedtls_x509_crt_frame *frame );
static int x509_crt_subject_from_frame( mbedtls_x509_crt_frame *frame,
                                        mbedtls_x509_name *subject );
static int x509_crt_issuer_from_frame( mbedtls_x509_crt_frame *frame,
                                       mbedtls_x509_name *issuer );
static int x509_crt_certificate_policies_from_frame( mbedtls_x509_crt_frame *frame,
                                        mbedtls_x509_sequence *policies );
static int x509_crt_subject_alt_from_frame( mbedtls_x509_crt_frame *frame,
                                        mbedtls_x509_sequence *subject_alt );
static int x509_crt_ext_key_usage_from_frame( mbedtls_x509_crt_frame *frame,
                                        mbedtls_x509_sequence *ext_key_usage );

static void x509_free_sequence( mbedtls_x509_sequence *seq );
static void x509_free_name( mbedtls_x509_name *name );

static int x509_crt_pk_acquire( mbedtls_x509_crt *crt,
                                mbedtls_pk_context **pk );
static int x509_crt_frame_acquire( mbedtls_x509_crt const *crt,
                                   mbedtls_x509_crt_frame **frame );
static void x509_crt_pk_release( mbedtls_x509_crt *crt,
                                 mbedtls_pk_context *pk );
static void x509_crt_frame_release( mbedtls_x509_crt *crt,
                                 mbedtls_pk_context *pk );

static int x509_crt_frame_acquire( mbedtls_x509_crt const *crt,
                                   mbedtls_x509_crt_frame **frame_ptr )
{
    int ret;
    mbedtls_x509_crt_frame *frame;

    frame = mbedtls_calloc( 1, sizeof( mbedtls_x509_crt_frame ) );
    if( frame == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );

    ret = x509_crt_parse_frame( crt->raw.p, crt->raw.p + crt->raw.len,
                                frame );
    if( ret != 0 )
        return( ret );

    *frame_ptr = frame;
    return( 0 );
}

static void x509_crt_frame_release( mbedtls_x509_crt const *crt,
                                    mbedtls_x509_crt_frame *frame )
{
    ((void) crt);
    if( frame == NULL )
        return;
    mbedtls_free( frame );
}
static int x509_crt_pk_acquire( mbedtls_x509_crt *crt,
                                mbedtls_pk_context **pk )
{
    *pk = &crt->pk;
    return( 0 );
}

static void x509_crt_pk_release( mbedtls_x509_crt *crt,
                                 mbedtls_pk_context *pk )
{
    ((void) crt);
    ((void) pk);
    return;
}

/*
 * Item in a verification chain: cert and flags for it
 */
typedef struct {
    mbedtls_x509_crt *crt;
    uint32_t flags;
} x509_crt_verify_chain_item;

/*
 * Max size of verification chain: end-entity + intermediates + trusted root
 */
#define X509_MAX_VERIFY_CHAIN_SIZE    ( MBEDTLS_X509_MAX_INTERMEDIATE_CA + 2 )

/*
 * Default profile
 */
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_default =
{
#if defined(MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES)
    /* Allow SHA-1 (weak, but still safe in controlled environments) */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA1 ) |
#endif
    /* Only SHA-2 hashes */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA224 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA512 ),
    0xFFFFFFF, /* Any PK alg    */
    0xFFFFFFF, /* Any curve     */
    2048,
};

/*
 * Next-default profile
 */
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_next =
{
    /* Hashes from SHA-256 and above */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA512 ),
    0xFFFFFFF, /* Any PK alg    */
#if defined(MBEDTLS_ECP_C)
    /* Curves at or above 128-bit security level */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP256R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP384R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP521R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_BP256R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_BP384R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_BP512R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP256K1 ),
#else
    0,
#endif
    2048,
};

/*
 * NSA Suite B Profile
 */
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_suiteb =
{
    /* Only SHA-256 and 384 */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ),
    /* Only ECDSA */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_ECDSA ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_ECKEY ),
#if defined(MBEDTLS_ECP_C)
    /* Only NIST P-256 and P-384 */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP256R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP384R1 ),
#else
    0,
#endif
    0,
};

/*
 * Check md_alg against profile
 * Return 0 if md_alg is acceptable for this profile, -1 otherwise
 */
static int x509_profile_check_md_alg( const mbedtls_x509_crt_profile *profile,
                                      mbedtls_md_type_t md_alg )
{
    if( md_alg == MBEDTLS_MD_NONE )
        return( -1 );

    if( ( profile->allowed_mds & MBEDTLS_X509_ID_FLAG( md_alg ) ) != 0 )
        return( 0 );

    return( -1 );
}

/*
 * Check pk_alg against profile
 * Return 0 if pk_alg is acceptable for this profile, -1 otherwise
 */
static int x509_profile_check_pk_alg( const mbedtls_x509_crt_profile *profile,
                                      mbedtls_pk_type_t pk_alg )
{
    if( pk_alg == MBEDTLS_PK_NONE )
        return( -1 );

    if( ( profile->allowed_pks & MBEDTLS_X509_ID_FLAG( pk_alg ) ) != 0 )
        return( 0 );

    return( -1 );
}

/*
 * Check key against profile
 * Return 0 if pk is acceptable for this profile, -1 otherwise
 */
static int x509_profile_check_key( const mbedtls_x509_crt_profile *profile,
                                   const mbedtls_pk_context *pk )
{
    const mbedtls_pk_type_t pk_alg = mbedtls_pk_get_type( pk );

#if defined(MBEDTLS_RSA_C)
    if( pk_alg == MBEDTLS_PK_RSA || pk_alg == MBEDTLS_PK_RSASSA_PSS )
    {
        if( mbedtls_pk_get_bitlen( pk ) >= profile->rsa_min_bitlen )
            return( 0 );

        return( -1 );
    }
#endif

#if defined(MBEDTLS_ECP_C)
    if( pk_alg == MBEDTLS_PK_ECDSA ||
        pk_alg == MBEDTLS_PK_ECKEY ||
        pk_alg == MBEDTLS_PK_ECKEY_DH )
    {
        const mbedtls_ecp_group_id gid = mbedtls_pk_ec( *pk )->grp.id;

        if( gid == MBEDTLS_ECP_DP_NONE )
            return( -1 );

        if( ( profile->allowed_curves & MBEDTLS_X509_ID_FLAG( gid ) ) != 0 )
            return( 0 );

        return( -1 );
    }
#endif

    return( -1 );
}

/*
 * Return 0 if name matches wildcard, -1 otherwise
 */
static int x509_check_wildcard( char const *cn,
                                size_t cn_len,
                                unsigned char const *buf,
                                size_t buf_len )
{
    size_t i;
    size_t cn_idx = 0;

    /* We can't have a match if there is no wildcard to match */
    if( buf_len < 3 || buf[0] != '*' || buf[1] != '.' )
        return( -1 );

    for( i = 0; i < cn_len; ++i )
    {
        if( cn[i] == '.' )
        {
            cn_idx = i;
            break;
        }
    }

    if( cn_idx == 0 )
        return( -1 );

    if( mbedtls_x509_memcasecmp( buf + 1, cn + cn_idx,
                                 buf_len - 1, cn_len - cn_idx ) == 0 )
    {
        return( 0 );
    }

    return( -1 );
}

/*
 * Reset (init or clear) a verify_chain
 */
static void x509_crt_verify_chain_reset(
    mbedtls_x509_crt_verify_chain *ver_chain )
{
    size_t i;

    for( i = 0; i < MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE; i++ )
    {
        ver_chain->items[i].crt = NULL;
        ver_chain->items[i].flags = (uint32_t) -1;
    }

    ver_chain->len = 0;

#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    ver_chain->trust_ca_cb_result = NULL;
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */
}

/*
 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 */
static int x509_get_version( unsigned char **p,
                             const unsigned char *end,
                             int *ver )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            *ver = 0;
            return( 0 );
        }

        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = *p + len;

    if( ( ret = mbedtls_asn1_get_int( p, end, ver ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_VERSION + ret );

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_VERSION +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 *  Validity ::= SEQUENCE {
 *       notBefore      Time,
 *       notAfter       Time }
 */
static int x509_get_dates( unsigned char **p,
                           const unsigned char *end,
                           mbedtls_x509_time *from,
                           mbedtls_x509_time *to )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_DATE + ret );

    end = *p + len;

    if( ( ret = mbedtls_x509_get_time( p, end, from ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_x509_get_time( p, end, to ) ) != 0 )
        return( ret );

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_DATE +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * X.509 v2/v3 unique identifier (not parsed)
 */
static int x509_get_uid( unsigned char **p,
                         const unsigned char *end,
                         mbedtls_x509_buf *uid, int n )
{
    int ret;

    if( *p == end )
        return( 0 );

    uid->tag = **p;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &uid->len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | n ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
            return( 0 );

        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    uid->p = *p;
    *p += uid->len;

    return( 0 );
}

static int x509_get_basic_constraints( unsigned char **p,
                                       const unsigned char *end,
                                       int *ca_istrue,
                                       int *max_pathlen )
{
    int ret;
    size_t len;

    /*
     * BasicConstraints ::= SEQUENCE {
     *      cA                      BOOLEAN DEFAULT FALSE,
     *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
     */
    *ca_istrue = 0; /* DEFAULT FALSE */
    *max_pathlen = 0; /* endless */

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( ret );

    if( *p == end )
        return( 0 );

    if( ( ret = mbedtls_asn1_get_bool( p, end, ca_istrue ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
            ret = mbedtls_asn1_get_int( p, end, ca_istrue );

        if( ret != 0 )
            return( ret );

        if( *ca_istrue != 0 )
            *ca_istrue = 1;
    }

    if( *p == end )
        return( 0 );

    if( ( ret = mbedtls_asn1_get_int( p, end, max_pathlen ) ) != 0 )
        return( ret );

    if( *p != end )
        return( MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    (*max_pathlen)++;

    return( 0 );
}

static int x509_get_ns_cert_type( unsigned char **p,
                                       const unsigned char *end,
                                       unsigned char *ns_cert_type)
{
    int ret;
    mbedtls_x509_bitstring bs = { 0, 0, NULL };

    if( ( ret = mbedtls_asn1_get_bitstring( p, end, &bs ) ) != 0 )
        return( ret );

    if( bs.len != 1 )
        return( MBEDTLS_ERR_ASN1_INVALID_LENGTH );

    /* Get actual bitstring */
    *ns_cert_type = *bs.p;
    return( 0 );
}

static int x509_get_key_usage( unsigned char **p,
                               const unsigned char *end,
                               unsigned int *key_usage)
{
    int ret;
    size_t i;
    mbedtls_x509_bitstring bs = { 0, 0, NULL };

    if( ( ret = mbedtls_asn1_get_bitstring( p, end, &bs ) ) != 0 )
        return( ret );

    if( bs.len < 1 )
        return( MBEDTLS_ERR_ASN1_INVALID_LENGTH );

    /* Get actual bitstring */
    *key_usage = 0;
    for( i = 0; i < bs.len && i < sizeof( unsigned int ); i++ )
    {
        *key_usage |= (unsigned int) bs.p[i] << (8*i);
    }

    return( 0 );
}

/*
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * KeyPurposeId ::= OBJECT IDENTIFIER
 */
static int x509_get_ext_key_usage( unsigned char **p,
                               const unsigned char *end,
                               mbedtls_x509_sequence *ext_key_usage)
{
    return( mbedtls_asn1_get_sequence_of( p, end, ext_key_usage,
                                          MBEDTLS_ASN1_OID ) );
}

/*
 * SubjectAltName ::= GeneralNames
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 * GeneralName ::= CHOICE {
 *      otherName                       [0]     OtherName,
 *      rfc822Name                      [1]     IA5String,
 *      dNSName                         [2]     IA5String,
 *      x400Address                     [3]     ORAddress,
 *      directoryName                   [4]     Name,
 *      ediPartyName                    [5]     EDIPartyName,
 *      uniformResourceIdentifier       [6]     IA5String,
 *      iPAddress                       [7]     OCTET STRING,
 *      registeredID                    [8]     OBJECT IDENTIFIER }
 *
 * OtherName ::= SEQUENCE {
 *      type-id    OBJECT IDENTIFIER,
 *      value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 * EDIPartyName ::= SEQUENCE {
 *      nameAssigner            [0]     DirectoryString OPTIONAL,
 *      partyName               [1]     DirectoryString }
 *
 * NOTE: we list all types, but only use dNSName and otherName
 * of type HwModuleName, as defined in RFC 4108, at this point.
 */
static int x509_parse_subject_alt_name_cb( void *ctx,
                                           int tag,
                                           unsigned char *data,
                                           size_t data_len )
{
    int ret;
    mbedtls_x509_subject_alternative_name dummy_san_buf;
    mbedtls_x509_buf tmp_san_buf;

    ((void) ctx);
    memset( &dummy_san_buf, 0, sizeof( dummy_san_buf ) );

    tmp_san_buf.p = data;
    tmp_san_buf.len = data_len;
    tmp_san_buf.tag = tag;

    /*
     * Check that the SAN are structured correctly.
     */

    ret = mbedtls_x509_parse_subject_alt_name( &tmp_san_buf, &dummy_san_buf );
    /* Ignore unknown SANs. */
    if( ret == MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE )
        ret = 0;

    return( ret );
}

static int x509_get_subject_alt_name_cb( void *ctx,
                                         int tag,
                                         unsigned char *data,
                                         size_t data_len )
{
    int ret;
    mbedtls_x509_subject_alternative_name dummy_san_buf = { 0 };
    mbedtls_asn1_sequence **cur_ptr = (mbedtls_asn1_sequence **) ctx;
    mbedtls_asn1_sequence *cur = *cur_ptr;

    mbedtls_x509_buf tmp_san_buf;
    tmp_san_buf.p = data;
    tmp_san_buf.len = data_len;
    tmp_san_buf.tag = tag;

    /*
     * Check that the SAN are structured correctly.
     */
    ret = mbedtls_x509_parse_subject_alt_name( &tmp_san_buf, &dummy_san_buf );
    if( ret != 0 && ret != MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE )
        return( ret );

    /* Allocate and assign next pointer */
    if( cur->buf.p != NULL )
    {
        cur->next = mbedtls_calloc( 1, sizeof( mbedtls_asn1_sequence ) );
        if( cur->next == NULL )
            return( MBEDTLS_ERR_ASN1_ALLOC_FAILED );
        cur = cur->next;
    }

    cur->buf = tmp_san_buf;
    *cur_ptr = cur;
    return( 0 );
}

static int x509_get_subject_alt_name( unsigned char *p,
                                      const unsigned char *end,
                                      mbedtls_x509_sequence *subject_alt_name )
{
    return( mbedtls_asn1_traverse_sequence_of( &p, end,
                                               MBEDTLS_ASN1_TAG_CLASS_MASK,
                                               MBEDTLS_ASN1_CONTEXT_SPECIFIC,
                                               0, 0,
                                               x509_get_subject_alt_name_cb,
                                               (void*) &subject_alt_name ) );
}

/*
 * This function takes the ASN.1 buffer representing a PolicyInformation
 * SEQUENCE and replaces it by the ASN.1 sub-buffer representing the
 * policyIdentifier field of the PolicyInformation structure.
 *
 * Upon an ASN.1 parsing failure, the corresponding ASN.1 error code is
 * returned. In this case, the state of the passed buffer structure is
 * undefined.
 *
 * PolicyInformation ::= SEQUENCE {
 *     policyIdentifier   CertPolicyId,
 *     policyQualifiers   SEQUENCE SIZE (1..MAX) OF
 *                             PolicyQualifierInfo OPTIONAL }
 */
static int x509_extract_policy_id( mbedtls_x509_buf_raw *policy )
{
    int ret;
    size_t len;
    unsigned char *p = policy->p;
    unsigned char *end = p + policy->len;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                                      MBEDTLS_ASN1_OID ) ) != 0 )
    {
        return( ret );
    }

    /* Update buffer to point to the CertPolicyId instead
     * of the outer SEQUENCE. */
    policy->p = p;
    policy->len = len;

    p += len;

    /* Check for the optional policy qualifier. */
    if( p < end )
    {
        if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                                          MBEDTLS_ASN1_CONSTRUCTED |
                                          MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        {
            return( ret );
        }

        /* Skip over policy qualifier. */
        p += len;
    }

    if( p != end )
        return( MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/* This is a certificate policy parsing callback suitable for use with
 * mbedtls_asn1_traverse_sequence_of(). The context parameter must be
 * a pointer to an `int` which is set to `1` in case an unknown policy
 * is found. Otherwise, its value is unchanged. */
static int x509_crt_parse_policies_cb( void *ctx,
                                       int tag,
                                       unsigned char *p,
                                       size_t len )
{
    int ret;
    mbedtls_x509_buf_raw policy;
    int *unknown_policy_found = (int *) ctx;

    ((void) tag);

    /* Check structural sanity and extract policy OID. */
    policy.p = p;
    policy.len = len;

    ret = x509_extract_policy_id( &policy );
    if( ret != 0 )
        return( ret );

    /*
     * Only AnyPolicy is currently supported when enforcing policy.
     */
    if( MBEDTLS_OID_CMP_RAW( MBEDTLS_OID_ANY_POLICY,
                             policy.p, policy.len ) != 0 )
    {
        *unknown_policy_found = 1;
    }

    return( 0 );
}

/*
 * X.509 v3 extensions
 *
 */
static int x509_crt_get_ext_cb( void *ctx,
                                int tag,
                                unsigned char *p,
                                size_t ext_len )
{
    int ret;
    mbedtls_x509_crt_frame *frame = (mbedtls_x509_crt_frame *) ctx;
    size_t len;
    unsigned char *end, *end_ext_octet;
    mbedtls_x509_buf extn_oid = { 0, 0, NULL };
    int is_critical = 0; /* DEFAULT FALSE */
    int ext_type = 0;

    ((void) tag);

    /*
     * Extension  ::=  SEQUENCE  {
     *      extnID      OBJECT IDENTIFIER,
     *      critical    BOOLEAN DEFAULT FALSE,
     *      extnValue   OCTET STRING  }
     */

    end = p + ext_len;

    /* Get extension ID */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &extn_oid.len,
                                      MBEDTLS_ASN1_OID ) ) != 0 )
        goto err;

    extn_oid.tag = MBEDTLS_ASN1_OID;
    extn_oid.p = p;
    p += extn_oid.len;

    /* Get optional critical */
    if( ( ret = mbedtls_asn1_get_bool( &p, end, &is_critical ) ) != 0 &&
        ( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG ) )
        goto err;

    /* Data should be octet string type */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                                      MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        goto err;

    end_ext_octet = p + len;
    if( end_ext_octet != end )
    {
        ret = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        goto err;
    }

    /*
     * Detect supported extensions
     */
    ret = mbedtls_oid_get_x509_ext_type( &extn_oid, &ext_type );
    if( ret != 0 )
    {
#if !defined(MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION)
        if( is_critical )
        {
            /* Data is marked as critical: fail */
            ret = MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            goto err;
        }
#endif
        return( 0 );
    }

    /* Forbid repeated extensions */
    if( ( frame->ext_types & ext_type ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS );

    frame->ext_types |= ext_type;
    switch( ext_type )
    {
        case MBEDTLS_X509_EXT_BASIC_CONSTRAINTS:
        {
            int ca_istrue;
            int max_pathlen;

            /* Parse basic constraints */
            ret = x509_get_basic_constraints( &p, end_ext_octet,
                                              &ca_istrue,
                                              &max_pathlen );
            if( ret != 0 )
                goto err;

            frame->ca_istrue   = ca_istrue;
            frame->max_pathlen = max_pathlen;
            break;
        }

        case MBEDTLS_X509_EXT_KEY_USAGE:
            /* Parse key usage */
            ret = x509_get_key_usage( &p, end_ext_octet,
                                      &frame->key_usage );
            if( ret != 0 )
                goto err;
            break;

        case MBEDTLS_X509_EXT_SUBJECT_ALT_NAME:
            /* Copy reference to raw subject alt name data. */
            frame->subject_alt_raw.p   = p;
            frame->subject_alt_raw.len = end_ext_octet - p;

            ret = mbedtls_asn1_traverse_sequence_of( &p, end_ext_octet,
                                      MBEDTLS_ASN1_TAG_CLASS_MASK,
                                      MBEDTLS_ASN1_CONTEXT_SPECIFIC,
                                      0, 0,
                                      x509_parse_subject_alt_name_cb,
                                      NULL );
            if( ret != 0 )
                goto err;
            break;

        case MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE:
            /* Parse extended key usage */
            frame->ext_key_usage_raw.p   = p;
            frame->ext_key_usage_raw.len = end_ext_octet - p;
            if( frame->ext_key_usage_raw.len == 0 )
            {
                ret = MBEDTLS_ERR_ASN1_INVALID_LENGTH;
                goto err;
            }

            /* Check structural sanity of extension. */
            ret = mbedtls_asn1_traverse_sequence_of( &p, end_ext_octet,
                                                     0xFF, MBEDTLS_ASN1_OID,
                                                     0, 0, NULL, NULL );
            if( ret != 0 )
                goto err;

            break;

        case MBEDTLS_X509_EXT_NS_CERT_TYPE:
            /* Parse netscape certificate type */
            ret = x509_get_ns_cert_type( &p, end_ext_octet,
                                         &frame->ns_cert_type );
            if( ret != 0 )
                goto err;
            break;

        case MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES:
        {
            int unknown_policy_seen = 0;
            frame->crt_policies_raw.p = p;
            frame->crt_policies_raw.len = end_ext_octet - p;

            /* Check structural sanity of extension. */
            ret = mbedtls_asn1_traverse_sequence_of( &p, end_ext_octet,
                                            0xFF, MBEDTLS_ASN1_CONSTRUCTED |
                                                  MBEDTLS_ASN1_SEQUENCE,
                                            0, 0,
                                            x509_crt_parse_policies_cb,
                                            &unknown_policy_seen );

            if( ret != 0 )
                goto err;

#if !defined(MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION)
            if( is_critical && ( unknown_policy_seen == 1 ) )
            {
                ret = MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
                goto err;
            }
#endif

            break;
        }

        default:
            /*
             * If this is a non-critical extension, which the oid layer
             * supports, but there isn't an X.509 parser for it,
             * skip the extension.
             */
#if !defined(MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION)
            if( is_critical )
                return( MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE );
#endif
            p = end_ext_octet;
            break;
    }

    return( 0 );

err:
    return( ret );
}

static int x509_crt_frame_parse_ext( mbedtls_x509_crt_frame *frame )
{
    int ret;
    unsigned char *p = frame->v3_ext.p;
    unsigned char *end = p + frame->v3_ext.len;

    if( p == end )
        return( 0 );

    ret = mbedtls_asn1_traverse_sequence_of( &p, end,
                 0xFF, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED,
                 0, 0, x509_crt_get_ext_cb, frame );

    if( ret == MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE )
        return( ret );
    if( ret == MBEDTLS_ERR_X509_INVALID_EXTENSIONS )
        return( ret );

    if( ret != 0 )
        ret += MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

    return( ret );
}

static int x509_crt_parse_frame( unsigned char *start,
                                 unsigned char *end,
                                 mbedtls_x509_crt_frame *frame )
{
    int ret;
    unsigned char *p;
    size_t len;

    mbedtls_x509_buf tmp;
    unsigned char *tbs_start;

    mbedtls_x509_buf outer_sig_alg;
    size_t inner_sig_alg_len;
    unsigned char *inner_sig_alg_start;

    memset( frame, 0, sizeof( *frame ) );

    /*
     * Certificate  ::=  SEQUENCE {
     *      tbsCertificate       TBSCertificate,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING
     * }
     *
     */
    p = start;

    frame->raw.p = p;
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );
    }

    /* NOTE: We are currently not checking that the `Certificate`
     * structure spans the entire buffer. */
    end = p + len;
    frame->raw.len = end - frame->raw.p;

    /*
     * TBSCertificate  ::=  SEQUENCE  { ...
     */
    frame->tbs.p = p;
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( ret + MBEDTLS_ERR_X509_INVALID_FORMAT );
    }
    tbs_start = p;

    /* Breadth-first parsing: Jump over TBS for now. */
    p += len;
    frame->tbs.len = p - frame->tbs.p;

    /*
     *  AlgorithmIdentifier ::= SEQUENCE { ...
     */
    outer_sig_alg.p = p;
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_ALG + ret );
    }
    p += len;
    outer_sig_alg.len = p - outer_sig_alg.p;

    /*
     *  signatureValue       BIT STRING
     */
    ret = mbedtls_x509_get_sig( &p, end, &tmp );
    if( ret != 0 )
        return( ret );
    frame->sig.p   = tmp.p;
    frame->sig.len = tmp.len;

    /* Check that we consumed the entire `Certificate` structure. */
    if( p != end )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    /* Parse TBSCertificate structure
     *
     * TBSCertificate  ::=  SEQUENCE  {
     *             version         [0]  EXPLICIT Version DEFAULT v1,
     *             serialNumber         CertificateSerialNumber,
     *             signature            AlgorithmIdentifier,
     *             issuer               Name,
     *             validity             Validity,
     *             subject              Name,
     *             subjectPublicKeyInfo SubjectPublicKeyInfo,
     *             issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                                  -- If present, version MUST be v2 or v3
     *             subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                                  -- If present, version MUST be v2 or v3
     *             extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                                  -- If present, version MUST be v3
     *         }
     */
    end = frame->tbs.p + frame->tbs.len;
    p = tbs_start;

    /*
     * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */
    {
        int version;
        ret = x509_get_version( &p, end, &version );
        if( ret != 0 )
            return( ret );

        if( version < 0 || version > 2 )
            return( MBEDTLS_ERR_X509_UNKNOWN_VERSION );

        frame->version = version + 1;
    }

    /*
     * CertificateSerialNumber  ::=  INTEGER
     */
    ret = mbedtls_x509_get_serial( &p, end, &tmp );
    if( ret != 0 )
        return( ret );

    frame->serial.p   = tmp.p;
    frame->serial.len = tmp.len;

    /*
     * signature            AlgorithmIdentifier
     */
    inner_sig_alg_start = p;
    ret = mbedtls_x509_get_sig_alg_raw( &p, end, &frame->sig_md,
                                        &frame->sig_pk, NULL );
    if( ret != 0 )
        return( ret );
    inner_sig_alg_len = p - inner_sig_alg_start;

    frame->sig_alg.p   = inner_sig_alg_start;
    frame->sig_alg.len = inner_sig_alg_len;

    /* Consistency check:
     * Inner and outer AlgorithmIdentifier structures must coincide:
     *
     * Quoting RFC 5280, Section 4.1.1.2:
     *    This field MUST contain the same algorithm identifier as the
     *    signature field in the sequence tbsCertificate (Section 4.1.2.3).
     */
    if( outer_sig_alg.len != inner_sig_alg_len ||
        memcmp( outer_sig_alg.p, inner_sig_alg_start, inner_sig_alg_len ) != 0 )
    {
        return( MBEDTLS_ERR_X509_SIG_MISMATCH );
    }

    /*
     * issuer               Name
     *
     * Name ::= CHOICE { -- only one possibility for now --
     *                      rdnSequence  RDNSequence }
     *
     * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     */
    frame->issuer_raw_with_hdr.p = p;

    ret = mbedtls_asn1_get_tag( &p, end, &len,
                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( ret + MBEDTLS_ERR_X509_INVALID_FORMAT );
    frame->issuer_raw.p   = p;
    frame->issuer_raw.len = len;
    p += len;

    /* Comparing the raw buffer to itself amounts to structural validation. */
    ret = mbedtls_x509_name_cmp_raw( &frame->issuer_raw,
                                     &frame->issuer_raw,
                                     NULL, NULL );
    if( ret != 0 )
        return( ret );

    frame->issuer_raw_with_hdr.len = p - frame->issuer_raw_with_hdr.p;

    /*
     * Validity ::= SEQUENCE { ...
     */
    ret = x509_get_dates( &p, end, &frame->valid_from, &frame->valid_to );
    if( ret != 0 )
        return( ret );

    /*
     * subject              Name
     *
     * Name ::= CHOICE { -- only one possibility for now --
     *                      rdnSequence  RDNSequence }
     *
     * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     */
    frame->subject_raw_with_hdr.p = p;

    ret = mbedtls_asn1_get_tag( &p, end, &len,
                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( ret + MBEDTLS_ERR_X509_INVALID_FORMAT );
    frame->subject_raw.p   = p;
    frame->subject_raw.len = len;
    p += len;

    /* Comparing the raw buffer to itself amounts to structural validation. */
    ret = mbedtls_x509_name_cmp_raw( &frame->subject_raw,
                                     &frame->subject_raw,
                                     NULL, NULL );
    if( ret != 0 )
        return( ret );

    frame->subject_raw_with_hdr.len = p - frame->subject_raw_with_hdr.p;

    /*
     * SubjectPublicKeyInfo
     */
    frame->pubkey_raw.p = p;
    ret = mbedtls_asn1_get_tag( &p, end, &len,
                            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( ret + MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );
    p += len;
    frame->pubkey_raw.len = p - frame->pubkey_raw.p;

    /*
     *  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     */
    if( frame->version == 2 || frame->version == 3 )
    {
        ret = x509_get_uid( &p, end, &tmp, 1 /* implicit tag */ );
        if( ret != 0 )
            return( ret );

        frame->issuer_id.p   = tmp.p;
        frame->issuer_id.len = tmp.len;
    }

    /*
     *  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     */
    if( frame->version == 2 || frame->version == 3 )
    {
        ret = x509_get_uid( &p, end, &tmp, 2 /* implicit tag */ );
        if( ret != 0 )
            return( ret );

        frame->subject_id.p   = tmp.p;
        frame->subject_id.len = tmp.len;
    }

    /*
     *  extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                       -- If present, version shall be v3
     */
#if !defined(MBEDTLS_X509_ALLOW_EXTENSIONS_NON_V3)
    if( frame->version == 3 )
#endif
    {
        if( p != end )
        {
            ret = mbedtls_asn1_get_tag( &p, end, &len,
                                        MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                        MBEDTLS_ASN1_CONSTRUCTED | 3 );
            if( len == 0 )
                ret = MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            if( ret != 0 )
                return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

            frame->v3_ext.p = p;
            frame->v3_ext.len = len;

            p += len;
        }

        ret = x509_crt_frame_parse_ext( frame );
        if( ret != 0 )
            return( ret );
    }

    /* Wrapup: Check that we consumed the entire `TBSCertificate` structure. */
    if( p != end )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    return( 0 );
}

static int x509_crt_subject_from_frame( mbedtls_x509_crt_frame *frame,
                                        mbedtls_x509_name *subject )
{
    unsigned char *p = frame->subject_raw.p;
    unsigned char *end = p + frame->subject_raw.len;

    return( mbedtls_x509_get_name( &p, end, subject ) );
}

static int x509_crt_issuer_from_frame( mbedtls_x509_crt_frame *frame,
                                       mbedtls_x509_name *issuer )
{
    unsigned char *p = frame->issuer_raw.p;
    unsigned char *end = p + frame->issuer_raw.len;

    return( mbedtls_x509_get_name( &p, end, issuer ) );
}

static int x509_crt_certificate_policies_from_frame(
    mbedtls_x509_crt_frame *frame,
    mbedtls_x509_sequence *certificate_policies )
{
    int ret;
    unsigned char *p   = frame->crt_policies_raw.p;
    unsigned char *end = p + frame->crt_policies_raw.len;

    memset( certificate_policies, 0, sizeof( *certificate_policies ) );

    if( ( frame->ext_types & MBEDTLS_X509_EXT_CERTIFICATE_POLICIES ) == 0 )
        return( 0 );

    /* Build linked list of policies in the certificate. */
    ret = mbedtls_asn1_traverse_sequence_of( &p, end,
                                             0xFF,
                                             MBEDTLS_ASN1_CONSTRUCTED |
                                             MBEDTLS_ASN1_SEQUENCE,
                                             0, 0,
                                             asn1_build_sequence_cb,
                                             (void*) &certificate_policies );
    if( ret != 0 )
        goto exit;

    /* Extract policy OIDs. */
    while( certificate_policies != NULL )
    {
        mbedtls_x509_buf_raw policy;
        policy.p   = certificate_policies->buf.p;
        policy.len = certificate_policies->buf.len;

        ret = x509_extract_policy_id( &policy );
        if( ret != 0 )
            return( ret );

        certificate_policies->buf.p = policy.p;
        certificate_policies->buf.len = policy.len;

        certificate_policies = certificate_policies->next;
    }

exit:

    if( ret != 0 )
        mbedtls_x509_sequence_free( certificate_policies );

    return( ret );
}

static int x509_crt_subject_alt_from_frame( mbedtls_x509_crt_frame *frame,
                                            mbedtls_x509_sequence *subject_alt )
{
    int ret;
    unsigned char *p   = frame->subject_alt_raw.p;
    unsigned char *end = p + frame->subject_alt_raw.len;

    memset( subject_alt, 0, sizeof( *subject_alt ) );

    if( ( frame->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME ) == 0 )
        return( 0 );

    ret = x509_get_subject_alt_name( p, end, subject_alt );
    if( ret != 0 )
        ret += MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    return( ret );
}

static int x509_crt_ext_key_usage_from_frame( mbedtls_x509_crt_frame *frame,
                                        mbedtls_x509_sequence *ext_key_usage )
{
    int ret;
    unsigned char *p   = frame->ext_key_usage_raw.p;
    unsigned char *end = p + frame->ext_key_usage_raw.len;

    memset( ext_key_usage, 0, sizeof( *ext_key_usage ) );

    if( ( frame->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE ) == 0 )
        return( 0 );

    ret = x509_get_ext_key_usage( &p, end, ext_key_usage );
    if( ret != 0 )
    {
        ret += MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        return( ret );
    }

    return( 0 );
}

static int x509_crt_pk_from_frame( mbedtls_x509_crt_frame *frame,
                                   mbedtls_pk_context *pk )
{
    unsigned char *p   = frame->pubkey_raw.p;
    unsigned char *end = p + frame->pubkey_raw.len;
    return( mbedtls_pk_parse_subpubkey( &p, end, pk ) );
}

/*
 * Parse and fill a single X.509 certificate in DER format
 */
static int x509_crt_parse_der_core( mbedtls_x509_crt *crt,
                                    const unsigned char *buf,
                                    size_t buflen,
                                    int make_copy )
{
    int ret;
    mbedtls_x509_crt_frame frame;

    if( crt == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    if( make_copy == 0 )
    {
        crt->raw.p = (unsigned char*) buf;
        crt->raw.len = buflen;
        crt->own_buffer = 0;
    }
    else
    {
        crt->raw.p = mbedtls_calloc( 1, buflen );
        if( crt->raw.p == NULL )
            return( MBEDTLS_ERR_X509_ALLOC_FAILED );
        crt->raw.len = buflen;
        memcpy( crt->raw.p, buf, buflen );

        crt->own_buffer = 1;
    }

    /* Parse CRT frame.
     * This omits:
     * - Issuer, Subject
     * - ExtKeyUsage, SubjectAltNames,
     * - Time
     * - PK
     */
    ret = x509_crt_parse_frame( crt->raw.p,
                                crt->raw.p + crt->raw.len,
                                &frame );
    if( ret != 0 )
        goto exit;

    /* Currently, we accept DER encoded CRTs with trailing garbage
     * and promise to not account for the garbage in the `raw` field.
     *
     * Note that this means that `crt->raw.len` is not necessarily the
     * full size of the heap buffer allocated at `crt->raw.p` in case
     * of copy-mode, but this is not a problem: freeing the buffer doesn't
     * need the size, and the garbage data doesn't need zeroization. */
    crt->raw.len = frame->raw.len;

    /* Copy frame to legacy CRT structure -- that's inefficient, but if
     * memory matters, the new CRT structure should be used anyway. */
    crt->tbs.p   = frame.tbs.p;
    crt->tbs.len = frame.tbs.len;
    crt->serial.p   = frame.serial.p;
    crt->serial.len = frame.serial.len;
    crt->issuer_raw.p   = frame.issuer_raw_with_hdr.p;
    crt->issuer_raw.len = frame.issuer_raw_with_hdr.len;
    crt->subject_raw.p   = frame.subject_raw_with_hdr.p;
    crt->subject_raw.len = frame.subject_raw_with_hdr.len;
    crt->issuer_raw_no_hdr = frame.issuer_raw;
    crt->subject_raw_no_hdr = frame.subject_raw;
    crt->issuer_id.p   = frame.issuer_id.p;
    crt->issuer_id.len = frame.issuer_id.len;
    crt->subject_id.p   = frame.subject_id.p;
    crt->subject_id.len = frame.subject_id.len;
    crt->pk_raw.p   = frame.pubkey_raw.p;
    crt->pk_raw.len = frame.pubkey_raw.len;
    crt->ext_key_usage_raw = frame.ext_key_usage_raw;
    crt->subject_alt_raw = frame.subject_alt_raw;
    crt->sig.p   = frame.sig.p;
    crt->sig.len = frame.sig.len;
    crt->valid_from = frame.valid_from;
    crt->valid_to = frame.valid_to;
    crt->v3_ext.p   = frame.v3_ext.p;
    crt->v3_ext.len = frame.v3_ext.len;
    crt->version      = frame.version;
    crt->ca_istrue    = frame.ca_istrue;
    crt->max_pathlen  = frame.max_pathlen;
    crt->ext_types    = frame.ext_types;
    crt->key_usage    = frame.key_usage;
    crt->ns_cert_type = frame.ns_cert_type;

    /*
     * Obtain the remaining fields from the frame.
     */

    {
        /* sig_oid: Previously, needed for convenience in
         * mbedtls_x509_crt_info(), now pure legacy burden. */
        unsigned char *tmp = frame.sig_alg.p;
        unsigned char *end = tmp + frame.sig_alg.len;
        mbedtls_x509_buf sig_oid, sig_params;

        ret = mbedtls_x509_get_alg( &tmp, end,
                                    &sig_oid, &sig_params );
        if( ret != 0 )
        {
            /* This should never happen, because we check
             * the sanity of the AlgorithmIdentifier structure
             * during frame parsing. */
            ret = MBEDTLS_ERR_X509_FATAL_ERROR;
            goto exit;
        }
        crt->sig_oid = sig_oid;

        /* Signature parameters */
        tmp = frame.sig_alg.p;
        ret = mbedtls_x509_get_sig_alg_raw( &tmp, end,
                                            &crt->sig_md, &crt->sig_pk,
                                            &crt->sig_opts );
        if( ret != 0 )
        {
            /* Again, this should never happen. */
            ret = MBEDTLS_ERR_X509_FATAL_ERROR;
            goto exit;
        }
    }

    ret = x509_crt_pk_from_frame( &frame, &crt->pk );
    if( ret != 0 )
        goto exit;

    ret = x509_crt_subject_from_frame( &frame, &crt->subject );
    if( ret != 0 )
        goto exit;

    ret = x509_crt_issuer_from_frame( &frame, &crt->issuer );
    if( ret != 0 )
        goto exit;

    ret = x509_crt_subject_alt_from_frame( &frame, &crt->subject_alt_names );
    if( ret != 0 )
        goto exit;

    ret = x509_crt_certificate_policies_from_frame( &frame,
                                         &crt->certificate_policies );
    if( ret != 0 )
        goto exit;

    ret = x509_crt_ext_key_usage_from_frame( &frame, &crt->ext_key_usage );
    if( ret != 0 )
        goto exit;

exit:
    if( ret != 0 )
        mbedtls_x509_crt_free( crt );

    return( ret );
}

/*
 * Parse one X.509 certificate in DER format from a buffer and add them to a
 * chained list
 */
static int mbedtls_x509_crt_parse_der_internal( mbedtls_x509_crt *chain,
                                                const unsigned char *buf,
                                                size_t buflen,
                                                int make_copy )
{
    int ret;
    mbedtls_x509_crt *crt = chain, *prev = NULL;

    /*
     * Check for valid input
     */
    if( crt == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    while( crt->version != 0 && crt->next != NULL )
    {
        prev = crt;
        crt = crt->next;
    }

    /*
     * Add new certificate on the end of the chain if needed.
     */
    if( crt->version != 0 && crt->next == NULL )
    {
        crt->next = mbedtls_calloc( 1, sizeof( mbedtls_x509_crt ) );

        if( crt->next == NULL )
            return( MBEDTLS_ERR_X509_ALLOC_FAILED );

        prev = crt;
        mbedtls_x509_crt_init( crt->next );
        crt = crt->next;
    }

    if( ( ret = x509_crt_parse_der_core( crt, buf, buflen, make_copy ) ) != 0 )
    {
        if( prev )
            prev->next = NULL;

        if( crt != chain )
            mbedtls_free( crt );

        return( ret );
    }

    return( 0 );
}

int mbedtls_x509_crt_parse_der_nocopy( mbedtls_x509_crt *chain,
                                       const unsigned char *buf,
                                       size_t buflen )
{
    return( mbedtls_x509_crt_parse_der_internal( chain, buf, buflen, 0 ) );
}

int mbedtls_x509_crt_parse_der( mbedtls_x509_crt *chain,
                                const unsigned char *buf,
                                size_t buflen )
{
    return( mbedtls_x509_crt_parse_der_internal( chain, buf, buflen, 1 ) );
}

/*
 * Parse one or more PEM certificates from a buffer and add them to the chained
 * list
 */
int mbedtls_x509_crt_parse( mbedtls_x509_crt *chain,
                            const unsigned char *buf,
                            size_t buflen )
{
#if defined(MBEDTLS_PEM_PARSE_C)
    int success = 0, first_error = 0, total_failed = 0;
    int buf_format = MBEDTLS_X509_FORMAT_DER;
#endif

    /*
     * Check for valid input
     */
    if( chain == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    /*
     * Determine buffer content. Buffer contains either one DER certificate or
     * one or more PEM certificates.
     */
#if defined(MBEDTLS_PEM_PARSE_C)
    if( buflen != 0 && buf[buflen - 1] == '\0' &&
        strstr( (const char *) buf, "-----BEGIN CERTIFICATE-----" ) != NULL )
    {
        buf_format = MBEDTLS_X509_FORMAT_PEM;
    }

    if( buf_format == MBEDTLS_X509_FORMAT_DER )
        return mbedtls_x509_crt_parse_der( chain, buf, buflen );
#else
    return mbedtls_x509_crt_parse_der( chain, buf, buflen );
#endif

#if defined(MBEDTLS_PEM_PARSE_C)
    if( buf_format == MBEDTLS_X509_FORMAT_PEM )
    {
        int ret;
        mbedtls_pem_context pem;

        /* 1 rather than 0 since the terminating NULL byte is counted in */
        while( buflen > 1 )
        {
            size_t use_len;
            mbedtls_pem_init( &pem );

            /* If we get there, we know the string is null-terminated */
            ret = mbedtls_pem_read_buffer( &pem,
                           "-----BEGIN CERTIFICATE-----",
                           "-----END CERTIFICATE-----",
                           buf, NULL, 0, &use_len );

            if( ret == 0 )
            {
                /*
                 * Was PEM encoded
                 */
                buflen -= use_len;
                buf += use_len;
            }
            else if( ret == MBEDTLS_ERR_PEM_BAD_INPUT_DATA )
            {
                return( ret );
            }
            else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
            {
                mbedtls_pem_free( &pem );

                /*
                 * PEM header and footer were found
                 */
                buflen -= use_len;
                buf += use_len;

                if( first_error == 0 )
                    first_error = ret;

                total_failed++;
                continue;
            }
            else
                break;

            ret = mbedtls_x509_crt_parse_der( chain, pem.buf, pem.buflen );

            mbedtls_pem_free( &pem );

            if( ret != 0 )
            {
                /*
                 * Quit parsing on a memory error
                 */
                if( ret == MBEDTLS_ERR_X509_ALLOC_FAILED )
                    return( ret );

                if( first_error == 0 )
                    first_error = ret;

                total_failed++;
                continue;
            }

            success = 1;
        }
    }

    if( success )
        return( total_failed );
    else if( first_error )
        return( first_error );
    else
        return( MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT );
#endif /* MBEDTLS_PEM_PARSE_C */
}

#if defined(MBEDTLS_FS_IO)
/*
 * Load one or more certificates and add them to the chained list
 */
int mbedtls_x509_crt_parse_file( mbedtls_x509_crt *chain, const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = mbedtls_x509_crt_parse( chain, buf, n );

    mbedtls_platform_zeroize( buf, n );
    mbedtls_free( buf );

    return( ret );
}

int mbedtls_x509_crt_parse_path( mbedtls_x509_crt *chain, const char *path )
{
    int ret = 0;
#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)
    int w_ret;
    WCHAR szDir[MAX_PATH];
    char filename[MAX_PATH];
    char *p;
    size_t len = strlen( path );

    WIN32_FIND_DATAW file_data;
    HANDLE hFind;

    if( len > MAX_PATH - 3 )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    memset( szDir, 0, sizeof(szDir) );
    memset( filename, 0, MAX_PATH );
    memcpy( filename, path, len );
    filename[len++] = '\\';
    p = filename + len;
    filename[len++] = '*';

    w_ret = MultiByteToWideChar( CP_ACP, 0, filename, (int)len, szDir,
                                 MAX_PATH - 3 );
    if( w_ret == 0 )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    hFind = FindFirstFileW( szDir, &file_data );
    if( hFind == INVALID_HANDLE_VALUE )
        return( MBEDTLS_ERR_X509_FILE_IO_ERROR );

    len = MAX_PATH - len;
    do
    {
        memset( p, 0, len );

        if( file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
            continue;

        w_ret = WideCharToMultiByte( CP_ACP, 0, file_data.cFileName,
                                     lstrlenW( file_data.cFileName ),
                                     p, (int) len - 1,
                                     NULL, NULL );
        if( w_ret == 0 )
        {
            ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
            goto cleanup;
        }

        w_ret = mbedtls_x509_crt_parse_file( chain, filename );
        if( w_ret < 0 )
            ret++;
        else
            ret += w_ret;
    }
    while( FindNextFileW( hFind, &file_data ) != 0 );

    if( GetLastError() != ERROR_NO_MORE_FILES )
        ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;

cleanup:
    FindClose( hFind );
#else /* _WIN32 */
    int t_ret;
    int snp_ret;
    struct stat sb;
    struct dirent *entry;
    char entry_name[MBEDTLS_X509_MAX_FILE_PATH_LEN];
    DIR *dir = opendir( path );

    if( dir == NULL )
        return( MBEDTLS_ERR_X509_FILE_IO_ERROR );

#if defined(MBEDTLS_THREADING_C)
    if( ( ret = mbedtls_mutex_lock( &mbedtls_threading_readdir_mutex ) ) != 0 )
    {
        closedir( dir );
        return( ret );
    }
#endif /* MBEDTLS_THREADING_C */

    while( ( entry = readdir( dir ) ) != NULL )
    {
        snp_ret = mbedtls_snprintf( entry_name, sizeof entry_name,
                                    "%s/%s", path, entry->d_name );

        if( snp_ret < 0 || (size_t)snp_ret >= sizeof entry_name )
        {
            ret = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
            goto cleanup;
        }
        else if( stat( entry_name, &sb ) == -1 )
        {
            ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
            goto cleanup;
        }

        if( !S_ISREG( sb.st_mode ) )
            continue;

        // Ignore parse errors
        //
        t_ret = mbedtls_x509_crt_parse_file( chain, entry_name );
        if( t_ret < 0 )
            ret++;
        else
            ret += t_ret;
    }

cleanup:
    closedir( dir );

#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &mbedtls_threading_readdir_mutex ) != 0 )
        ret = MBEDTLS_ERR_THREADING_MUTEX_ERROR;
#endif /* MBEDTLS_THREADING_C */

#endif /* _WIN32 */

    return( ret );
}
#endif /* MBEDTLS_FS_IO */

/*
 * OtherName ::= SEQUENCE {
 *      type-id    OBJECT IDENTIFIER,
 *      value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 * HardwareModuleName ::= SEQUENCE {
 *                           hwType OBJECT IDENTIFIER,
 *                           hwSerialNum OCTET STRING }
 *
 * NOTE: we currently only parse and use otherName of type HwModuleName,
 * as defined in RFC 4108.
 */
static int x509_get_other_name( const mbedtls_x509_buf *subject_alt_name,
                                mbedtls_x509_san_other_name *other_name )
{
    int ret = 0;
    size_t len;
    unsigned char *p = subject_alt_name->p;
    const unsigned char *end = p + subject_alt_name->len;
    mbedtls_x509_buf cur_oid;

    if( ( subject_alt_name->tag &
        ( MBEDTLS_ASN1_TAG_CLASS_MASK | MBEDTLS_ASN1_TAG_VALUE_MASK ) ) !=
        ( MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_OTHER_NAME ) )
    {
        /*
         * The given subject alternative name is not of type "othername".
         */
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );
    }

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                                      MBEDTLS_ASN1_OID ) ) != 0 )
        return( ret );

    cur_oid.tag = MBEDTLS_ASN1_OID;
    cur_oid.p = p;
    cur_oid.len = len;

    /*
     * Only HwModuleName is currently supported.
     */
    if( MBEDTLS_OID_CMP( MBEDTLS_OID_ON_HW_MODULE_NAME, &cur_oid ) != 0 )
    {
        return( MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE );
    }

    p += len;
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC ) ) != 0 )
    {
        return( ret );
    }

    if( end != p + len )
    {
        return( MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
       return( ret );

    if( end != p + len )
    {
        return( MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OID ) ) != 0 )
        return( ret );

    other_name->value.hardware_module_name.oid.tag = MBEDTLS_ASN1_OID;
    other_name->value.hardware_module_name.oid.p = p;
    other_name->value.hardware_module_name.oid.len = len;

    p += len;
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                                      MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        return( ret );

    other_name->value.hardware_module_name.val.tag = MBEDTLS_ASN1_OCTET_STRING;
    other_name->value.hardware_module_name.val.p = p;
    other_name->value.hardware_module_name.val.len = len;
    p += len;
    if( p != end )
    {
        return( MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }
    return( 0 );
}

static int x509_info_subject_alt_name( char **buf, size_t *size,
                                       const mbedtls_x509_sequence
                                                    *subject_alt_name,
                                       const char *prefix )
{
    int ret;
    size_t n = *size;
    char *p = *buf;
    const mbedtls_x509_sequence *cur = subject_alt_name;
    mbedtls_x509_subject_alternative_name san;
    int parse_ret;

    while( cur != NULL )
    {
        memset( &san, 0, sizeof( san ) );
        parse_ret = mbedtls_x509_parse_subject_alt_name( &cur->buf, &san );
        if( parse_ret != 0 )
        {
            if( parse_ret == MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE )
            {
                ret = mbedtls_snprintf( p, n, "\n%s    <unsupported>", prefix );
                MBEDTLS_X509_SAFE_SNPRINTF;
            }
            else
            {
                ret = mbedtls_snprintf( p, n, "\n%s    <malformed>", prefix );
                MBEDTLS_X509_SAFE_SNPRINTF;
            }
            cur = cur->next;
            continue;
        }

        switch( san.type )
        {
            /*
             * otherName
             */
            case MBEDTLS_X509_SAN_OTHER_NAME:
            {
                mbedtls_x509_san_other_name *other_name = &san.san.other_name;

                ret = mbedtls_snprintf( p, n, "\n%s    otherName :", prefix );
                MBEDTLS_X509_SAFE_SNPRINTF;

                if( MBEDTLS_OID_CMP( MBEDTLS_OID_ON_HW_MODULE_NAME,
                                     &other_name->value.hardware_module_name.oid ) != 0 )
                {
                    ret = mbedtls_snprintf( p, n, "\n%s        hardware module name :", prefix );
                    MBEDTLS_X509_SAFE_SNPRINTF;
                    ret = mbedtls_snprintf( p, n, "\n%s            hardware type          : ", prefix );
                    MBEDTLS_X509_SAFE_SNPRINTF;

                    ret = mbedtls_oid_get_numeric_string( p, n, &other_name->value.hardware_module_name.oid );
                    MBEDTLS_X509_SAFE_SNPRINTF;

                    ret = mbedtls_snprintf( p, n, "\n%s            hardware serial number : ", prefix );
                    MBEDTLS_X509_SAFE_SNPRINTF;

                    if( other_name->value.hardware_module_name.val.len >= n )
                    {
                        *p = '\0';
                        return( MBEDTLS_ERR_X509_BUFFER_TOO_SMALL );
                    }

                    memcpy( p, other_name->value.hardware_module_name.val.p,
                            other_name->value.hardware_module_name.val.len );
                    p += other_name->value.hardware_module_name.val.len;

                    n -= other_name->value.hardware_module_name.val.len;

                }/* MBEDTLS_OID_ON_HW_MODULE_NAME */
            }
            break;

            /*
             * dNSName
             */
            case MBEDTLS_X509_SAN_DNS_NAME:
            {
                ret = mbedtls_snprintf( p, n, "\n%s    dNSName : ", prefix );
                MBEDTLS_X509_SAFE_SNPRINTF;
                if( san.san.unstructured_name.len >= n )
                {
                    *p = '\0';
                    return( MBEDTLS_ERR_X509_BUFFER_TOO_SMALL );
                }

                memcpy( p, san.san.unstructured_name.p, san.san.unstructured_name.len );
                p += san.san.unstructured_name.len;
                n -= san.san.unstructured_name.len;
            }
            break;

            /*
             * Type not supported, skip item.
             */
            default:
                ret = mbedtls_snprintf( p, n, "\n%s    <unsupported>", prefix );
                MBEDTLS_X509_SAFE_SNPRINTF;
                break;
        }

        cur = cur->next;
    }

    *p = '\0';

    *size = n;
    *buf = p;

    return( 0 );
}

int mbedtls_x509_parse_subject_alt_name( const mbedtls_x509_buf *san_buf,
                                         mbedtls_x509_subject_alternative_name *san )
{
    int ret;
    switch( san_buf->tag &
            ( MBEDTLS_ASN1_TAG_CLASS_MASK |
              MBEDTLS_ASN1_TAG_VALUE_MASK ) )
    {
        /*
         * otherName
         */
        case( MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_OTHER_NAME ):
        {
            mbedtls_x509_san_other_name other_name;

            ret = x509_get_other_name( san_buf, &other_name );
            if( ret != 0 )
                return( ret );

            memset( san, 0, sizeof( mbedtls_x509_subject_alternative_name ) );
            san->type = MBEDTLS_X509_SAN_OTHER_NAME;
            memcpy( &san->san.other_name,
                    &other_name, sizeof( other_name ) );

        }
        break;

        /*
         * dNSName
         */
        case( MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_DNS_NAME ):
        {
            memset( san, 0, sizeof( mbedtls_x509_subject_alternative_name ) );
            san->type = MBEDTLS_X509_SAN_DNS_NAME;

            memcpy( &san->san.unstructured_name,
                    san_buf, sizeof( *san_buf ) );

        }
        break;

        /*
         * Type not supported
         */
        default:
            return( MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE );
    }
    return( 0 );
}

#define PRINT_ITEM(i)                           \
    {                                           \
        ret = mbedtls_snprintf( p, n, "%s" i, sep );    \
        MBEDTLS_X509_SAFE_SNPRINTF;                        \
        sep = ", ";                             \
    }

#define CERT_TYPE(type,name)                    \
    if( ns_cert_type & (type) )                 \
        PRINT_ITEM( name );

static int x509_info_cert_type( char **buf, size_t *size,
                                unsigned char ns_cert_type )
{
    int ret;
    size_t n = *size;
    char *p = *buf;
    const char *sep = "";

    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT,         "SSL Client" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER,         "SSL Server" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_EMAIL,              "Email" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING,     "Object Signing" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_RESERVED,           "Reserved" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_SSL_CA,             "SSL CA" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA,           "Email CA" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA,  "Object Signing CA" );

    *size = n;
    *buf = p;

    return( 0 );
}

#define KEY_USAGE(code,name)    \
    if( key_usage & (code) )    \
        PRINT_ITEM( name );

static int x509_info_key_usage( char **buf, size_t *size,
                                unsigned int key_usage )
{
    int ret;
    size_t n = *size;
    char *p = *buf;
    const char *sep = "";

    KEY_USAGE( MBEDTLS_X509_KU_DIGITAL_SIGNATURE,    "Digital Signature" );
    KEY_USAGE( MBEDTLS_X509_KU_NON_REPUDIATION,      "Non Repudiation" );
    KEY_USAGE( MBEDTLS_X509_KU_KEY_ENCIPHERMENT,     "Key Encipherment" );
    KEY_USAGE( MBEDTLS_X509_KU_DATA_ENCIPHERMENT,    "Data Encipherment" );
    KEY_USAGE( MBEDTLS_X509_KU_KEY_AGREEMENT,        "Key Agreement" );
    KEY_USAGE( MBEDTLS_X509_KU_KEY_CERT_SIGN,        "Key Cert Sign" );
    KEY_USAGE( MBEDTLS_X509_KU_CRL_SIGN,             "CRL Sign" );
    KEY_USAGE( MBEDTLS_X509_KU_ENCIPHER_ONLY,        "Encipher Only" );
    KEY_USAGE( MBEDTLS_X509_KU_DECIPHER_ONLY,        "Decipher Only" );

    *size = n;
    *buf = p;

    return( 0 );
}

static int x509_info_ext_key_usage( char **buf, size_t *size,
                                    const mbedtls_x509_sequence *extended_key_usage )
{
    int ret;
    const char *desc;
    size_t n = *size;
    char *p = *buf;
    const mbedtls_x509_sequence *cur = extended_key_usage;
    const char *sep = "";

    while( cur != NULL )
    {
        if( mbedtls_oid_get_extended_key_usage( &cur->buf, &desc ) != 0 )
            desc = "???";

        ret = mbedtls_snprintf( p, n, "%s%s", sep, desc );
        MBEDTLS_X509_SAFE_SNPRINTF;

        sep = ", ";

        cur = cur->next;
    }

    *size = n;
    *buf = p;

    return( 0 );
}

static int x509_info_cert_policies( char **buf, size_t *size,
                                    const mbedtls_x509_sequence *certificate_policies )
{
    int ret;
    const char *desc;
    size_t n = *size;
    char *p = *buf;
    const mbedtls_x509_sequence *cur = certificate_policies;
    const char *sep = "";

    while( cur != NULL )
    {
        if( mbedtls_oid_get_certificate_policies( &cur->buf, &desc ) != 0 )
            desc = "???";

        ret = mbedtls_snprintf( p, n, "%s%s", sep, desc );
        MBEDTLS_X509_SAFE_SNPRINTF;

        sep = ", ";

        cur = cur->next;
    }

    *size = n;
    *buf = p;

    return( 0 );
}

/*
 * Return an informational string about the certificate.
 */
#define BEFORE_COLON    18
#define BC              "18"
int mbedtls_x509_crt_info( char *buf, size_t size, const char *prefix,
                   const mbedtls_x509_crt *crt )
{
    int ret;
    size_t n;
    char *p;
    char key_size_str[BEFORE_COLON];

    p = buf;
    n = size;

    if( NULL == crt )
    {
        ret = mbedtls_snprintf( p, n, "\nCertificate is uninitialised!\n" );
        MBEDTLS_X509_SAFE_SNPRINTF;

        return( (int) ( size - n ) );
    }

    ret = mbedtls_snprintf( p, n, "%scert. version     : %d\n",
                               prefix, crt->version );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_snprintf( p, n, "%sserial number     : ",
                               prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_x509_serial_gets( p, n, &crt->serial );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%sissuer name       : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_x509_dn_gets( p, n, &crt->issuer  );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%ssubject name      : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_x509_dn_gets( p, n, &crt->subject );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%sissued  on        : " \
                   "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                   crt->valid_from.year, crt->valid_from.mon,
                   crt->valid_from.day,  crt->valid_from.hour,
                   crt->valid_from.min,  crt->valid_from.sec );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%sexpires on        : " \
                   "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                   crt->valid_to.year, crt->valid_to.mon,
                   crt->valid_to.day,  crt->valid_to.hour,
                   crt->valid_to.min,  crt->valid_to.sec );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%ssigned using      : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_x509_sig_alg_gets( p, n, sig_info.sig_pk,
                                     sig_info.sig_md, sig_info.sig_opts );
    MBEDTLS_X509_SAFE_SNPRINTF;

    /* Key size */
    if( ( ret = mbedtls_x509_key_size_helper( key_size_str, BEFORE_COLON,
                                      mbedtls_pk_get_name( &crt->pk ) ) ) != 0 )
    {
        return( ret );
    }

    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s: %d bits", prefix, key_size_str,
                          (int) mbedtls_pk_get_bitlen( &crt->pk ) );
    MBEDTLS_X509_SAFE_SNPRINTF;

    /*
     * Optional extensions
     */

    if( crt->ext_types & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS )
    {
        ret = mbedtls_snprintf( p, n, "\n%sbasic constraints : CA=%s", prefix,
                        crt->ca_istrue ? "true" : "false" );
        MBEDTLS_X509_SAFE_SNPRINTF;

        if( crt->max_pathlen > 0 )
        {
            ret = mbedtls_snprintf( p, n, ", max_pathlen=%d", crt->max_pathlen - 1 );
            MBEDTLS_X509_SAFE_SNPRINTF;
        }
    }

    if( crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME )
    {
        ret = mbedtls_snprintf( p, n, "\n%ssubject alt name  :", prefix );
        MBEDTLS_X509_SAFE_SNPRINTF;

        if( ( ret = x509_info_subject_alt_name( &p, &n,
                                                &crt->subject_alt_names,
                                                prefix ) ) != 0 )
            return( ret );
    }

    if( crt->ext_types & MBEDTLS_X509_EXT_NS_CERT_TYPE )
    {
        ret = mbedtls_snprintf( p, n, "\n%scert. type        : ", prefix );
        MBEDTLS_X509_SAFE_SNPRINTF;

        if( ( ret = x509_info_cert_type( &p, &n, crt->ns_cert_type ) ) != 0 )
            return( ret );
    }

    if( crt->ext_types & MBEDTLS_X509_EXT_KEY_USAGE )
    {
        ret = mbedtls_snprintf( p, n, "\n%skey usage         : ", prefix );
        MBEDTLS_X509_SAFE_SNPRINTF;

        if( ( ret = x509_info_key_usage( &p, &n, crt->key_usage ) ) != 0 )
            return( ret );
    }

    if( crt->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE )
    {
        ret = mbedtls_snprintf( p, n, "\n%sext key usage     : ", prefix );
        MBEDTLS_X509_SAFE_SNPRINTF;

        if( ( ret = x509_info_ext_key_usage( &p, &n,
                                             &crt->ext_key_usage ) ) != 0 )
            return( ret );
    }

    if( crt->ext_types & MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES )
    {
        ret = mbedtls_snprintf( p, n, "\n%scertificate policies : ", prefix );
        MBEDTLS_X509_SAFE_SNPRINTF;

        if( ( ret = x509_info_cert_policies( &p, &n,
                                             &crt->certificate_policies ) ) != 0 )
            return( ret );
    }

    ret = mbedtls_snprintf( p, n, "\n" );
    MBEDTLS_X509_SAFE_SNPRINTF;

    return( (int) ( size - n ) );
}

struct x509_crt_verify_string {
    int code;
    const char *string;
};

static const struct x509_crt_verify_string x509_crt_verify_strings[] = {
    { MBEDTLS_X509_BADCERT_EXPIRED,       "The certificate validity has expired" },
    { MBEDTLS_X509_BADCERT_REVOKED,       "The certificate has been revoked (is on a CRL)" },
    { MBEDTLS_X509_BADCERT_CN_MISMATCH,   "The certificate Common Name (CN) does not match with the expected CN" },
    { MBEDTLS_X509_BADCERT_NOT_TRUSTED,   "The certificate is not correctly signed by the trusted CA" },
    { MBEDTLS_X509_BADCRL_NOT_TRUSTED,    "The CRL is not correctly signed by the trusted CA" },
    { MBEDTLS_X509_BADCRL_EXPIRED,        "The CRL is expired" },
    { MBEDTLS_X509_BADCERT_MISSING,       "Certificate was missing" },
    { MBEDTLS_X509_BADCERT_SKIP_VERIFY,   "Certificate verification was skipped" },
    { MBEDTLS_X509_BADCERT_OTHER,         "Other reason (can be used by verify callback)" },
    { MBEDTLS_X509_BADCERT_FUTURE,        "The certificate validity starts in the future" },
    { MBEDTLS_X509_BADCRL_FUTURE,         "The CRL is from the future" },
    { MBEDTLS_X509_BADCERT_KEY_USAGE,     "Usage does not match the keyUsage extension" },
    { MBEDTLS_X509_BADCERT_EXT_KEY_USAGE, "Usage does not match the extendedKeyUsage extension" },
    { MBEDTLS_X509_BADCERT_NS_CERT_TYPE,  "Usage does not match the nsCertType extension" },
    { MBEDTLS_X509_BADCERT_BAD_MD,        "The certificate is signed with an unacceptable hash." },
    { MBEDTLS_X509_BADCERT_BAD_PK,        "The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA)." },
    { MBEDTLS_X509_BADCERT_BAD_KEY,       "The certificate is signed with an unacceptable key (eg bad curve, RSA too short)." },
    { MBEDTLS_X509_BADCRL_BAD_MD,         "The CRL is signed with an unacceptable hash." },
    { MBEDTLS_X509_BADCRL_BAD_PK,         "The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA)." },
    { MBEDTLS_X509_BADCRL_BAD_KEY,        "The CRL is signed with an unacceptable key (eg bad curve, RSA too short)." },
    { 0, NULL }
};

int mbedtls_x509_crt_verify_info( char *buf, size_t size, const char *prefix,
                          uint32_t flags )
{
    int ret;
    const struct x509_crt_verify_string *cur;
    char *p = buf;
    size_t n = size;

    for( cur = x509_crt_verify_strings; cur->string != NULL ; cur++ )
    {
        if( ( flags & cur->code ) == 0 )
            continue;

        ret = mbedtls_snprintf( p, n, "%s%s\n", prefix, cur->string );
        MBEDTLS_X509_SAFE_SNPRINTF;
        flags ^= cur->code;
    }

    if( flags != 0 )
    {
        ret = mbedtls_snprintf( p, n, "%sUnknown reason "
                                       "(this should not happen)\n", prefix );
        MBEDTLS_X509_SAFE_SNPRINTF;
    }

    return( (int) ( size - n ) );
}

#if defined(MBEDTLS_X509_CHECK_KEY_USAGE)
int mbedtls_x509_crt_check_key_usage( const mbedtls_x509_crt *crt,
                                      unsigned int usage )
{
    unsigned int usage_must, usage_may;
    unsigned int may_mask = MBEDTLS_X509_KU_ENCIPHER_ONLY
                          | MBEDTLS_X509_KU_DECIPHER_ONLY;

    if( ( crt->ext_types & MBEDTLS_X509_EXT_KEY_USAGE ) == 0 )
        return( 0 );

    usage_must = usage & ~may_mask;

    if( ( ( crt->key_usage & ~may_mask ) & usage_must ) != usage_must )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    usage_may = usage & may_mask;

    if( ( ( crt->key_usage & may_mask ) | usage_may ) != usage_may )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    return( 0 );
}
#endif

#if defined(MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE)
typedef struct
{
    const char *oid;
    size_t oid_len;
} x509_crt_check_ext_key_usage_cb_ctx_t;

static int x509_crt_check_ext_key_usage_cb( void *ctx,
                                            int tag,
                                            unsigned char *data,
                                            size_t data_len )
{
    x509_crt_check_ext_key_usage_cb_ctx_t *cb_ctx =
        (x509_crt_check_ext_key_usage_cb_ctx_t *) ctx;
    ((void) tag);

    if( MBEDTLS_OID_CMP_RAW( MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE,
                             data, data_len ) == 0 )
    {
        return( 1 );
    }

    if( data_len == cb_ctx->oid_len && memcmp( data, cb_ctx->oid,
                                               data_len ) == 0 )
    {
        return( 1 );
    }

    return( 0 );
}

int mbedtls_x509_crt_check_extended_key_usage( const mbedtls_x509_crt *crt,
                                               const char *usage_oid,
                                               size_t usage_len )
{
    int ret;
    unsigned ext_types;
    unsigned char *p, *end;
    x509_crt_check_ext_key_usage_cb_ctx_t cb_ctx = { usage_oid, usage_len };

    /* Extension is not mandatory, absent means no restriction */
    ext_types = crt->ext_types;
    if( ( ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE ) == 0 )
        return( 0 );

    p = crt->ext_key_usage_raw.p;
    end = p + crt->ext_key_usage_raw.len;

    ret = mbedtls_asn1_traverse_sequence_of( &p, end,
                                             0xFF, MBEDTLS_ASN1_OID, 0, 0,
                                             x509_crt_check_ext_key_usage_cb,
                                             &cb_ctx );
    if( ret == 1 )
        return( 0 );

    return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );
}
#endif /* MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE */

#if defined(MBEDTLS_X509_CRL_PARSE_C)
/*
 * Return 1 if the certificate is revoked, or 0 otherwise.
 */
static int x509_serial_is_revoked( unsigned char const *serial,
                                 size_t serial_len,
                                 const mbedtls_x509_crl *crl )
{
    const mbedtls_x509_crl_entry *cur = &crl->entry;

    while( cur != NULL && cur->serial.len != 0 )
    {
        if( serial_len == cur->serial.len &&
            memcmp( serial, cur->serial.p, serial_len ) == 0 )
        {
            if( mbedtls_x509_time_is_past( &cur->revocation_date ) )
                return( 1 );
        }

        cur = cur->next;
    }

    return( 0 );
}

int mbedtls_x509_crt_is_revoked( const mbedtls_x509_crt *crt,
                                 const mbedtls_x509_crl *crl )
{
    return( x509_serial_is_revoked( crt->serial.p,
                                    crt->serial.len,
                                    crl ) );
}

/*
 * Check that the given certificate is not revoked according to the CRL.
 * Skip validation if no CRL for the given CA is present.
 */
static int x509_crt_verifycrl( unsigned char *crt_serial,
                               size_t crt_serial_len,
                               mbedtls_x509_crt *ca,
                               mbedtls_x509_crl *crl_list,
                               const mbedtls_x509_crt_profile *profile )
{
    int flags = 0;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    const mbedtls_md_info_t *md_info;

    if( ca == NULL )
        return( flags );

    while( crl_list != NULL )
    {
        if( crl_list->version == 0 ||
            mbedtls_x509_name_cmp_raw( &crl_list->issuer_raw_no_hdr,
                                       &ca->subject_raw_no_hdr,
                                       NULL, NULL ) != 0 )
        {
            crl_list = crl_list->next;
            continue;
        }

        /*
         * Check if the CA is configured to sign CRLs
         */
#if defined(MBEDTLS_X509_CHECK_KEY_USAGE)
        if( mbedtls_x509_crt_check_key_usage( ca,
                                              MBEDTLS_X509_KU_CRL_SIGN ) != 0 )
        {
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }
#endif

        /*
         * Check if CRL is correctly signed by the trusted CA
         */
        if( x509_profile_check_md_alg( profile, crl_list->sig_md ) != 0 )
            flags |= MBEDTLS_X509_BADCRL_BAD_MD;

        if( x509_profile_check_pk_alg( profile, crl_list->sig_pk ) != 0 )
            flags |= MBEDTLS_X509_BADCRL_BAD_PK;

        md_info = mbedtls_md_info_from_type( crl_list->sig_md );
        if( mbedtls_md( md_info, crl_list->tbs.p, crl_list->tbs.len, hash ) != 0 )
        {
            /* Note: this can't happen except after an internal error */
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }

        if( x509_profile_check_key( profile, &ca->pk ) != 0 )
            flags |= MBEDTLS_X509_BADCERT_BAD_KEY;

        if( mbedtls_pk_verify_ext( crl_list->sig_pk, crl_list->sig_opts, &ca->pk,
                           crl_list->sig_md, hash, mbedtls_md_get_size( md_info ),
                           crl_list->sig.p, crl_list->sig.len ) != 0 )
        {
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }

        /*
         * Check for validity of CRL (Do not drop out)
         */
        if( mbedtls_x509_time_is_past( &crl_list->next_update ) )
            flags |= MBEDTLS_X509_BADCRL_EXPIRED;

        if( mbedtls_x509_time_is_future( &crl_list->this_update ) )
            flags |= MBEDTLS_X509_BADCRL_FUTURE;

        /*
         * Check if certificate is revoked
         */
        if( x509_serial_is_revoked( crt_serial, crt_serial_len,
                                    crl_list ) )
        {
            flags |= MBEDTLS_X509_BADCERT_REVOKED;
            break;
        }

        crl_list = crl_list->next;
    }

    return( flags );
}
#endif /* MBEDTLS_X509_CRL_PARSE_C */

/*
 * Check the signature of a certificate by its parent
 */
static int x509_crt_check_signature( const mbedtls_x509_crt_sig_info *sig_info,
                                     mbedtls_x509_crt *parent,
                                     mbedtls_x509_crt_restart_ctx *rs_ctx )
{
    int ret;
    mbedtls_pk_context *pk;

    ret = x509_crt_pk_acquire( parent, &pk );
    if( ret != 0 )
        return( MBEDTLS_ERR_X509_FATAL_ERROR );

    /* Skip expensive computation on obvious mismatch */
    if( ! mbedtls_pk_can_do( pk, sig_info->sig_pk ) )
    {
        ret = -1;
        goto exit;
    }

#if !( defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE) )
    ((void) rs_ctx);
#else
    if( rs_ctx != NULL && sig_info->sig_pk == MBEDTLS_PK_ECDSA )
    {
        ret = mbedtls_pk_verify_restartable( pk,
                    sig_info->sig_md,
                    sig_info->crt_hash, sig_info->crt_hash_len,
                    sig_info->sig.p, sig_info->sig.len,
                    &rs_ctx->pk );
    }
    else
#endif
    {
        ret = mbedtls_pk_verify_ext( sig_info->sig_pk,
                                     sig_info->sig_opts,
                                     pk,
                                     sig_info->sig_md,
                                     sig_info->crt_hash, sig_info->crt_hash_len,
                                     sig_info->sig.p, sig_info->sig.len );
    }

exit:
    x509_crt_pk_release( parent, pk );
    return( ret );
}

/*
 * Check if 'parent' is a suitable parent (signing CA) for 'child'.
 * Return 0 if yes, -1 if not.
 *
 * top means parent is a locally-trusted certificate
 */
static int x509_crt_check_parent( const mbedtls_x509_crt_sig_info *child_sig,
                                  const mbedtls_x509_crt *parent,
                                  int top )
{
    int need_ca_bit;

    /* Parent must be the issuer */
    if( mbedtls_x509_name_cmp_raw( &child_sig->issuer_raw,
                                   &parent->subject_raw_no_hdr,
                                   NULL, NULL ) != 0 )
    {
        return( -1 );
    }

    /* Parent must have the basicConstraints CA bit set as a general rule */
    need_ca_bit = 1;

    /* Exception: v1/v2 certificates that are locally trusted. */
    if( top && parent->version < 3 )
        need_ca_bit = 0;

    if( need_ca_bit && ! parent->ca_istrue )
        return( -1 );

#if defined(MBEDTLS_X509_CHECK_KEY_USAGE)
    if( need_ca_bit &&
        mbedtls_x509_crt_check_key_usage( parent, MBEDTLS_X509_KU_KEY_CERT_SIGN ) != 0 )
    {
        return( -1 );
    }
#endif

    return( 0 );
}

typedef struct mbedtls_x509_crt_sig_info
{
    mbedtls_md_type_t sig_md;
    mbedtls_pk_type_t sig_pk;
    void *sig_opts;
    uint8_t crt_hash[MBEDTLS_MD_MAX_SIZE];
    size_t crt_hash_len;
    mbedtls_x509_buf_raw sig;
    mbedtls_x509_buf_raw issuer_raw;
} mbedtls_x509_crt_sig_info;

static void x509_crt_free_sig_info( mbedtls_x509_crt_sig_info *info )
{
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    mbedtls_free( info->sig_opts );
#else
    ((void) info);
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */
}

static int x509_crt_get_sig_info( mbedtls_x509_crt_frame const *frame,
                                  mbedtls_x509_crt_sig_info *info )
{

#if defined(MBEDTLS_USE_PSA_CRYPTO)

    psa_hash_operation_t hash_operation = PSA_HASH_OPERATION_INIT;
    psa_algorithm_t hash_alg = mbedtls_psa_translate_md( frame->sig_md );

    /* Make sure that this function leaves the target structure
     * ready to be freed, regardless of success of failure. */
    info->sig_opts   = NULL;

    if( psa_hash_setup( &hash_operation, hash_alg ) != PSA_SUCCESS )
        return( -1 );

    if( psa_hash_update( &hash_operation, frame->tbs.p, frame->tbs.len )
        != PSA_SUCCESS )
    {
        return( -1 );
    }

    if( psa_hash_finish( &hash_operation,
                         info->crt_hash,
                         sizeof( info->crt_hash ),
                         &info->crt_hash_len )
        != PSA_SUCCESS )
    {
        return( -1 );
    }

    info->issuer_raw = frame->issuer_raw;
    info->sig_md     = frame->sig_md;
    info->sig_pk     = frame->sig_pk;
    info->sig        = frame->sig;

#else /* MBEDTLS_USE_PSA_CRYPTO */
    const mbedtls_md_info_t *md_info;

    /* Make sure that this function leaves the target structure
     * ready to be freed, regardless of success of failure. */
    info->sig_opts = NULL;

    md_info = mbedtls_md_info_from_type( frame->sig_md );
    if( mbedtls_md( md_info, frame->tbs.p, frame->tbs.len,
                    info->crt_hash ) != 0 )
    {
        /* Note: this can't happen except after an internal error */
        return( -1 );
    }

    info->crt_hash_len = mbedtls_md_get_size( md_info );

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    {
        int ret;
        unsigned char *alg_start = frame->sig_alg.p;
        unsigned char *alg_end = alg_start + frame->sig_alg.len;

        /* Get signature options -- currently only
         * necessary for RSASSA-PSS. */
        ret = mbedtls_x509_get_sig_alg_raw( &alg_start, alg_end, &info->sig_md,
                                            &info->sig_pk, &info->sig_opts );
        if( ret != 0 )
        {
            /* Note: this can't happen except after an internal error */
            return( -1 );
        }
    }
#else /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */
    info->sig_md   = frame->sig_md;
    info->sig_pk   = frame->sig_pk;
#endif /* !MBEDTLS_X509_RSASSA_PSS_SUPPORT */

    info->issuer_raw = frame->issuer_raw;
    info->sig        = frame->sig;

#endif /* MBEDTLS_USE_PSA_CRYPTO */

    return( 0 );
}

/*
 * Find a suitable parent for child in candidates, or return NULL.
 *
 * Here suitable is defined as:
 *  1. subject name matches child's issuer
 *  2. if necessary, the CA bit is set and key usage allows signing certs
 *  3. for trusted roots, the signature is correct
 *     (for intermediates, the signature is checked and the result reported)
 *  4. pathlen constraints are satisfied
 *
 * If there's a suitable candidate which is also time-valid, return the first
 * such. Otherwise, return the first suitable candidate (or NULL if there is
 * none).
 *
 * The rationale for this rule is that someone could have a list of trusted
 * roots with two versions on the same root with different validity periods.
 * (At least one user reported having such a list and wanted it to just work.)
 * The reason we don't just require time-validity is that generally there is
 * only one version, and if it's expired we want the flags to state that
 * rather than NOT_TRUSTED, as would be the case if we required it here.
 *
 * The rationale for rule 3 (signature for trusted roots) is that users might
 * have two versions of the same CA with different keys in their list, and the
 * way we select the correct one is by checking the signature (as we don't
 * rely on key identifier extensions). (This is one way users might choose to
 * handle key rollover, another relies on self-issued certs, see [SIRO].)
 *
 * Arguments:
 *  - [in] child: certificate for which we're looking for a parent
 *  - [in] candidates: chained list of potential parents
 *  - [out] r_parent: parent found (or NULL)
 *  - [out] r_signature_is_good: 1 if child signature by parent is valid, or 0
 *  - [in] top: 1 if candidates consists of trusted roots, ie we're at the top
 *         of the chain, 0 otherwise
 *  - [in] path_cnt: number of intermediates seen so far
 *  - [in] self_cnt: number of self-signed intermediates seen so far
 *         (will never be greater than path_cnt)
 *  - [in-out] rs_ctx: context for restarting operations
 *
 * Return value:
 *  - 0 on success
 *  - MBEDTLS_ERR_ECP_IN_PROGRESS otherwise
 */
static int x509_crt_find_parent_in(
                        mbedtls_x509_crt_sig_info const *child_sig,
                        mbedtls_x509_crt *candidates,
                        mbedtls_x509_crt **r_parent,
                        int *r_signature_is_good,
                        int top,
                        unsigned path_cnt,
                        unsigned self_cnt,
                        mbedtls_x509_crt_restart_ctx *rs_ctx )
{
    int ret;
    mbedtls_x509_crt *parent, *fallback_parent;
    int signature_is_good, fallback_signature_is_good;

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /* did we have something in progress? */
    if( rs_ctx != NULL && rs_ctx->parent != NULL )
    {
        /* restore saved state */
        parent = rs_ctx->parent;
        fallback_parent = rs_ctx->fallback_parent;
        fallback_signature_is_good = rs_ctx->fallback_signature_is_good;

        /* clear saved state */
        rs_ctx->parent = NULL;
        rs_ctx->fallback_parent = NULL;
        rs_ctx->fallback_signature_is_good = 0;

        /* resume where we left */
        goto check_signature;
    }
#endif

    fallback_parent = NULL;
    fallback_signature_is_good = 0;

    for( parent = candidates; parent != NULL; parent = parent->next )
    {
        int parent_valid, parent_match, path_len_ok;

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
check_signature:
#endif

        parent_valid = parent_match = path_len_ok = 0;

        if( mbedtls_x509_time_is_past( &parent->valid_from ) &&
            mbedtls_x509_time_is_future( &parent->valid_to ) )
        {
            parent_valid = 1;
        }

        /* basic parenting skills (name, CA bit, key usage) */
        if( x509_crt_check_parent( child_sig, parent, top ) == 0 )
            parent_match = 1;

        /* +1 because stored max_pathlen is 1 higher that the actual value */
        if( !( parent->max_pathlen > 0 &&
               (size_t) parent->max_pathlen < 1 + path_cnt - self_cnt ) )
        {
            path_len_ok = 1;
        }

        if( parent_match == 0 || path_len_ok == 0 )
            continue;

        /* Signature */
        ret = x509_crt_check_signature( child_sig, parent, rs_ctx );

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
        if( rs_ctx != NULL && ret == MBEDTLS_ERR_ECP_IN_PROGRESS )
        {
            /* save state */
            rs_ctx->parent = parent;
            rs_ctx->fallback_parent = fallback_parent;
            rs_ctx->fallback_signature_is_good = fallback_signature_is_good;

            return( ret );
        }
#else
        (void) ret;
#endif

        signature_is_good = ret == 0;
        if( top && ! signature_is_good )
            continue;

        /* optional time check */
        if( !parent_valid )
        {
            if( fallback_parent == NULL )
            {
                fallback_parent = parent;
                fallback_signature_is_good = signature_is_good;
            }

            continue;
        }

        *r_parent = parent;
        *r_signature_is_good = signature_is_good;

        break;
    }

    if( parent == NULL )
    {
        *r_parent = fallback_parent;
        *r_signature_is_good = fallback_signature_is_good;
    }

    return( 0 );
}

/*
 * Find a parent in trusted CAs or the provided chain, or return NULL.
 *
 * Searches in trusted CAs first, and return the first suitable parent found
 * (see find_parent_in() for definition of suitable).
 *
 * Arguments:
 *  - [in] child: certificate for which we're looking for a parent, followed
 *         by a chain of possible intermediates
 *  - [in] trust_ca: list of locally trusted certificates
 *  - [out] parent: parent found (or NULL)
 *  - [out] parent_is_trusted: 1 if returned `parent` is trusted, or 0
 *  - [out] signature_is_good: 1 if child signature by parent is valid, or 0
 *  - [in] path_cnt: number of links in the chain so far (EE -> ... -> child)
 *  - [in] self_cnt: number of self-signed certs in the chain so far
 *         (will always be no greater than path_cnt)
 *  - [in-out] rs_ctx: context for restarting operations
 *
 * Return value:
 *  - 0 on success
 *  - MBEDTLS_ERR_ECP_IN_PROGRESS otherwise
 */
static int x509_crt_find_parent(
                        mbedtls_x509_crt_sig_info const *child_sig,
                        mbedtls_x509_crt *rest,
                        mbedtls_x509_crt *trust_ca,
                        mbedtls_x509_crt **parent,
                        int *parent_is_trusted,
                        int *signature_is_good,
                        unsigned path_cnt,
                        unsigned self_cnt,
                        mbedtls_x509_crt_restart_ctx *rs_ctx )
{
    int ret;
    mbedtls_x509_crt *search_list;

    *parent_is_trusted = 1;

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /* restore then clear saved state if we have some stored */
    if( rs_ctx != NULL && rs_ctx->parent_is_trusted != -1 )
    {
        *parent_is_trusted = rs_ctx->parent_is_trusted;
        rs_ctx->parent_is_trusted = -1;
    }
#endif

    while( 1 ) {
        search_list = *parent_is_trusted ? trust_ca : rest;

        ret = x509_crt_find_parent_in( child_sig, search_list,
                                       parent, signature_is_good,
                                       *parent_is_trusted,
                                       path_cnt, self_cnt, rs_ctx );

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
        if( rs_ctx != NULL && ret == MBEDTLS_ERR_ECP_IN_PROGRESS )
        {
            /* save state */
            rs_ctx->parent_is_trusted = *parent_is_trusted;
            return( ret );
        }
#else
        (void) ret;
#endif

        /* stop here if found or already in second iteration */
        if( *parent != NULL || *parent_is_trusted == 0 )
            break;

        /* prepare second iteration */
        *parent_is_trusted = 0;
    }

    /* extra precaution against mistakes in the caller */
    if( *parent == NULL )
    {
        *parent_is_trusted = 0;
        *signature_is_good = 0;
    }

    return( 0 );
}

/*
 * Check if an end-entity certificate is locally trusted
 *
 * Currently we require such certificates to be self-signed (actually only
 * check for self-issued as self-signatures are not checked)
 */
static int x509_crt_check_ee_locally_trusted(
                    mbedtls_x509_crt_frame const *crt,
                    mbedtls_x509_crt const *trust_ca )
{
    mbedtls_x509_crt const *cur;

    /* look for an exact match with trusted cert */
    for( cur = trust_ca; cur != NULL; cur = cur->next )
    {
        if( crt->raw.len == cur->raw.len &&
            memcmp( crt->raw.p, cur->raw.p, crt->raw.len ) == 0 )
        {
            return( 0 );
        }
    }

    /* too bad */
    return( -1 );
}

/*
 * Build and verify a certificate chain
 *
 * Given a peer-provided list of certificates EE, C1, ..., Cn and
 * a list of trusted certs R1, ... Rp, try to build and verify a chain
 *      EE, Ci1, ... Ciq [, Rj]
 * such that every cert in the chain is a child of the next one,
 * jumping to a trusted root as early as possible.
 *
 * Verify that chain and return it with flags for all issues found.
 *
 * Special cases:
 * - EE == Rj -> return a one-element list containing it
 * - EE, Ci1, ..., Ciq cannot be continued with a trusted root
 *   -> return that chain with NOT_TRUSTED set on Ciq
 *
 * Tests for (aspects of) this function should include at least:
 * - trusted EE
 * - EE -> trusted root
 * - EE -> intermediate CA -> trusted root
 * - if relevant: EE untrusted
 * - if relevant: EE -> intermediate, untrusted
 * with the aspect under test checked at each relevant level (EE, int, root).
 * For some aspects longer chains are required, but usually length 2 is
 * enough (but length 1 is not in general).
 *
 * Arguments:
 *  - [in] crt: the cert list EE, C1, ..., Cn
 *  - [in] trust_ca: the trusted list R1, ..., Rp
 *  - [in] ca_crl, profile: as in verify_with_profile()
 *  - [out] ver_chain: the built and verified chain
 *      Only valid when return value is 0, may contain garbage otherwise!
 *      Restart note: need not be the same when calling again to resume.
 *  - [in-out] rs_ctx: context for restarting operations
 *
 * Return value:
 *  - non-zero if the chain could not be fully built and examined
 *  - 0 is the chain was successfully built and examined,
 *      even if it was found to be invalid
 */
static int x509_crt_verify_chain(
                mbedtls_x509_crt *crt,
                mbedtls_x509_crt *trust_ca,
                mbedtls_x509_crl *ca_crl,
                mbedtls_x509_crt_ca_cb_t f_ca_cb,
                void *p_ca_cb,
                const mbedtls_x509_crt_profile *profile,
                mbedtls_x509_crt_verify_chain *ver_chain,
                mbedtls_x509_crt_restart_ctx *rs_ctx )
{
    /* Don't initialize any of those variables here, so that the compiler can
     * catch potential issues with jumping ahead when restarting */
    int ret;
    uint32_t *flags;
    mbedtls_x509_crt_verify_chain_item *cur;
    mbedtls_x509_crt *child_crt;
    mbedtls_x509_crt *parent;
    int parent_is_trusted;
    int child_is_trusted;
    int signature_is_good;
    unsigned self_cnt;
    mbedtls_x509_crt *cur_trust_ca = NULL;

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /* resume if we had an operation in progress */
    if( rs_ctx != NULL && rs_ctx->in_progress == x509_crt_rs_find_parent )
    {
        /* restore saved state */
        *ver_chain = rs_ctx->ver_chain; /* struct copy */
        self_cnt = rs_ctx->self_cnt;

        /* restore derived state */
        cur = &ver_chain->items[ver_chain->len - 1];
        child_crt = cur->crt;

        child_is_trusted = 0;
        goto find_parent;
    }
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    child_crt = crt;
    self_cnt = 0;
    parent_is_trusted = 0;
    child_is_trusted = 0;

    while( 1 ) {
#if defined(MBEDTLS_X509_CRL_PARSE_C)
        mbedtls_x509_buf_raw child_serial;
#endif /* MBEDTLS_X509_CRL_PARSE_C */
        int self_issued;

        /* Add certificate to the verification chain */
        cur = &ver_chain->items[ver_chain->len];
        cur->crt = child_crt;
        cur->flags = 0;
        ver_chain->len++;

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
find_parent:
#endif

        flags = &cur->flags;

        {
            mbedtls_x509_crt_sig_info child_sig;
            {
                mbedtls_x509_crt_frame *child;

                ret = x509_crt_frame_acquire( child_crt, &child );
                if( ret != 0 )
                    return( MBEDTLS_ERR_X509_FATAL_ERROR );

                /* Check time-validity (all certificates) */
                if( mbedtls_x509_time_is_past( &child->valid_to ) )
                    *flags |= MBEDTLS_X509_BADCERT_EXPIRED;
                if( mbedtls_x509_time_is_future( &child->valid_from ) )
                    *flags |= MBEDTLS_X509_BADCERT_FUTURE;

                /* Stop here for trusted roots (but not for trusted EE certs) */
                if( child_is_trusted )
                {
                    x509_crt_frame_release( child_crt, child );
                    return( 0 );
                }

                self_issued = 0;
                if( mbedtls_x509_name_cmp_raw( &child->issuer_raw,
                                               &child->subject_raw,
                                               NULL, NULL ) == 0 )
                {
                    self_issued = 1;
                }

                /* Check signature algorithm: MD & PK algs */
                if( x509_profile_check_md_alg( profile, child->sig_md ) != 0 )
                    *flags |= MBEDTLS_X509_BADCERT_BAD_MD;

                if( x509_profile_check_pk_alg( profile, child->sig_pk ) != 0 )
                    *flags |= MBEDTLS_X509_BADCERT_BAD_PK;

                /* Special case: EE certs that are locally trusted */
                if( ver_chain->len == 1 && self_issued &&
                    x509_crt_check_ee_locally_trusted( child, trust_ca ) == 0 )
                {
                    x509_crt_frame_release( child_crt, child );
                    return( 0 );
                }

#if defined(MBEDTLS_X509_CRL_PARSE_C)
                child_serial = child->serial;
#endif /* MBEDTLS_X509_CRL_PARSE_C */

                ret = x509_crt_get_sig_info( child, &child_sig );

                x509_crt_frame_release( child_crt, child );
                if( ret != 0 )
                    return( MBEDTLS_ERR_X509_FATAL_ERROR );
            }

            /* Obtain list of potential trusted signers from CA callback,
             * or use statically provided list. */
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
            if( f_ca_cb != NULL )
            {
                mbedtls_x509_crt_free( ver_chain->trust_ca_cb_result );
                mbedtls_free( ver_chain->trust_ca_cb_result );
                ver_chain->trust_ca_cb_result = NULL;

                ret = f_ca_cb( p_ca_cb, child_crt,
                               &ver_chain->trust_ca_cb_result );
                if( ret != 0 )
                    return( MBEDTLS_ERR_X509_FATAL_ERROR );

                cur_trust_ca = ver_chain->trust_ca_cb_result;
            }
            else
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */
            {
                ((void) f_ca_cb);
                ((void) p_ca_cb);
                cur_trust_ca = trust_ca;
            }

            /* Look for a parent in trusted CAs or up the chain */
            ret = x509_crt_find_parent( &child_sig, child_crt->next,
                                        cur_trust_ca, &parent,
                                        &parent_is_trusted, &signature_is_good,
                                        ver_chain->len - 1, self_cnt, rs_ctx );

            x509_crt_free_sig_info( &child_sig );
        }

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
        if( rs_ctx != NULL && ret == MBEDTLS_ERR_ECP_IN_PROGRESS )
        {
            /* save state */
            rs_ctx->in_progress = x509_crt_rs_find_parent;
            rs_ctx->self_cnt = self_cnt;
            rs_ctx->ver_chain = *ver_chain; /* struct copy */
            return( ret );
        }
#else
        (void) ret;
#endif

        /* No parent? We're done here */
        if( parent == NULL )
        {
            *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
            return( 0 );
        }

        /* Count intermediate self-issued (not necessarily self-signed) certs.
         * These can occur with some strategies for key rollover, see [SIRO],
         * and should be excluded from max_pathlen checks. */
        if( ver_chain->len != 1 && self_issued )
            self_cnt++;

        /* path_cnt is 0 for the first intermediate CA,
         * and if parent is trusted it's not an intermediate CA */
        if( ! parent_is_trusted &&
            ver_chain->len > MBEDTLS_X509_MAX_INTERMEDIATE_CA )
        {
            /* return immediately to avoid overflow the chain array */
            return( MBEDTLS_ERR_X509_FATAL_ERROR );
        }

        /* signature was checked while searching parent */
        if( ! signature_is_good )
            *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;

        /* check size of signing key */
        if( x509_profile_check_key( profile, &parent->pk ) != 0 )
            *flags |= MBEDTLS_X509_BADCERT_BAD_KEY;

#if defined(MBEDTLS_X509_CRL_PARSE_C)
        /* Check trusted CA's CRL for the given crt */
        *flags |= x509_crt_verifycrl( child_serial.p,
                                      child_serial.len,
                                      parent, ca_crl, profile );
#else
        (void) ca_crl;
#endif

        /* prepare for next iteration */
        child_crt = parent;
        parent = NULL;
        child_is_trusted = parent_is_trusted;
        signature_is_good = 0;
    }
}

/*
 * Check for CN match
 */
static int x509_crt_check_cn( unsigned char const *buf,
                              size_t buflen,
                              const char *cn,
                              size_t cn_len )
{
    /* Try exact match */
    if( mbedtls_x509_memcasecmp( cn, buf, buflen, cn_len ) == 0 )
        return( 0 );

    /* try wildcard match */
    if( x509_check_wildcard( cn, cn_len, buf, buflen ) == 0 )
    {
        return( 0 );
    }

    return( -1 );
}

/* Returns 1 on a match and 0 on a mismatch.
 * This is because this function is used as a callback for
 * mbedtls_x509_name_cmp_raw(), which continues the name
 * traversal as long as the callback returns 0. */
static int x509_crt_check_name( void *ctx,
                                mbedtls_x509_buf *oid,
                                mbedtls_x509_buf *val,
                                int next_merged )
{
    char const *cn = (char const*) ctx;
    size_t cn_len = strlen( cn );
    ((void) next_merged);

    if( MBEDTLS_OID_CMP( MBEDTLS_OID_AT_CN, oid ) == 0 &&
        x509_crt_check_cn( val->p, val->len, cn, cn_len ) == 0 )
    {
        return( 1 );
    }

    return( 0 );
}

/* Returns 1 on a match and 0 on a mismatch.
 * This is because this function is used as a callback for
 * mbedtls_asn1_traverse_sequence_of(), which continues the
 * traversal as long as the callback returns 0. */
static int x509_crt_subject_alt_check_name( void *ctx,
                                            int tag,
                                            unsigned char *data,
                                            size_t data_len )
{
    char const *cn = (char const*) ctx;
    size_t cn_len = strlen( cn );
    ((void) tag);

    if( x509_crt_check_cn( data, data_len, cn, cn_len ) == 0 )
        return( 1 );

    return( 0 );
}

/*
 * Verify the requested CN - only call this if cn is not NULL!
 */
static void x509_crt_verify_name( const mbedtls_x509_crt *crt,
                                  const char *cn,
                                  uint32_t *flags )
{
    int ret;

    if( crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME )
    {
        unsigned char *p =
            crt->subject_alt_raw.p;
        const unsigned char *end =
            crt->subject_alt_raw.p + crt->subject_alt_raw.len;

        ret = mbedtls_asn1_traverse_sequence_of( &p, end,
                                      MBEDTLS_ASN1_TAG_CLASS_MASK,
                                      MBEDTLS_ASN1_CONTEXT_SPECIFIC,
                                      0, 0,
                                      x509_crt_subject_alt_check_name,
                                      (void*) cn );
    }
    else
    {
        ret = mbedtls_x509_name_cmp_raw( &crt->subject_raw_no_hdr,
                                         &crt->subject_raw_no_hdr,
                                         x509_crt_check_name, (void*) cn );
    }

    if( ret != 1 )
        *flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
}

/*
 * Merge the flags for all certs in the chain, after calling callback
 */
static int x509_crt_merge_flags_with_cb(
           uint32_t *flags,
           const mbedtls_x509_crt_verify_chain *ver_chain,
           int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
           void *p_vrfy )
{
    int ret;
    unsigned i;
    uint32_t cur_flags;
    const mbedtls_x509_crt_verify_chain_item *cur;

    for( i = ver_chain->len; i != 0; --i )
    {
        cur = &ver_chain->items[i-1];
        cur_flags = cur->flags;

        if( NULL != f_vrfy )
            if( ( ret = f_vrfy( p_vrfy, cur->crt, (int) i-1, &cur_flags ) ) != 0 )
                return( ret );

        *flags |= cur_flags;
    }

    return( 0 );
}

/*
 * Verify the certificate validity, with profile, restartable version
 *
 * This function:
 *  - checks the requested CN (if any)
 *  - checks the type and size of the EE cert's key,
 *    as that isn't done as part of chain building/verification currently
 *  - builds and verifies the chain
 *  - then calls the callback and merges the flags
 *
 * The parameters pairs `trust_ca`, `ca_crl` and `f_ca_cb`, `p_ca_cb`
 * are mutually exclusive: If `f_ca_cb != NULL`, it will be used by the
 * verification routine to search for trusted signers, and CRLs will
 * be disabled. Otherwise, `trust_ca` will be used as the static list
 * of trusted signers, and `ca_crl` will be use as the static list
 * of CRLs.
 */
static int x509_crt_verify_restartable_ca_cb( mbedtls_x509_crt *crt,
                     mbedtls_x509_crt *trust_ca,
                     mbedtls_x509_crl *ca_crl,
                     mbedtls_x509_crt_ca_cb_t f_ca_cb,
                     void *p_ca_cb,
                     const mbedtls_x509_crt_profile *profile,
                     const char *cn, uint32_t *flags,
                     int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                     void *p_vrfy,
                     mbedtls_x509_crt_restart_ctx *rs_ctx )
{
    int ret;
    mbedtls_pk_type_t pk_type;
    mbedtls_x509_crt_verify_chain ver_chain;
    uint32_t ee_flags;

    *flags = 0;
    ee_flags = 0;
    x509_crt_verify_chain_reset( &ver_chain );

    if( profile == NULL )
    {
        ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        goto exit;
    }

    /* check name if requested */
    if( cn != NULL )
        x509_crt_verify_name( crt, cn, &ee_flags );

    /* Check the type and size of the key */
    pk_type = mbedtls_pk_get_type( &crt->pk );

    if( x509_profile_check_pk_alg( profile, pk_type ) != 0 )
        ee_flags |= MBEDTLS_X509_BADCERT_BAD_PK;

    if( x509_profile_check_key( profile, &crt->pk ) != 0 )
        ee_flags |= MBEDTLS_X509_BADCERT_BAD_KEY;

    /* Check the chain */
    ret = x509_crt_verify_chain( crt, trust_ca, ca_crl,
                                 f_ca_cb, p_ca_cb, profile,
                                 &ver_chain, rs_ctx );

    if( ret != 0 )
        goto exit;

    /* Merge end-entity flags */
    ver_chain.items[0].flags |= ee_flags;

    /* Build final flags, calling callback on the way if any */
    ret = x509_crt_merge_flags_with_cb( flags, &ver_chain, f_vrfy, p_vrfy );

exit:

#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    mbedtls_x509_crt_free( ver_chain.trust_ca_cb_result );
    mbedtls_free( ver_chain.trust_ca_cb_result );
    ver_chain.trust_ca_cb_result = NULL;
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx != NULL && ret != MBEDTLS_ERR_ECP_IN_PROGRESS )
        mbedtls_x509_crt_restart_free( rs_ctx );
#endif

    /* prevent misuse of the vrfy callback - VERIFY_FAILED would be ignored by
     * the SSL module for authmode optional, but non-zero return from the
     * callback means a fatal error so it shouldn't be ignored */
    if( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED )
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;

    if( ret != 0 )
    {
        *flags = (uint32_t) -1;
        return( ret );
    }

    if( *flags != 0 )
        return( MBEDTLS_ERR_X509_CERT_VERIFY_FAILED );

    return( 0 );
}


/*
 * Verify the certificate validity (default profile, not restartable)
 */
int mbedtls_x509_crt_verify( mbedtls_x509_crt *crt,
                     mbedtls_x509_crt *trust_ca,
                     mbedtls_x509_crl *ca_crl,
                     const char *cn, uint32_t *flags,
                     int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                     void *p_vrfy )
{
    return( x509_crt_verify_restartable_ca_cb( crt, trust_ca, ca_crl,
                                         NULL, NULL,
                                         &mbedtls_x509_crt_profile_default,
                                         cn, flags,
                                         f_vrfy, p_vrfy, NULL ) );
}

/*
 * Verify the certificate validity (user-chosen profile, not restartable)
 */
int mbedtls_x509_crt_verify_with_profile( mbedtls_x509_crt *crt,
                     mbedtls_x509_crt *trust_ca,
                     mbedtls_x509_crl *ca_crl,
                     const mbedtls_x509_crt_profile *profile,
                     const char *cn, uint32_t *flags,
                     int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                     void *p_vrfy )
{
    return( x509_crt_verify_restartable_ca_cb( crt, trust_ca, ca_crl,
                                                 NULL, NULL,
                                                 profile, cn, flags,
                                                 f_vrfy, p_vrfy, NULL ) );
}

#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
/*
 * Verify the certificate validity (user-chosen profile, CA callback,
 *                                  not restartable).
 */
int mbedtls_x509_crt_verify_with_ca_cb( mbedtls_x509_crt *crt,
                     mbedtls_x509_crt_ca_cb_t f_ca_cb,
                     void *p_ca_cb,
                     const mbedtls_x509_crt_profile *profile,
                     const char *cn, uint32_t *flags,
                     int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                     void *p_vrfy )
{
    return( x509_crt_verify_restartable_ca_cb( crt, NULL, NULL,
                                                 f_ca_cb, p_ca_cb,
                                                 profile, cn, flags,
                                                 f_vrfy, p_vrfy, NULL ) );
}
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */

int mbedtls_x509_crt_verify_restartable( mbedtls_x509_crt *crt,
                     mbedtls_x509_crt *trust_ca,
                     mbedtls_x509_crl *ca_crl,
                     const mbedtls_x509_crt_profile *profile,
                     const char *cn, uint32_t *flags,
                     int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                     void *p_vrfy,
                     mbedtls_x509_crt_restart_ctx *rs_ctx )
{
    return( x509_crt_verify_restartable_ca_cb( crt, trust_ca, ca_crl,
                                                 NULL, NULL,
                                                 profile, cn, flags,
                                                 f_vrfy, p_vrfy, rs_ctx ) );
}


/*
 * Initialize a certificate chain
 */
void mbedtls_x509_crt_init( mbedtls_x509_crt *crt )
{
    memset( crt, 0, sizeof(mbedtls_x509_crt) );
}

/*
 * Unallocate all certificate data
 */

static void x509_free_sequence( mbedtls_x509_sequence *seq )
{
    while( seq != NULL )
    {
        mbedtls_x509_sequence *next = seq->next;
        mbedtls_platform_zeroize( seq, sizeof( *seq ) );
        mbedtls_free( seq );
        seq = next;
    }
}

static void x509_free_name( mbedtls_x509_name *name )
{
    while( name != NULL )
    {
        mbedtls_x509_name *next = name->next;
        mbedtls_platform_zeroize( name, sizeof( *name ) );
        mbedtls_free( name );
        name = next;
    }
}

void mbedtls_x509_crt_free( mbedtls_x509_crt *crt )
{
    mbedtls_x509_crt *cert_cur = crt;
    mbedtls_x509_crt *cert_prv;

    if( crt == NULL )
        return;

    do
    {
        mbedtls_pk_free( &cert_cur->pk );

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
        mbedtls_free( cert_cur->sig_opts );
#endif

        x509_free_name( cert_cur->issuer.next );
        x509_free_name( cert_cur->subject.next );
        x509_free_sequence( cert_cur->ext_key_usage.next );
        x509_free_sequence( cert_cur->subject_alt_names.next );

        seq_cur = cert_cur->certificate_policies.next;
        while( seq_cur != NULL )
        {
            seq_prv = seq_cur;
            seq_cur = seq_cur->next;
            mbedtls_platform_zeroize( seq_prv,
                                      sizeof( mbedtls_x509_sequence ) );
            mbedtls_free( seq_prv );
        }

        if( cert_cur->raw.p != NULL && cert_cur->own_buffer )
        {
            mbedtls_platform_zeroize( cert_cur->raw.p, cert_cur->raw.len );
            mbedtls_free( cert_cur->raw.p );
        }

        cert_cur = cert_cur->next;
    }
    while( cert_cur != NULL );

    cert_cur = crt;
    do
    {
        cert_prv = cert_cur;
        cert_cur = cert_cur->next;

        mbedtls_platform_zeroize( cert_prv, sizeof( mbedtls_x509_crt ) );
        if( cert_prv != crt )
            mbedtls_free( cert_prv );
    }
    while( cert_cur != NULL );
}

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
/*
 * Initialize a restart context
 */
void mbedtls_x509_crt_restart_init( mbedtls_x509_crt_restart_ctx *ctx )
{
    mbedtls_pk_restart_init( &ctx->pk );

    ctx->parent = NULL;
    ctx->fallback_parent = NULL;
    ctx->fallback_signature_is_good = 0;

    ctx->parent_is_trusted = -1;

    ctx->in_progress = x509_crt_rs_none;
    ctx->self_cnt = 0;
    x509_crt_verify_chain_reset( &ctx->ver_chain );
}

/*
 * Free the components of a restart context
 */
void mbedtls_x509_crt_restart_free( mbedtls_x509_crt_restart_ctx *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_pk_restart_free( &ctx->pk );
    mbedtls_x509_crt_restart_init( ctx );
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

#endif /* MBEDTLS_X509_CRT_PARSE_C */
