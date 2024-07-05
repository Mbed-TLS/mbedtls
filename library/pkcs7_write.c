/*
 *  PKCS7 Generation Writing
 *
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
 */

#include "common.h"

#include "mbedtls/build_info.h"
#if defined(MBEDTLS_PKCS7_WRITE_C)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/asn1write.h"
#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/pkcs7.h"
#include "mbedtls/pkcs7_write.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#if defined(MBEDTLS_FS_IO)
#include <sys/stat.h>
#include <sys/types.h>
#endif
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_free free
#define mbedtls_calloc calloc
#define mbedtls_printf printf
#define mbedtls_snprintf snprintf
#endif

/* STRUCTURE OF PKCS7 AND CORRESPONDING FUNCTIONS THAT HANDLE THEM:
 *PKCS7 {
 *    CONSTRUCTED | SEQUENCE                                         ->pkcs7_set_pkcs7_oid
 *        OID (Signed Data)                                          ->^
 *        CONSTRUCTED | CONTEXT SPECIFIC                             ->pkcs7_set_signed_data
 *            CONSTRUCTED | SEQUENCE                                 ->pkcs7_set_version
 *                INTEGER (version)                                  ->^
 *                CONSTRUCTED |SET                                   ->pkcs7_set_algo_id
 *                    OID (hash Alg)                                 ->^
 *                CONSTRUCTED | SEQUENCE                             ->pkcs7_set_signed_data_oid
 *                    OID (PKCS7 Data)                               ->^
 *                CONSTRUCTED | CONTEXT SPECIFIC                     ->pkcs7_set_signer_certs
 *                    entire certificate for each signer             ->^
 *                CONSTRUCTED | SET                                  ->pkcs7_set_signers_data
 *                    CONSTRUCTED | SEQUENCE (for each signer)       ->pkcs7_set_each_signer_data
 *                        INTEGER (signedInfoVersion)                ->pkcs7_set_signer_cert_data
 *                        CONSTRUCTED | SEQUENCE                     ->^
 *                            certificate issuer info                ->^
 *                            certificate serial                     ->^
 *                        CONSTRUCTED | SEQUENCE                     ->pkcs7_set_algorithm_ids
 *                            OID (hash Alg)                         ->^
 *                        CONSTRUCTED | SEQUENCE                     ->^
 *                            OID (Signature Alg (RSA))              ->^
 *                        OCTET STRING (signature)                   ->pkcs7_set_signature
 * }
 */

/* struct for containing information needed to generate the pkcs7
 * used for less function arguments */
typedef struct mbedtls_pkcs7_info {
    unsigned char **crts;
    size_t *crt_sizes;
    unsigned char **keys;
    size_t *key_sizes;
    size_t key_pairs;
    const unsigned char *data;
    size_t data_size;
    mbedtls_md_type_t hash_func;
    const char *hash_func_oid;
    /*  if already_signed_flag is 1 then then PKCS7Info.keys contains signatures, if 0 then contains siging key in DER format */
    int already_signed_flag;
    int (*rng_func)(void *, unsigned char *, size_t);
    void *rng_param;
} mbedtls_pkcs7_info;

static size_t get_leading_unused_bytes( unsigned char *data, size_t data_size )
{
    size_t unused_bytes = 0;
    while( unused_bytes < data_size && data[unused_bytes] == 0x00 )
        unused_bytes++;
    return( unused_bytes );
}


static int pkcs7_hash_create( const unsigned char *data, size_t size,
                              mbedtls_md_type_t hash_func,
                              unsigned char **out_hash, size_t *out_hash_size )
{
    const mbedtls_md_info_t *md_info;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    md_info = mbedtls_md_info_from_type( hash_func );
    if( md_info == NULL ) {
        ret = MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
        goto out;
    }
    *out_hash = mbedtls_calloc( 1, (size_t) mbedtls_md_get_size( md_info ) );
    if( *out_hash == NULL ) {
        ret = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
        goto out;
    }
    ret = mbedtls_md( md_info, data, size, (unsigned char *) *out_hash );
    if( ret ) {
        mbedtls_free( *out_hash );
        *out_hash = NULL;
        goto out;
    }

    *out_hash_size = (size_t) mbedtls_md_get_size( md_info );
    ret = 0;

out:
    return( ret );
}

static int alloc_more_mem( unsigned char **start, size_t *size,
                           unsigned char **ptr )
{
    unsigned char *new_start = NULL, *new_ptr = NULL;
    size_t curr_len;
    /* new buffer is double the size of the old buffer, cant realloc bc new data
     * must be infront of old data */
    new_start = mbedtls_calloc( 1, *size * 2 );
    if( new_start == NULL )
        return( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );

    /* number of bytes to copy is the number of bytes between ptr and the end of
     * the buffer */
    curr_len = ( *start ) + ( *size ) - ( *ptr );
    /* new buffer will be the same as the old one only there will be 'size' number
     * of bytes padded to the front, remember we are writing the buffer from
     * highest memory address to lowest so new data will go in the front */
    new_ptr = new_start + ( *size ) + ( ( *ptr ) - ( *start ) );
    memcpy( new_ptr, *ptr, curr_len );
    /* free old buffer */
    mbedtls_platform_zeroize( *ptr, curr_len);
    mbedtls_free( *start );
    /* update values */
    *start = new_start;
    *ptr = new_ptr;
    *size = 2 * ( *size );
    return( 0 );
}

/* helps to determine the appropriate mbedtls_asn1_write function */
enum pkcs7_data_types {
    WRITE_VERSION,
    WRITE_TAG,
    WRITE_OID,
    WRITE_OID_NO_NULL_TAG,
    WRITE_SIGNATURE,
    WRITE_RAW_BUFFER,
    WRITE_SERIAL
};

/**
 * \brief               A general way to add data to the pkcs7 buffer from a given data type.
 * \param buffer         Start of the pkcs7 data buffer.
 * \param size          Size of pkcs7 data buffer.
 * \param ptr           Points to the current location of where the data has been written
 *                      to. memory from buffer to pointer should be unused.
 *                      Remember, mbedtls writes their buffers from the end of a buffer to
 *                      the start.
 * \param data_type     The type of data that is trying to be written,
 *                      see pkcs7_data_types enum for possible values.
 * \param value         The new data to be added to the pkcs7.
 * \param value_size    The length of the new value, if data_type = tag then it
 *                      is length of data contained in the tag
 *                      (not the length of the tag itself).
 * \param param         Extra argument if adding algorithm identifier (data_type = WRITE_OID)
 *                      to show the size of the param buffer, ignored for other data types.
 * \note                If the data buffer is too small to hold the new value, an attempt will
 *                      be made to move the data and pointers into a larger buffer.
 * \return              0 for success, else errno.
 */
static int pkcs7_write_data( unsigned char **buffer, size_t *size,
                             unsigned char **ptr, int data_type, const void *value,
                             size_t value_size, size_t param )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    /* pointer for current spot in data, in case it fails but ptr changes */
    unsigned char *ptr_tmp = *ptr;
    do {
        /* do function depending on data type */
        switch ( data_type ) {
            case WRITE_VERSION :
                ret = mbedtls_asn1_write_int( ptr, *buffer, *(int *) value );
                break;

            case WRITE_TAG :
                ret = mbedtls_asn1_write_len( ptr, *buffer, value_size );
                if( ret >= 0 )
                    ret = mbedtls_asn1_write_tag( ptr, *buffer, *(unsigned char *) value );
                break;

            case WRITE_OID :
                ret = mbedtls_asn1_write_algorithm_identifier(
                          ptr, *buffer, (const char *) value, value_size, param );
                break;

            case WRITE_OID_NO_NULL_TAG :
                ret = mbedtls_asn1_write_oid( ptr, *buffer, (const char *) value, value_size );
                if( ret >= 0 ) {
                    ret = mbedtls_asn1_write_len( ptr, *buffer, ptr_tmp - *ptr );
                    if( ret >= 0 )
                        ret = mbedtls_asn1_write_tag( ptr, *buffer,
                                                      ( MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) );
                }
                break;

            case WRITE_SIGNATURE :
                ret = mbedtls_asn1_write_octet_string( ptr, *buffer, value, value_size );
                break;

            case WRITE_RAW_BUFFER :
                ret = mbedtls_asn1_write_raw_buffer( ptr, *buffer, value, value_size );
                break;

            case WRITE_SERIAL :
                ret = mbedtls_asn1_write_tagged_string( ptr, *buffer, MBEDTLS_ASN1_INTEGER,
                                                        (const char *) value, value_size );
                break;
            default:
                ret = MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
        }
        /* if setting data failed, allocate more data */
        if( ret == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL ) {
            /* set ptr back to old one, could have changed when function failed */
            *ptr = ptr_tmp;

            if( alloc_more_mem( buffer, size, ptr ) )
                return( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );

            /* reset ptr_tmp because ptr was allacated to some other place in memory */
            ptr_tmp = *ptr;
        } else if( ret < 0 ) {
            return( MBEDTLS_ERR_ASN1_INVALID_DATA );
        }

    } while( ret == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    /* asn1 write functions return number of bytes written on success */
    return( ret > 0 ? 0 : ret );
}

static int pkcs7_set_signature( unsigned char **start, size_t *size,
                                unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info,
                                mbedtls_x509_crt *pub, unsigned char *priv,
                                size_t priv_size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t out_sig_size, hash_size, sig_size;
    unsigned char *hash = NULL;
    char *signature = NULL;
    mbedtls_pk_context *priv_key;

    /* generate hash to sign, this will return alloc'd mem on success */
    ret = pkcs7_hash_create( pkcs7_info->data, pkcs7_info->data_size,
                             pkcs7_info->hash_func,
                             &hash, &hash_size );
    if( ret != 0 )
        return( ret );

    /* if the private key already holds signature (see definition of pkcs7_info.keys)
     * then just write the signature, no generation is needed
     */
    if( pkcs7_info->already_signed_flag ) {
        /* ensure decrypted signature is equal to the hash of input data */
        ret = mbedtls_pk_verify( &pub->pk, pkcs7_info->hash_func, hash, hash_size,
                                 priv, priv_size );
        if( ret ) {
            ret = MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
        } else {
            ret = pkcs7_write_data( start, size, ptr, MBEDTLS_ASN1_OCTET_STRING, priv,
                                    priv_size, 0 );
        }
        mbedtls_free( hash );

        return( ret );
    }

    /* if here we know that `priv` contains a private key, not a signature */
    priv_key = mbedtls_calloc( 1, sizeof( *priv_key ) );
    if( priv_key == NULL )
        return( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );

    mbedtls_pk_init( priv_key );
    /* make sure private key parses into private key format */
    ret = mbedtls_pk_parse_key( priv_key, priv, priv_size, NULL, 0,
                                pkcs7_info->rng_func, pkcs7_info->rng_param );
    if( ret != 0 )
        goto out;

    /* make sure private key is matched with public key */
    ret = mbedtls_pk_check_pair( &( pub->pk ), priv_key,
                                 pkcs7_info->rng_func, pkcs7_info->rng_param );
    if( ret != 0 )
        goto out;

    /* make sure private key is RSA, otherwise quit */
    if( mbedtls_pk_get_type(priv_key) != MBEDTLS_PK_RSA ) {
        ret = MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE;
        goto out;
    }
    /* get size of RSA signature, ex 2048, 4096 ... */
    sig_size = mbedtls_pk_get_len( priv_key->pk_ctx );

    signature = mbedtls_calloc( 1, sig_size );
    if( signature == NULL ) {
        ret = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
        goto out;
    }


    ret = mbedtls_pk_sign( priv_key, pkcs7_info->hash_func,
                           (const unsigned char *) hash, hash_size,
                           (unsigned char *) signature, sig_size, &out_sig_size,
                           pkcs7_info->rng_func, pkcs7_info->rng_param );
    if( ret != 0 ) {
        mbedtls_free( signature );
        goto out;
    }
    ret = pkcs7_write_data( start, size, ptr, WRITE_SIGNATURE, signature,
                            sig_size, 0 );
    mbedtls_free( signature );

out:
    mbedtls_pk_free( priv_key );
    mbedtls_free( priv_key );
    mbedtls_free( hash );

    return( ret );
}

static int pkcs7_set_algorithm_ids( unsigned char **start, size_t *size,
                                    unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info,
                                    mbedtls_x509_crt *pub, unsigned char *priv,
                                    size_t priv_size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = pkcs7_set_signature( start, size, ptr, pkcs7_info, pub, priv, priv_size );
    if( ret != 0 )
        return( ret );

    /* make sure it is rsa encryption, that is all we support right now */
    if( mbedtls_pk_get_type(&pub->pk) != MBEDTLS_PK_RSA ) {
        ret = MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE;
        return( ret );
    }
    ret = pkcs7_write_data(
              start, size, ptr, WRITE_OID, (void *) MBEDTLS_OID_PKCS1_RSA,
              strlen( MBEDTLS_OID_PKCS1_RSA ), 0 );
    if( ret == 0 ) {
        ret = pkcs7_write_data(
                  start, size, ptr, WRITE_OID, (void *) pkcs7_info->hash_func_oid,
                  strlen( pkcs7_info->hash_func_oid ), 0 );
    }

    return( ret );
}

static int pkcs7_set_signer_cert_data( unsigned char **start, size_t *size,
                                       unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info,
                                       mbedtls_x509_crt *pub, unsigned char *priv,
                                       size_t priv_size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED,
        signed_info_version = MBEDTLS_PKCS7_SIGNER_INFO_VERSION;
    size_t bytes_written_in_step, curr_len;
    unsigned char tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;

    ret = pkcs7_set_algorithm_ids( start, size, ptr, pkcs7_info, pub, priv,
                                   priv_size );
    if( ret != 0 )
        return( ret );

    /* add serial */
    curr_len = *size - ( *ptr - *start );
    ret = pkcs7_write_data( start, size, ptr,
                            WRITE_SERIAL,
                            pub->serial.p, pub->serial.len, 0 );
    if( ret != 0 )
        return( ret );

    ret = pkcs7_write_data( start, size, ptr, WRITE_RAW_BUFFER,
                            pub->issuer_raw.p, pub->issuer_raw.len, 0 );
    if( ret != 0 )
        return( ret );

    /* add info */
    bytes_written_in_step = *size - ( *ptr - *start ) - curr_len;
    ret = pkcs7_write_data( start, size, ptr,
                            WRITE_TAG, &tag,
                            bytes_written_in_step, 0 );
    if( ret == 0 ) {
        /* add signed info version, see https:// tools.ietf.org/html/rfc2315
         * section 9.2 */
        ret = pkcs7_write_data( start, size, ptr, WRITE_VERSION,
                                &signed_info_version, sizeof( signed_info_version ), 0 );
    }

    return( ret );
}

static int pkcs7_set_each_signer_data( unsigned char **start, size_t *size,
                                       unsigned char **ptr,
                                       mbedtls_pkcs7_info *pkcs7_info )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t bytes_written_in_step, curr_len;
    unsigned char tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
    mbedtls_x509_crt *cert = NULL;
    /* if no signers than quit */
    if( pkcs7_info->key_pairs < 1 ) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO;
    }

    for( size_t i = 0; i < pkcs7_info->key_pairs; i++ ) {
        cert = mbedtls_calloc( 1, sizeof( *cert ) );
        if( cert == NULL ) {
            ret = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
            goto out;
        }
        mbedtls_x509_crt_init( cert );
        /* puts cert data into x509_Crt struct and returns number of failed parses */
        ret = mbedtls_x509_crt_parse( cert, pkcs7_info->crts[i],
                                      pkcs7_info->crt_sizes[i] );
        if( ret != 0 )
            goto out;

        curr_len = *size - ( *ptr - *start );
        ret = pkcs7_set_signer_cert_data( start, size, ptr, pkcs7_info, cert,
                                          pkcs7_info->keys[i], pkcs7_info->key_sizes[i] );
        if( ret != 0 )
            goto out;
        bytes_written_in_step = *size - ( *ptr - *start ) - curr_len;
        ret = pkcs7_write_data( start, size, ptr,
                                WRITE_TAG, &tag,
                                bytes_written_in_step, 0 );
        if( ret != 0 )
            goto out;

        mbedtls_x509_crt_free( cert );
        mbedtls_free( cert );
        cert = NULL;
    }

out:
    mbedtls_x509_crt_free( cert );
    mbedtls_free( cert );

    return( ret );
}

static int pkcs7_set_signers_data( unsigned char **start, size_t *size,
                                   unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t bytes_written_in_step, curr_len;
    unsigned char tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET;

    curr_len = *size - ( *ptr - *start );

    ret = pkcs7_set_each_signer_data( start, size, ptr, pkcs7_info );
    if( ret != 0 )
        return( ret );

    bytes_written_in_step = *size - ( *ptr - *start ) - curr_len;
    ret = pkcs7_write_data( start, size, ptr,
                            WRITE_TAG, &tag,
                            bytes_written_in_step, 0 );

    return( ret );
}

static int pkcs7_set_signer_certs( unsigned char **start, size_t *size,
                                   unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t bytes_written_in_step, curr_len;
    unsigned char tag =  MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED;

    ret = pkcs7_set_signers_data( start, size, ptr, pkcs7_info );

    if( ret != 0 )
        return( ret );

    curr_len = *size - ( *ptr - *start );
    for( size_t i = 0; i < pkcs7_info->key_pairs; i++ ) {
        ret = pkcs7_write_data( start, size, ptr, WRITE_RAW_BUFFER,
                                pkcs7_info->crts[i], pkcs7_info->crt_sizes[i], 0 );
        if( ret )
            break;
    }
    if( ret == 0 ) {
        bytes_written_in_step = *size - ( *ptr - *start ) - curr_len;
        ret = pkcs7_write_data( start, size, ptr, WRITE_TAG,
                                &tag, bytes_written_in_step, 0 );
    }

    return( ret );
}

static int pkcs7_set_signed_data_oid( unsigned char **start, size_t *size,
                                      unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = pkcs7_set_signer_certs( start, size, ptr, pkcs7_info );
    if( ret != 0 )
        return( ret );

    ret = pkcs7_write_data( start, size, ptr, WRITE_OID_NO_NULL_TAG,
                            (void *) MBEDTLS_OID_PKCS7_DATA,
                            strlen(MBEDTLS_OID_PKCS7_DATA), 0 );

    return( ret );
}

static int pkcs7_set_algo_id( unsigned char **start, size_t *size,
                              unsigned char **ptr,
                              mbedtls_pkcs7_info *pkcs7_info )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET;
    size_t bytes_written_in_step, curr_len;

    ret = pkcs7_set_signed_data_oid( start, size, ptr, pkcs7_info );

    if( ret != 0 )
        return( ret );

    curr_len = *size - ( *ptr - *start );

    ret = pkcs7_write_data( start, size, ptr, WRITE_OID,
                            (void *) pkcs7_info->hash_func_oid,
                            strlen( pkcs7_info->hash_func_oid ), 0 );
    if( ret == 0 ) {
        /* bytes in step = new currently written bytes - old currently written */
        bytes_written_in_step = *size - ( *ptr - *start ) - curr_len;
        ret = pkcs7_write_data( start, size, ptr, WRITE_TAG, &tag,
                                bytes_written_in_step, 0 );
    }

    return( ret );
}

static int pkcs7_set_version( unsigned char **start, size_t *size,
                              unsigned char **ptr,
                              mbedtls_pkcs7_info *pkcs7_info )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int version = MBEDTLS_PKCS7_SIGNED_DATA_VERSION;

    ret = pkcs7_set_algo_id( start, size, ptr, pkcs7_info );
    if( ret != 0 )
        return( ret );

    ret = pkcs7_write_data( start, size, ptr, WRITE_VERSION, &version,
                            sizeof( version ), 0 );

    return( ret );
}

static int pkcs7_set_signed_data( unsigned char **start, size_t *size,
                                  unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t curr_len;
    unsigned char tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;

    ret = pkcs7_set_version( start, size, ptr, pkcs7_info );
    if( ret != 0 )
        return( ret );

    curr_len = *size - ( *ptr - *start );
    ret = pkcs7_write_data( start, size, ptr,
                            WRITE_TAG, &tag,
                            curr_len, 0 );

    return( ret );
}

static int pkcs7_set_pkcs7_oid( unsigned char **start, size_t *size,
                                unsigned char **ptr,
                                mbedtls_pkcs7_info *pkcs7_info )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t curr_len;
    unsigned char tag = MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED;

    ret = pkcs7_set_signed_data( start, size, ptr, pkcs7_info );

    if( ret != 0 )
        return( ret );

    curr_len = *size - ( *ptr - *start );
    ret = pkcs7_write_data( start, size, ptr,
                            WRITE_TAG,
                            &tag, curr_len, 0 );
    if( ret == 0 ) {
        curr_len = *size - ( *ptr - *start );
        ret = pkcs7_write_data(
                  start, size, ptr, WRITE_OID,
                  (void *) MBEDTLS_OID_PKCS7_SIGNED_DATA,
                  strlen( MBEDTLS_OID_PKCS7_SIGNED_DATA ), curr_len );
    }

    return( ret );
}

static int pkcs7_start_generation( unsigned char **start, size_t *size,
                                   unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info )
{
    /* This will call every other function before anything is actually written */
    return( pkcs7_set_pkcs7_oid( start, size, ptr, pkcs7_info ) );
}

int mbedtls_pkcs7_create( unsigned char **pkcs7, size_t *pkcs7_size,
                          const unsigned char *data, size_t data_size, const unsigned char **crts,
                          const unsigned char **keys, size_t *crt_sizes, size_t *key_sizes, size_t key_pairs,
                          mbedtls_md_type_t hash_func, int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng, int keys_are_sigs )
{
    unsigned char *pkcs7_buf = NULL, *hash_func_oid;
    unsigned char *ptr;
    size_t pkcs7_buf_size, white_space, oid_len;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_pkcs7_info info;
    /* ensure there are keys to sign with */
    if( key_pairs == 0 ) {
        ret = MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
        goto out;
    }
    /* get hash_func OID, no md is currently unsuported */
    if( hash_func <= MBEDTLS_MD_NONE || hash_func > MBEDTLS_MD_RIPEMD160 ) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_ALG;
        goto out;
    }
    ret = mbedtls_oid_get_oid_by_md( hash_func, (const char **) &hash_func_oid,
                                     &oid_len );
    if( ret ) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_ALG;
        goto out;
    }

    info.crts = (unsigned char **) crts;
    info.crt_sizes = crt_sizes;
    info.keys = (unsigned char **) keys;
    info.key_sizes = key_sizes;
    info.key_pairs = key_pairs;
    info.data = data;
    info.data_size = data_size;
    info.hash_func = hash_func;
    info.hash_func_oid = (char *) hash_func_oid;
    info.already_signed_flag = keys_are_sigs;
    info.rng_func =  f_rng;
    info.rng_param = p_rng;

    /* buffer size for pkcs7 will grow depending on space needed */
    pkcs7_buf_size = 2;
    pkcs7_buf = mbedtls_calloc( 1, pkcs7_buf_size );
    if( pkcs7_buf == NULL ) {
        ret = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
        goto out;
    }
    /* set ptr to the end of the buffer, mbedtls functions write backwards */
    ptr = pkcs7_buf + pkcs7_buf_size;

    /* this will call all other PKCS7 generation functions */
    ret = pkcs7_start_generation( (unsigned char **) &pkcs7_buf, &pkcs7_buf_size,
                                  &ptr, &info );
    if( ret )
        goto out;

    /* trim pkcs7 */
    white_space = get_leading_unused_bytes( pkcs7_buf, pkcs7_buf_size );
    pkcs7_buf_size -= white_space;

    /* copy into new buffer with only necessary allocated memory */
    *pkcs7_size = pkcs7_buf_size;
    *pkcs7 = mbedtls_calloc( 1, *pkcs7_size );
    if( *pkcs7 == NULL ) {
        ret = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
        goto out;
    }
    memcpy( *pkcs7, pkcs7_buf + white_space, *pkcs7_size );

out:
    mbedtls_free( pkcs7_buf );
    return( ret );
}
#endif
