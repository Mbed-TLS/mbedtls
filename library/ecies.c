
/**
 * Copyright (C) 2014 Virgil Security Inc.
 *
 * This file is part of extension to mbed TLS (http://polarssl.org)
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * Implementation is based on the standard ISO 18033-2.
 */

#include "polarssl/config.h"

#if defined(POLARSSL_ECIES_C)

#include "polarssl/ecies.h"
#include "polarssl/ecies_envelope.h"

#include "polarssl/pk.h"
#include "polarssl/cipher.h"
#include "polarssl/ecdh.h"
#include "polarssl/md.h"
#include "polarssl/kdf.h"

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#include <stdlib.h>
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

#ifdef POLARSSL_ECIES_DEBUG
#include <stdio.h>
#endif /* POLARSSL_ECIES_DEBUG */

#define INVOKE_AND_CHECK(result,invocation) \
    if ((result = invocation) < 0) goto exit;

#define ACCUMULATE_AND_CHECK(result, len, invocation) \
do { \
    if ((result = invocation) < 0) { \
        goto exit; \
    } else { \
        len += result; \
        result = 0; \
    } \
} while (0)

#define ECIES_OCTET_SIZE 8
#define ECIES_SIZE_TO_OCTETS(size) ((size + 7) / ECIES_OCTET_SIZE)

#define ECIES_ENVELOPE_VERSION 0
#define ECIES_CIPHER_PADDING POLARSSL_PADDING_PKCS7

#define ECIES_CIPHER_TYPE POLARSSL_CIPHER_AES_256_CBC
#define ECIES_MD_TYPE POLARSSL_MD_SHA256
#define ECIES_HMAC_TYPE POLARSSL_MD_SHA256
#define ECIES_KDF_TYPE POLARSSL_KDF_KDF2

static int ecies_ka(ecp_keypair *public, const ecp_keypair *private,
        mpi *shared, int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    if (public == NULL || private == NULL || shared == NULL) {
        return POLARSSL_ERR_ECIES_BAD_INPUT_DATA;
    }
    if (public->grp.id != private->grp.id) {
        return POLARSSL_ERR_ECIES_BAD_INPUT_DATA;
    }
    return ecdh_compute_shared(&public->grp, shared, &public->Q, &private->d,
            f_rng, p_rng);
}


#ifdef POLARSSL_ECIES_DEBUG
static void ecies_print_buf(const char *title, const unsigned char *buf,
        size_t buf_len)
{
    size_t i = 0;
    fprintf(stdout, "%s\n", title);
    for(i = 0; i < buf_len; ++i) {
        fprintf(stdout, "%02X%s", buf[i], ( i + 1 ) % 16 == 0 ? "\r\n" : " " );
    }

}
#endif /* POLARSSL_ECIES_DEBUG */

int ecies_encrypt(ecp_keypair *key, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int result = 0;
    ecp_keypair ephemeral_key;
    mpi shared_key;
    unsigned char *shared_key_binary = NULL; // MUST be released
    size_t shared_key_binary_len = 0;
    const md_info_t *md_info = NULL;
    const kdf_info_t *kdf_info = NULL;
    const md_info_t *hmac_info = NULL;
    unsigned char *kdf_value = NULL; // MUST be released
    size_t hmac_len = 0;
    unsigned char *hmac = NULL; // MUST be released
    size_t kdf_len = 0;
    unsigned char *cipher_key = NULL; // pointer inside data: kdf_value
    size_t cipher_key_len = 0;
    unsigned char *cipher_iv = NULL; // MUST be released
    size_t cipher_iv_len = 0;
    unsigned char *hmac_key = NULL; // pointer inside data: kdf_value
    size_t hmac_key_len = 0;
    cipher_context_t cipher_ctx;
    size_t cipher_block_size = 0;
    size_t cipher_enc_data_len = 0;
    size_t cipher_enc_header_len = 0;
    unsigned char *cipher_enc_data = NULL; // pointer inside data: output
    unsigned char *ephem_key_X_binary = NULL; // MUST be released
    size_t ephem_key_X_binary_len = 32;
    unsigned char *ephem_key_Y_binary = NULL; // MUST be released
    size_t ephem_key_Y_binary_len = 32;
    size_t kdf_input_len = 0;
    unsigned char *kdf_input;
    unsigned char *hmac_input = NULL;  // pointer inside data: output
    size_t hmac_input_len = 0;
    int hmac_extra = 8;

    if (key == NULL || input == NULL || output == NULL || olen == NULL) {
        return POLARSSL_ERR_ECIES_BAD_INPUT_DATA;
    }

    // Init structures.
    *olen = 0;

    md_info = md_info_from_type(ECIES_MD_TYPE);
    kdf_info = kdf_info_from_type(ECIES_KDF_TYPE);
    hmac_info = md_info_from_type(ECIES_HMAC_TYPE);

    mpi_init(&shared_key);
    ecp_keypair_init(&ephemeral_key);
    cipher_init(&cipher_ctx);
    INVOKE_AND_CHECK(result,
        cipher_init_ctx(&cipher_ctx, cipher_info_from_type(ECIES_CIPHER_TYPE))
    );

    cipher_iv_len = cipher_get_iv_size(&cipher_ctx);
    cipher_key_len = ECIES_SIZE_TO_OCTETS(cipher_get_key_size(&cipher_ctx));
    hmac_len = md_get_size(hmac_info);
    hmac_key_len = hmac_len;
    kdf_len = cipher_key_len + hmac_key_len;

    kdf_value = polarssl_malloc(kdf_len);
    if (kdf_value == NULL) {
        INVOKE_AND_CHECK(result, POLARSSL_ERR_ECIES_MALLOC_FAILED)
    }
    memset(kdf_value, 0, kdf_len);

    cipher_key = kdf_value;
    hmac_key = kdf_value + cipher_key_len;

    // 1. Generate ephemeral keypair.
    INVOKE_AND_CHECK(result,
        ecp_gen_key(key->grp.id, &ephemeral_key, f_rng, p_rng)
    );
    // 2. Compute shared secret key.
    INVOKE_AND_CHECK(result,
        ecies_ka(key, &ephemeral_key, &shared_key, f_rng, p_rng)
    );
    shared_key_binary_len = ECIES_SIZE_TO_OCTETS(key->grp.pbits);
    shared_key_binary = polarssl_malloc(shared_key_binary_len);
    if (shared_key_binary == NULL) {
        INVOKE_AND_CHECK(result, POLARSSL_ERR_ECIES_MALLOC_FAILED)
    }
    memset(shared_key_binary, 0, shared_key_binary_len);
    INVOKE_AND_CHECK(result,
        mpi_write_binary(&shared_key, shared_key_binary, shared_key_binary_len)
    );


    // 2.2 Convert the ephemeral key to binary, and append to shared_key_binary
    ephem_key_X_binary = polarssl_malloc(ephem_key_X_binary_len);
    ephem_key_Y_binary = polarssl_malloc(ephem_key_Y_binary_len);
    memset(ephem_key_X_binary, 0, ephem_key_X_binary_len);
    memset(ephem_key_Y_binary, 0, ephem_key_Y_binary_len);
   
    INVOKE_AND_CHECK(result,
        mpi_write_binary(&ephemeral_key.Q.X, ephem_key_X_binary, ephem_key_X_binary_len)
    );
    INVOKE_AND_CHECK(result,
        mpi_write_binary(&ephemeral_key.Q.Y, ephem_key_Y_binary, ephem_key_Y_binary_len)
    );

    // 2.4 Concatenate the pubkey, and shared_key

    kdf_input_len = 1 + ephem_key_X_binary_len + ephem_key_Y_binary_len + shared_key_binary_len;
    kdf_input = polarssl_malloc(kdf_input_len);
    memset(kdf_input, 0x04, 1);
    memcpy(kdf_input + 1 , ephem_key_X_binary, ephem_key_X_binary_len);
    memcpy(kdf_input +1 + ephem_key_X_binary_len, ephem_key_Y_binary, ephem_key_Y_binary_len);
    memcpy(kdf_input + 1 + ephem_key_X_binary_len + ephem_key_Y_binary_len, shared_key_binary, shared_key_binary_len);
   
    // 3. Derive keys (encryption key and hmac key).
    /* INVOKE_AND_CHECK(result, */
    /*     kdf(kdf_info, md_info, shared_key_binary, shared_key_binary_len, */
    /*             kdf_value, kdf_len) */
    /* ); */

    INVOKE_AND_CHECK(result,
		     kdf(kdf_info, md_info, kdf_input, kdf_input_len,
			 kdf_value, kdf_len)
    );

    
    // 4. Encrypt given message.
    cipher_iv = polarssl_malloc(cipher_iv_len);
    if (cipher_iv == NULL) {
        INVOKE_AND_CHECK(result, POLARSSL_ERR_ECIES_MALLOC_FAILED)
    }
    memset(cipher_iv, 0, cipher_iv_len);
    INVOKE_AND_CHECK(result,
        f_rng(p_rng, cipher_iv, cipher_iv_len)
    );
    INVOKE_AND_CHECK(result,
        cipher_setkey(&cipher_ctx, cipher_key,
                cipher_key_len * ECIES_OCTET_SIZE, POLARSSL_ENCRYPT)
    );
    INVOKE_AND_CHECK(result,
        cipher_set_padding_mode(&cipher_ctx, ECIES_CIPHER_PADDING)
    );
    INVOKE_AND_CHECK(result,
        cipher_reset(&cipher_ctx)
    );
    cipher_block_size = cipher_get_block_size(&cipher_ctx);
    cipher_enc_data_len = ilen + cipher_block_size;
    if (osize < cipher_enc_data_len) {
        result = POLARSSL_ERR_ECIES_OUTPUT_TOO_SMALL;
        goto exit;
    }
    cipher_enc_data = output + osize - cipher_enc_data_len;
    INVOKE_AND_CHECK(result,
        cipher_crypt(&cipher_ctx, cipher_iv, cipher_iv_len, input, ilen,
                cipher_enc_data, &cipher_enc_data_len)
    );
    // 5. Get HMAC for encrypted message.
    hmac = polarssl_malloc(hmac_len);
    if (hmac == NULL) {
        INVOKE_AND_CHECK(result, POLARSSL_ERR_ECIES_MALLOC_FAILED)
    }
    memset(hmac, 0, hmac_len);

    hmac_input_len = cipher_enc_data_len + hmac_extra;
    hmac_input = polarssl_malloc(hmac_input_len);
    memcpy(hmac_input, cipher_enc_data, cipher_enc_data_len);
    memset(hmac_input + cipher_enc_data_len, 0, hmac_extra);
    
    /* INVOKE_AND_CHECK(result, */
    /*     md_hmac(hmac_info, hmac_key, hmac_key_len, */
    /*             cipher_enc_data, cipher_enc_data_len, hmac) */
    /* ); */

    INVOKE_AND_CHECK(result,
        md_hmac(hmac_info, hmac_key, hmac_key_len,
                hmac_input, hmac_input_len, hmac)
    );

    // 6. Write envelope.
    cipher_enc_header_len = 0;
    ACCUMULATE_AND_CHECK(result, cipher_enc_header_len,
        ecies_write_content_info(&cipher_enc_data, output, ECIES_CIPHER_TYPE,
                cipher_iv, cipher_iv_len, cipher_enc_data_len)
    );

    ACCUMULATE_AND_CHECK(result, cipher_enc_header_len,
        ecies_write_hmac(&cipher_enc_data, output, md_get_type(hmac_info),
                hmac, hmac_len)
    );

    ACCUMULATE_AND_CHECK(result, cipher_enc_header_len,
        ecies_write_kdf(&cipher_enc_data, output, kdf_get_type(kdf_info),
                md_get_type(md_info))
    );

    ACCUMULATE_AND_CHECK(result, cipher_enc_header_len,
        ecies_write_originator(&cipher_enc_data, output, &ephemeral_key)
    );
    ACCUMULATE_AND_CHECK(result, cipher_enc_header_len,
        ecies_write_version(&cipher_enc_data, output, ECIES_ENVELOPE_VERSION)
    );
    ACCUMULATE_AND_CHECK(result, cipher_enc_header_len,
        ecies_write_envelope(&cipher_enc_data, output, cipher_enc_header_len)
    );
    memmove(output, cipher_enc_data, cipher_enc_header_len);
    memset(output + cipher_enc_header_len, 0, osize - cipher_enc_header_len);
exit:
    *olen = cipher_enc_header_len;
    cipher_free(&cipher_ctx);
    ecp_keypair_free(&ephemeral_key);
    mpi_free(&shared_key);
    if (shared_key_binary != NULL) {
        polarssl_free(shared_key_binary);
    }
    if (kdf_value != NULL) {
        polarssl_free(kdf_value);
    }
    if (cipher_iv != NULL) {
        polarssl_free(cipher_iv);
    }
    if (hmac != NULL) {
        polarssl_free(hmac);
    }
    if (ephem_key_X_binary != NULL) {
      polarssl_free(ephem_key_X_binary);
    }
    if (ephem_key_Y_binary != NULL) {
      polarssl_free(ephem_key_Y_binary);
    }
    if (hmac_input != NULL) {
      polarssl_free(hmac_input);
    }
    return result;
}


int ecies_decrypt(ecp_keypair *key, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int result = 0;
    int version = 0;
    ecp_keypair *ephemeral_key = NULL; // MUST be released
    mpi shared_key;
    unsigned char *shared_key_binary = NULL; // MUST be released
    size_t shared_key_binary_len = 0;
    md_type_t md_type = POLARSSL_MD_NONE;
    kdf_type_t kdf_type = POLARSSL_KDF_NONE;
    md_type_t hmac_type = POLARSSL_MD_NONE;
    unsigned char *kdf_value = NULL; // MUST be released
    size_t hmac_base_len = 0;
    unsigned char *hmac_base = NULL; // pointer inside data: input
    size_t hmac_len = 0;
    unsigned char *hmac = NULL; // MUST be released
    size_t kdf_len = 0;
    unsigned char *cipher_key = NULL; // pointer inside data: kdf_value
    size_t cipher_key_len = 0;
    unsigned char *hmac_key = NULL; // pointer inside data: kdf_value
    size_t hmac_key_len = 0;
    unsigned char *cipher_iv = NULL; // pointer inside data: input
    size_t cipher_iv_len = 0;
    cipher_type_t cipher_type = POLARSSL_CIPHER_NONE;
    cipher_context_t cipher_ctx;
    size_t cipher_enc_data_len = 0;
    size_t cipher_enc_header_len = 0;
    unsigned char *cipher_enc_data = NULL; // pointer inside data: input
    unsigned char *cipher_enc_header = NULL; // pointer inside data: input
    unsigned char *ephem_key_X_binary = NULL; // MUST be released
    size_t ephem_key_X_binary_len = 32;
    unsigned char *ephem_key_Y_binary = NULL; // MUST be released
    size_t ephem_key_Y_binary_len = 32;
    size_t kdf_input_len = 0;
    unsigned char *kdf_input;
    unsigned char *hmac_input = NULL;  // pointer inside data: output
    size_t hmac_input_len = 0;
    int hmac_extra = 8;

    if (key == NULL || input == NULL || output == NULL || olen == NULL) {
        return POLARSSL_ERR_ECIES_BAD_INPUT_DATA;
    }

    // Init structures.
    *olen = 0;
    cipher_init(&cipher_ctx);
    mpi_init(&shared_key);
    cipher_enc_header = (unsigned char *)input;
    INVOKE_AND_CHECK(result,
        ecies_read_envelope(&cipher_enc_header, input + ilen,
                &cipher_enc_header_len)
    );
    INVOKE_AND_CHECK(result,
        ecies_read_version(&cipher_enc_header, input + ilen, &version)
    );
    if (version != ECIES_ENVELOPE_VERSION) {
        result = POLARSSL_ERR_ECIES_MALFORMED_DATA;
        goto exit;
    }
    INVOKE_AND_CHECK(result,
        ecies_read_originator(&cipher_enc_header, input + ilen, &ephemeral_key)
    );
    INVOKE_AND_CHECK(result,
        ecies_read_kdf(&cipher_enc_header, input + ilen, &kdf_type, &md_type)
    );
    INVOKE_AND_CHECK(result,
        ecies_read_hmac(&cipher_enc_header, input + ilen, &hmac_type,
                &hmac_base, &hmac_base_len)
    );
    INVOKE_AND_CHECK(result,
        ecies_read_content_info(&cipher_enc_header, input + ilen, &cipher_type,
                &cipher_iv, &cipher_iv_len, &cipher_enc_data,
                &cipher_enc_data_len)
    );

    INVOKE_AND_CHECK(result,
        cipher_init_ctx(&cipher_ctx, cipher_info_from_type(cipher_type))
    );
    cipher_key_len = ECIES_SIZE_TO_OCTETS(cipher_get_key_size(&cipher_ctx));
    hmac_len = md_get_size(md_info_from_type(hmac_type));
    hmac_key_len = hmac_len;
    kdf_len = cipher_key_len + hmac_key_len;
    kdf_value = polarssl_malloc(kdf_len);
    if (kdf_value == NULL) {
        INVOKE_AND_CHECK(result, POLARSSL_ERR_ECIES_MALLOC_FAILED)
    }
    memset(kdf_value, 0, kdf_len);
    cipher_key = kdf_value;
    hmac_key = kdf_value + cipher_key_len;
    hmac = polarssl_malloc(hmac_len);
    if (hmac == NULL) {
        INVOKE_AND_CHECK(result, POLARSSL_ERR_ECIES_MALLOC_FAILED)
    }
    memset(hmac, 0, hmac_len);

    // 1. Compute shared secret key.
    INVOKE_AND_CHECK(result,
        ecies_ka(ephemeral_key, key, &shared_key, f_rng, p_rng)
    );
    shared_key_binary_len = ECIES_SIZE_TO_OCTETS(key->grp.pbits);
    shared_key_binary = polarssl_malloc(shared_key_binary_len);
    if (shared_key_binary == NULL) {
        INVOKE_AND_CHECK(result, POLARSSL_ERR_ECIES_MALLOC_FAILED)
    }
    memset(shared_key_binary, 0, shared_key_binary_len);
    INVOKE_AND_CHECK(result,
        mpi_write_binary(&shared_key, shared_key_binary, shared_key_binary_len)
    );


    // 1.2 Convert the ephemeral key to binary, and append to shared_key_binary
    ephem_key_X_binary = polarssl_malloc(ephem_key_X_binary_len);
    ephem_key_Y_binary = polarssl_malloc(ephem_key_Y_binary_len);
    memset(ephem_key_X_binary, 0, ephem_key_X_binary_len);
    memset(ephem_key_Y_binary, 0, ephem_key_Y_binary_len);
   
    INVOKE_AND_CHECK(result,
		     mpi_write_binary((&ephemeral_key->Q.X), ephem_key_X_binary, ephem_key_X_binary_len)
    );
    INVOKE_AND_CHECK(result,
		     mpi_write_binary((&ephemeral_key->Q.Y), ephem_key_Y_binary, ephem_key_Y_binary_len)
    );

    // 1.4 Concatenate the pubkey, and shared_key

    kdf_input_len = 1 + ephem_key_X_binary_len + ephem_key_Y_binary_len + shared_key_binary_len;
    kdf_input = polarssl_malloc(kdf_input_len);
    memset(kdf_input, 0x04, 1);
    memcpy(kdf_input + 1 , ephem_key_X_binary, ephem_key_X_binary_len);
    memcpy(kdf_input +1 + ephem_key_X_binary_len, ephem_key_Y_binary, ephem_key_Y_binary_len);
    memcpy(kdf_input + 1 + ephem_key_X_binary_len + ephem_key_Y_binary_len, shared_key_binary, shared_key_binary_len);

    
    // 2. Derive keys (encryption key and hmac key).
    /* INVOKE_AND_CHECK(result, */
    /* 		     kdf(kdf_info_from_type(kdf_type), md_info_from_type(md_type), */
    /* 			 shared_key_binary, shared_key_binary_len, kdf_value, kdf_len) */
    /* 		     ); */

    INVOKE_AND_CHECK(result,
		     kdf(kdf_info_from_type(kdf_type), md_info_from_type(md_type), kdf_input, kdf_input_len,
			 kdf_value, kdf_len)
		     );



    // 3. Get HMAC for encrypted message and compare it.

    memset(hmac, 0, hmac_len);

    hmac_input_len = cipher_enc_data_len + hmac_extra;
    hmac_input = polarssl_malloc(hmac_input_len);
    memcpy(hmac_input, cipher_enc_data, cipher_enc_data_len);
    memset(hmac_input + cipher_enc_data_len, 0, hmac_extra);
    
    /* INVOKE_AND_CHECK(result, */
    /*     md_hmac(md_info_from_type(hmac_type), hmac_key, hmac_key_len, */
    /*             cipher_enc_data, cipher_enc_data_len, hmac) */
    /* ); */

        INVOKE_AND_CHECK(result,
			 md_hmac(md_info_from_type(hmac_type), hmac_key, hmac_key_len,
                hmac_input, hmac_input_len, hmac)
    );

    

    if (hmac_base_len != hmac_len || memcmp(hmac_base, hmac, hmac_len) != 0) {
        result = POLARSSL_ERR_ECIES_MALFORMED_DATA;
        goto exit;
    }
    // 4. Decrypt given message.
    INVOKE_AND_CHECK(result,
        cipher_setkey(&cipher_ctx, cipher_key,
                cipher_key_len * ECIES_OCTET_SIZE, POLARSSL_DECRYPT)
    );
    INVOKE_AND_CHECK(result,
        cipher_set_padding_mode(&cipher_ctx, ECIES_CIPHER_PADDING)
    );
    INVOKE_AND_CHECK(result,
        cipher_reset(&cipher_ctx)
    );
    if (osize < cipher_enc_data_len) {
        result = POLARSSL_ERR_ECIES_OUTPUT_TOO_SMALL;
        goto exit;
    }
    INVOKE_AND_CHECK(result,
        cipher_crypt(&cipher_ctx, cipher_iv, cipher_iv_len, cipher_enc_data,
                cipher_enc_data_len, output, olen)
    );
exit:
    cipher_free(&cipher_ctx);
    ecp_keypair_free(ephemeral_key);
    mpi_free(&shared_key);
    if (shared_key_binary != NULL) {
        polarssl_free(shared_key_binary);
    }
    if (kdf_value != NULL) {
        polarssl_free(kdf_value);
    }
    if (hmac != NULL) {
        polarssl_free(hmac);
    }
        if (ephem_key_X_binary != NULL) {
      polarssl_free(ephem_key_X_binary);
    }
    if (ephem_key_Y_binary != NULL) {
      polarssl_free(ephem_key_Y_binary);
    }
    if (hmac_input != NULL) {
      polarssl_free(hmac_input);
    }
    return result;
}

#endif /* defined(POLARSSL_ECIES_C) */
