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

#ifndef POLARSSL_ECIES_H
#define POLARSSL_ECIES_H

#include "config.h"

#if defined(POLARSSL_ECP_C)
#include "polarssl/ecp.h"
#endif

#if defined(_MSC_VER) && !defined(EFIX64) && !defined(EFI32)
#include <basetsd.h>
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
#else
#include <inttypes.h>
#endif

#define POLARSSL_ERR_ECIES_BAD_INPUT_DATA                    -0x7F80  /**< Bad input parameters to function. */
#define POLARSSL_ERR_ECIES_OUTPUT_TOO_SMALL                  -0x7F00  /**< Output buffer too small. */
#define POLARSSL_ERR_ECIES_MALFORMED_DATA                    -0x7E80  /**< Encrypted data is malformed. */
#define POLARSSL_ERR_ECIES_MALLOC_FAILED                     -0x7D00  /**< Memory allocation failed */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Perform ECIES encryption.
 * \return         0 if successful
 */
int ecies_encrypt(ecp_keypair *key, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
/**
 * \brief          Perform ECIES decryption.
 * \return         0 if successful
 */
int ecies_decrypt(ecp_keypair *key, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);


#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_ECIES_H */
