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
 * \file ecies_envelope.h
 *
 * Provides function to process ECIES envelope ASN.1 structure:
 *
 *     ECIES-Envelope-Schema DEFINITIONS EXPLICIT TAGS ::=
 *     BEGIN
 *
 *        IMPORTS
 *
 *          -- Imports from RFC 5280, Appendix A.1
 *             AlgorithmIdentifier
 *                 FROM PKIX1Explicit88
 *                     { iso(1) identified-organization(3) dod(6)
 *                       internet(1) security(5) mechanisms(5) pkix(7)
 *                       mod(0) pkix1-explicit(18) }
 *
 *          -- Imports from ISO/IEC 18033-2, Appendix B
 *             KeyDerivationFunction
 *                 FROM AlgorithmObjectIdentifiers
 *                     { iso(1) standard(0) encryption-algorithms(18033) part(2)
 *                       asn1-module(0) algorithm-object-identifiers(0) };
 *
 *
 *         ECIES-Envelope ::= SEQUENCE {
 *             version          INTEGER { v0(0) },
 *             originator       OriginatorPublicKey,
 *             kdf              KeyDerivationFunction,
 *             hmac             DigestInfo,
 *             encryptedContent EncryptedContentInfo
 *         }
 *
 *         OriginatorPublicKey ::= SEQUENCE {
 *             algorithm AlgorithmIdentifier,
 *             publicKey BIT STRING
 *         }
 *
 *         DigestInfo ::= SEQUENCE {
 *             digestAlgorithm    DigestAlgorithmIdentifier,
 *             digest             Digest
 *         }
 *
 *         DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 *         Digest ::= OCTET STRING
 *
 *         EncryptedContentInfo ::= SEQUENCE {
 *             contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *             encryptedContent EncryptedContent
 *         }
 *
 *         ContentEncryptionAlgorithmIdentifier :: = AlgorithmIdentifier
 *
 *         EncryptedContent ::= OCTET STRING
 *     END
 */

#ifndef POLARSSL_ECIES_ENVELOPE_H
#define POLARSSL_ECIES_ENVELOPE_H

#include "ecp.h"
#include "md.h"
#include "kdf.h"
#include "cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Read actual envelope length.
 */
int ecies_read_envelope(unsigned char **p, const unsigned char *end, size_t *len);
/**
 * \brief Read envelope version.
 */
int ecies_read_version(unsigned char **p, const unsigned char *end, int *version);
/**
 * \brief Read originator public key as ECP key pair.
 */
int ecies_read_originator(unsigned char **p, const unsigned char *end,
        ecp_keypair **originator_keypair);
/**
 * \brief Read key derivation function and underlying digest function.
 */
int ecies_read_kdf(unsigned char **p, const unsigned char *end,
        kdf_type_t *kdf_type, md_type_t *md_type);
/**
 * \brief Read HMAC.
 */
int ecies_read_hmac(unsigned char **p, const unsigned char *end,
        md_type_t *hmac_type, unsigned char **hmac, size_t *hmac_len);
/**
 * \brief Read encrypted content info.
 */
int ecies_read_content_info(unsigned char **p, const unsigned char *end,
        cipher_type_t *cipher_type, unsigned char **iv, size_t *iv_len,
        unsigned char **data, size_t *data_len);

/**
 * \brief Write actual envelope length.
 * \return The length written or a negative error code.
 */
int ecies_write_envelope(unsigned char **p, unsigned char *start, size_t len);
/**
 * \brief Write envelope version.
 * \return The length written or a negative error code.
 */
int ecies_write_version(unsigned char **p, unsigned char *start, int version);
/**
 * \brief Write originator public key as ECP key pair.
 * \return The length written or a negative error code.
 */
int ecies_write_originator(unsigned char **p, unsigned char *start,
        ecp_keypair *originator_keypair);
/**
 * \brief Write key derivation function and underlying digest function.
 * \return The length written or a negative error code.
 */
int ecies_write_kdf(unsigned char **p, unsigned char *start,
        kdf_type_t kdf_type, md_type_t md_type);
/**
 * \brief Write HMAC.
 * \return The length written or a negative error code.
 */
int ecies_write_hmac(unsigned char **p, unsigned char *start,
        md_type_t hmac_type, const unsigned char *hmac, size_t hmac_len);
/**
 * \brief Write metadata for encrypted content info.
 * \return The length written or a negative error code.
 * \note Assume that *p param points to the encrypted data.
 */
int ecies_write_content_info(unsigned char **p, unsigned char *start,
        cipher_type_t cipher_type, const unsigned char *iv, size_t iv_len, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_ECIES_ENVELOPE_H */
