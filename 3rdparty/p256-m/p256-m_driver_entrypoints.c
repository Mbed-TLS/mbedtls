/*
 *  Driver entry points for p256-m
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
 */

#include "mbedtls/platform.h"
#include "p256-m_driver_entrypoints.h"
#include "p256-m/p256-m.h"
#include "psa/crypto.h"
#include <stddef.h>

#if defined(MBEDTLS_P256M_EXAMPLE_DRIVER_ENABLED)

/* INFORMATION ON PSA KEY EXPORT FORMATS:
 *
 * PSA exports SECP256R1 keys in two formats:
 * 1. Keypair format: 32 byte string which is just the private key (public key
 *                    can be calculated from the private key)
 * 2. Public Key format: A leading byte 0x04 (indicating uncompressed format),
 *                       followed by the 64 byte public key. This results in a
 *                       total of 65 bytes.
 *
 * p256-m's internal format for private keys matches PSA. Its format for public
 * keys is only 64 bytes; the same as PSA but without the leading byte (0x04).
 * Hence, when passing public keys from PSA to p256-m, the leading byte is
 * removed.
 */

/* Convert between p256-m and PSA error codes */
static psa_status_t p256_to_psa_error(int ret)
{
    switch (ret) {
        case P256_SUCCESS:
            return PSA_SUCCESS;
        case P256_INVALID_PUBKEY:
        case P256_INVALID_PRIVKEY:
            return PSA_ERROR_INVALID_ARGUMENT;
        case P256_INVALID_SIGNATURE:
            return PSA_ERROR_INVALID_SIGNATURE;
        case P256_RANDOM_FAILED:
        default:
            return PSA_ERROR_GENERIC_ERROR;
    }
}

psa_status_t p256_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length)
{
    /* We don't use this argument, but the specification mandates the signature
     * of driver entry-points. (void) used to avoid compiler warning. */
    (void) attributes;

    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    /*
     *  p256-m generates a 32 byte private key, and expects to write to a buffer
     *   that is of that size. */
    if (key_buffer_size != 32) {
        return status;
    }

    /*
     *  p256-m's keypair generation function outputs both public and private
     *  keys. Allocate a buffer to which the public key will be written. The
     *  private key will be written to key_buffer, which is passed to this
     *  function as an argument. */
    uint8_t public_key_buffer[64];

    status = p256_to_psa_error(
        p256_gen_keypair(key_buffer, public_key_buffer));
    if (status == PSA_SUCCESS) {
        *key_buffer_length = 32;
    }

    return status;
}

psa_status_t p256_transparent_key_agreement(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length)
{
    /* We don't use these arguments, but the specification mandates the
     * sginature of driver entry-points. (void) used to avoid compiler
     * warning. */
    (void) attributes;
    (void) alg;

    /*
     *  Check that private key = 32 bytes, peer public key = 65 bytes,
     *  and that the shared secret buffer is big enough. */
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;
    if (key_buffer_size != 32 || shared_secret_size < 32 ||
        peer_key_length != 65) {
        return status;
    }

    /* We add 1 to peer_key pointer to omit the leading byte of the public key
     * representation (0x04). See information about PSA key formats at the top
     * of the file. */
    status = p256_to_psa_error(
        p256_ecdh_shared_secret(shared_secret, key_buffer, peer_key+1));
    if (status == PSA_SUCCESS) {
        *shared_secret_length = 32;
    }

    return status;
}

psa_status_t p256_transparent_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length)
{
    /* We don't use these arguments, but the specification mandates the
     * sginature of driver entry-points. (void) used to avoid compiler
     * warning. */
    (void) attributes;
    (void) alg;

    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;
    if (key_buffer_size != 32 || signature_size != 64) {
        return status;
    }

    status = p256_to_psa_error(
        p256_ecdsa_sign(signature, key_buffer, hash, hash_length));
    if (status == PSA_SUCCESS) {
        *signature_length = 64;
    }

    return status;
}

/*  This function expects the key buffer to contain a 65 byte public key,
 *  as exported by psa_export_public_key() */
static psa_status_t p256_verify_hash_with_public_key(
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length)
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;
    if (key_buffer_size != 65 || signature_length != 64 || *key_buffer != 0x04) {
        return status;
    }

    /* We add 1 to public_key_buffer pointer to omit the leading byte of the
     * public key representation (0x04). See information about PSA key formats
     * at the top of the file. */
    const uint8_t *public_key_buffer = key_buffer + 1;
    status = p256_to_psa_error(
        p256_ecdsa_verify(signature, public_key_buffer, hash, hash_length));

    return status;
}

psa_status_t p256_transparent_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length)
{
    /* We don't use this argument, but the specification mandates the signature
     * of driver entry-points. (void) used to avoid compiler warning. */
    (void) alg;

    psa_status_t status;
    uint8_t public_key_buffer[65];
    size_t public_key_buffer_size = 65;

    size_t public_key_length = 65;
    /* As p256-m doesn't require dynamic allocation, we want to avoid it in
     * the entrypoint functions as well. psa_driver_wrapper_export_public_key()
     * requires size_t*, so we use a pointer to a stack variable. */
    size_t *public_key_length_ptr = &public_key_length;

    /* The contents of key_buffer may either be the 32 byte private key
     * (keypair format), or 0x04 followed by the 64 byte public key (public
     * key format). To ensure the key is in the latter format, the public key
     * is exported. */
    status = psa_driver_wrapper_export_public_key(
        attributes,
        key_buffer,
        key_buffer_size,
        public_key_buffer,
        public_key_buffer_size,
        public_key_length_ptr);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = p256_verify_hash_with_public_key(
        public_key_buffer,
        public_key_buffer_size,
        hash,
        hash_length,
        signature,
        signature_length);

exit:
    return status;
}

#endif /* MBEDTLS_P256M_EXAMPLE_DRIVER_ENABLED */
