#ifndef MBEDTLS_PSA_CRYPTO_ASYNC_TLS_H
#define MBEDTLS_PSA_CRYPTO_ASYNC_TLS_H

#include "mbedtls/psa_crypto_async_provider.h"

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*mbedtls_psa_async_tls_callback_t)(int success, void* context);

int mbedtls_psa_async_tls_bind(mbedtls_psa_async_crypto_provider_t* provider);
int mbedtls_psa_async_tls_unbind(mbedtls_psa_async_crypto_provider_t* provider);
int mbedtls_psa_async_tls_begin_call(void* owner);
void mbedtls_psa_async_tls_end_call(void* owner);
void mbedtls_psa_async_tls_service(void);
void mbedtls_psa_async_tls_abort(void);
void mbedtls_psa_async_tls_abort_owner(void* owner);
int mbedtls_psa_async_tls_busy(void);

void mbedtls_psa_async_tls_set_trusted_time(uint64_t unix_time);
void mbedtls_psa_async_tls_clear_trusted_time(void);
uint64_t mbedtls_psa_async_tls_get_trusted_time(void);

time_t mbedtls_platform_time(time_t* current_time);

int mbedtls_psa_async_tls_random_start(uint8_t* output, size_t length,
                                        mbedtls_psa_async_tls_callback_t callback, void* context);

int mbedtls_psa_async_tls_ecdh_p256_public_key_start(
    const uint8_t private_key[32], uint8_t public_key[65],
    mbedtls_psa_async_tls_callback_t callback, void* context);
int mbedtls_psa_async_tls_ecdh_p384_public_key_start(
    const uint8_t private_key[48], uint8_t public_key[97],
    mbedtls_psa_async_tls_callback_t callback, void* context);
int mbedtls_psa_async_tls_ecdh_p521_public_key_start(
    const uint8_t private_key[66], uint8_t public_key[133],
    mbedtls_psa_async_tls_callback_t callback, void* context);

int mbedtls_psa_async_tls_ecdh_p256_start(const uint8_t private_key[32],
                                           const uint8_t peer_public_key[65],
                                           uint8_t shared_secret[32],
                                           mbedtls_psa_async_tls_callback_t callback,
                                           void* context);
int mbedtls_psa_async_tls_ecdh_p384_start(const uint8_t private_key[48],
                                           const uint8_t peer_public_key[97],
                                           uint8_t shared_secret[48],
                                           mbedtls_psa_async_tls_callback_t callback,
                                           void* context);
int mbedtls_psa_async_tls_ecdh_p521_start(const uint8_t private_key[66],
                                           const uint8_t peer_public_key[133],
                                           uint8_t shared_secret[66],
                                           mbedtls_psa_async_tls_callback_t callback,
                                           void* context);

int mbedtls_psa_async_tls_ecdsa_p256_sign_start(
    const uint8_t private_key[32], const uint8_t hash[32], uint8_t signature[64],
    mbedtls_psa_async_tls_callback_t callback, void* context);
int mbedtls_psa_async_tls_ecdsa_p256_verify_start(
    const uint8_t public_key[65], const uint8_t hash[32], const uint8_t signature[64],
    mbedtls_psa_async_tls_callback_t callback, void* context);
int mbedtls_psa_async_tls_ecdsa_p384_sign_start(
    const uint8_t private_key[48], const uint8_t hash[48], uint8_t signature[96],
    mbedtls_psa_async_tls_callback_t callback, void* context);
int mbedtls_psa_async_tls_ecdsa_p384_verify_start(
    const uint8_t public_key[97], const uint8_t hash[48], const uint8_t signature[96],
    mbedtls_psa_async_tls_callback_t callback, void* context);
int mbedtls_psa_async_tls_ecdsa_p521_sign_start(
    const uint8_t private_key[66], const uint8_t hash[64], uint8_t signature[132],
    mbedtls_psa_async_tls_callback_t callback, void* context);
int mbedtls_psa_async_tls_ecdsa_p521_verify_start(
    const uint8_t public_key[133], const uint8_t hash[64], const uint8_t signature[132],
    mbedtls_psa_async_tls_callback_t callback, void* context);

int mbedtls_psa_async_tls_aead_encrypt_start(
    int algorithm, const uint8_t* key, size_t key_length, const uint8_t* nonce,
    size_t nonce_length, const uint8_t* aad, size_t aad_length, const uint8_t* plaintext,
    uint8_t* ciphertext, size_t length, uint8_t* tag, size_t tag_length,
    mbedtls_psa_async_tls_callback_t callback, void* context);
int mbedtls_psa_async_tls_aead_decrypt_start(
    int algorithm, const uint8_t* key, size_t key_length, const uint8_t* nonce,
    size_t nonce_length, const uint8_t* aad, size_t aad_length, const uint8_t* ciphertext,
    uint8_t* plaintext, size_t length, const uint8_t* tag, size_t tag_length,
    mbedtls_psa_async_tls_callback_t callback, void* context);

int mbedtls_psa_async_tls_aes_gcm128_encrypt_start(
    const uint8_t key[16], const uint8_t nonce[12], const uint8_t* aad, size_t aad_length,
    const uint8_t* plaintext, uint8_t* ciphertext, size_t length, uint8_t tag[16],
    mbedtls_psa_async_tls_callback_t callback, void* context);
int mbedtls_psa_async_tls_aes_gcm128_decrypt_start(
    const uint8_t key[16], const uint8_t nonce[12], const uint8_t* aad, size_t aad_length,
    const uint8_t* ciphertext, uint8_t* plaintext, size_t length, const uint8_t tag[16],
    mbedtls_psa_async_tls_callback_t callback, void* context);

int mbedtls_psa_async_tls_rsa_pss_verify_start(
    int hash_bits, const uint8_t* public_key, size_t public_key_length, const uint8_t* hash,
    size_t hash_length, const uint8_t* signature, size_t signature_length,
    mbedtls_psa_async_tls_callback_t callback, void* context);
int mbedtls_psa_async_tls_rsa_pkcs1_verify_start(
    int hash_bits, const uint8_t* public_key, size_t public_key_length, const uint8_t* hash,
    size_t hash_length, const uint8_t* signature, size_t signature_length,
    mbedtls_psa_async_tls_callback_t callback, void* context);
int mbedtls_psa_async_tls_rsa_pss_sign_start(
    int hash_bits, const uint8_t* private_key, size_t private_key_length, const uint8_t* hash,
    size_t hash_length, uint8_t* signature, size_t signature_length,
    mbedtls_psa_async_tls_callback_t callback, void* context);
int mbedtls_psa_async_tls_rsa_pkcs1_sign_start(
    int hash_bits, const uint8_t* private_key, size_t private_key_length, const uint8_t* hash,
    size_t hash_length, uint8_t* signature, size_t signature_length,
    mbedtls_psa_async_tls_callback_t callback, void* context);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PSA_CRYPTO_ASYNC_TLS_H */
