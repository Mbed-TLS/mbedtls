#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#include "mbedtls/psa_crypto_async_tls.h"

#include "mbedtls/psa_crypto_async_curves.h"

#include <mbedtls/platform_time.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/private/bignum.h>
#include <mbedtls/private/rsa.h>
#include <stdbool.h>
#include <string.h>

int mbedtls_rsa_parse_pubkey(mbedtls_rsa_context* rsa, const unsigned char* key, size_t key_length);
int mbedtls_rsa_parse_key(mbedtls_rsa_context* rsa, const unsigned char* key, size_t key_length);

#define MBEDTLS_PSA_CRYPTO_ASYNC_TLS_MAX_RSA_BYTES 512u
#define MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_OPERATION_CAPACITY 8u

typedef enum mbedtls_psa_async_tls_generic_stage_e {
  MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_IDLE = 0,
  MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_DIRECT = 1,
  MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_SIGNATURE_RANDOM = 2,
} mbedtls_psa_async_tls_generic_stage_t;

typedef struct mbedtls_psa_async_tls_generic_operation_s {
  mbedtls_psa_async_crypto_operation_t provider_operation;
  mbedtls_psa_async_crypto_request_t request;
  mbedtls_psa_async_tls_callback_t callback;
  void* callback_context;
  void* owner;
  mbedtls_psa_async_crypto_prime_curve_t curve;
  const uint8_t* private_key;
  const uint8_t* hash;
  uint8_t* signature;
  size_t coordinate_length;
  size_t key_bits;
  size_t hash_length;
  mbedtls_psa_async_tls_generic_stage_t stage;
  uint8_t nonce[66];
} mbedtls_psa_async_tls_generic_operation_t;

typedef enum mbedtls_psa_async_tls_rsa_stage_e {
  MBEDTLS_PSA_CRYPTO_ASYNC_TLS_RSA_IDLE = 0,
  MBEDTLS_PSA_CRYPTO_ASYNC_TLS_RSA_RANDOM = 1,
  MBEDTLS_PSA_CRYPTO_ASYNC_TLS_RSA_EXPONENTIATION = 2,
} mbedtls_psa_async_tls_rsa_stage_t;

typedef struct mbedtls_psa_async_tls_rsa_operation_s {
  mbedtls_psa_async_crypto_operation_t provider_operation;
  mbedtls_psa_async_crypto_request_t request;
  mbedtls_rsa_context rsa;
  mbedtls_psa_async_tls_callback_t callback;
  void* callback_context;
  void* owner;
  const uint8_t* hash;
  uint8_t* signature_output;
  size_t hash_length;
  size_t modulus_length;
  mbedtls_md_type_t hash_algorithm;
  bool signing;
  bool pss;
  bool rsa_initialized;
  mbedtls_psa_async_tls_rsa_stage_t stage;
  uint8_t modulus[MBEDTLS_PSA_CRYPTO_ASYNC_TLS_MAX_RSA_BYTES];
  uint8_t exponent[MBEDTLS_PSA_CRYPTO_ASYNC_TLS_MAX_RSA_BYTES];
  uint8_t encoded[MBEDTLS_PSA_CRYPTO_ASYNC_TLS_MAX_RSA_BYTES];
  uint8_t signature[MBEDTLS_PSA_CRYPTO_ASYNC_TLS_MAX_RSA_BYTES];
  uint8_t salt[64];
} mbedtls_psa_async_tls_rsa_operation_t;

static mbedtls_psa_async_crypto_provider_t* provider = NULL;
static size_t provider_bindings = 0u;
static uint64_t current_trusted_time = 0u;
static void* active_call_owner = NULL;
static mbedtls_psa_async_tls_rsa_operation_t rsa_operation = {0};
static mbedtls_psa_async_tls_generic_operation_t
    generic_operations[MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_OPERATION_CAPACITY] = {0};

static void zeroize(void* data, size_t size) {
  volatile uint8_t* bytes = (volatile uint8_t*)data;
  while (size-- != 0u) {
    *bytes++ = 0u;
  }
}

static void reset_rsa(void) {
  if (rsa_operation.rsa_initialized) {
    mbedtls_rsa_free(&rsa_operation.rsa);
  }
  zeroize(&rsa_operation, sizeof(rsa_operation));
}

static void finish_rsa(bool success) {
  mbedtls_psa_async_tls_callback_t callback = rsa_operation.callback;
  void* context = rsa_operation.callback_context;
  reset_rsa();
  if (callback != NULL) {
    callback(success ? 1 : 0, context);
  }
}

static mbedtls_psa_async_tls_generic_operation_t*
allocate_generic(mbedtls_psa_async_tls_callback_t callback, void* context) {
  if (provider == NULL || callback == NULL) {
    return NULL;
  }
  for (size_t index = 0u; index < MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_OPERATION_CAPACITY; ++index) {
    if (generic_operations[index].stage == MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_IDLE) {
      memset(&generic_operations[index], 0, sizeof(generic_operations[index]));
      generic_operations[index].callback = callback;
      generic_operations[index].callback_context = context;
      generic_operations[index].owner = active_call_owner;
      return &generic_operations[index];
    }
  }
  return NULL;
}

static void finish_generic(mbedtls_psa_async_tls_generic_operation_t* operation, bool success) {
  mbedtls_psa_async_tls_callback_t callback = operation->callback;
  void* context = operation->callback_context;
  zeroize(operation, sizeof(*operation));
  if (callback != NULL) {
    callback(success ? 1 : 0, context);
  }
}

static bool start_generic(mbedtls_psa_async_tls_generic_operation_t* operation,
                          const mbedtls_psa_async_crypto_request_t* request,
                          mbedtls_psa_async_tls_generic_stage_t stage) {
  operation->request = *request;
  if (mbedtls_psa_async_crypto_start(provider, &operation->provider_operation,
                                     &operation->request) != PSA_SUCCESS) {
    zeroize(operation, sizeof(*operation));
    return false;
  }
  operation->stage = stage;
  return true;
}

static const mbedtls_psa_async_crypto_prime_curve_t* curve_for_bits(size_t bits) {
  return mbedtls_psa_async_crypto_resolve_prime_curve(
      PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), bits);
}

static bool prepare_random(uint8_t* output, size_t length,
                           mbedtls_psa_async_tls_callback_t callback, void* context) {
  mbedtls_psa_async_tls_generic_operation_t* operation = allocate_generic(callback, context);
  if (operation == NULL || output == NULL || length == 0u) {
    return false;
  }
  mbedtls_psa_async_crypto_request_t request = {0};
  request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RANDOM;
  request.output = (mbedtls_psa_async_crypto_buffer_t){output, length};
  return start_generic(operation, &request, MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_DIRECT);
}

static bool prepare_ecdh_public(size_t bits, const uint8_t* private_key, uint8_t* public_key,
                                mbedtls_psa_async_tls_callback_t callback, void* context) {
  mbedtls_psa_async_tls_generic_operation_t* operation = allocate_generic(callback, context);
  const mbedtls_psa_async_crypto_prime_curve_t* curve = curve_for_bits(bits);
  const size_t coordinate_length = (bits + 7u) / 8u;
  if (operation == NULL || curve == NULL || private_key == NULL || public_key == NULL) {
    return false;
  }
  mbedtls_psa_async_crypto_request_t request = {0};
  request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_EXPORT_PUBLIC_KEY;
  request.key_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
  request.key_bits = bits;
  request.alg = PSA_ALG_ECDH;
  request.private_key = (mbedtls_psa_async_crypto_const_buffer_t){private_key, coordinate_length};
  request.public_key_output =
      (mbedtls_psa_async_crypto_buffer_t){public_key, coordinate_length * 2u + 1u};
  operation->curve = *curve;
  request.prime_curve = &operation->curve;
  return start_generic(operation, &request, MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_DIRECT);
}

static bool prepare_ecdh(size_t bits, const uint8_t* private_key, const uint8_t* peer_public_key,
                         uint8_t* shared_secret, mbedtls_psa_async_tls_callback_t callback,
                         void* context) {
  mbedtls_psa_async_tls_generic_operation_t* operation = allocate_generic(callback, context);
  const mbedtls_psa_async_crypto_prime_curve_t* curve = curve_for_bits(bits);
  const size_t coordinate_length = (bits + 7u) / 8u;
  if (operation == NULL || curve == NULL || private_key == NULL || peer_public_key == NULL ||
      shared_secret == NULL) {
    return false;
  }
  mbedtls_psa_async_crypto_request_t request = {0};
  request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_KEY_AGREEMENT;
  request.key_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
  request.key_bits = bits;
  request.alg = PSA_ALG_ECDH;
  request.private_key = (mbedtls_psa_async_crypto_const_buffer_t){private_key, coordinate_length};
  request.peer_key =
      (mbedtls_psa_async_crypto_const_buffer_t){peer_public_key, coordinate_length * 2u + 1u};
  request.shared_secret = (mbedtls_psa_async_crypto_buffer_t){shared_secret, coordinate_length};
  operation->curve = *curve;
  request.prime_curve = &operation->curve;
  return start_generic(operation, &request, MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_DIRECT);
}

static bool prepare_ecdsa_verify(size_t bits, const uint8_t* public_key, const uint8_t* hash,
                                 const uint8_t* signature,
                                 mbedtls_psa_async_tls_callback_t callback, void* context) {
  mbedtls_psa_async_tls_generic_operation_t* operation = allocate_generic(callback, context);
  const mbedtls_psa_async_crypto_prime_curve_t* curve = curve_for_bits(bits);
  const size_t coordinate_length = (bits + 7u) / 8u;
  if (operation == NULL || curve == NULL || public_key == NULL || hash == NULL ||
      signature == NULL) {
    return false;
  }
  mbedtls_psa_async_crypto_request_t request = {0};
  request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_VERIFY_HASH;
  request.key_type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
  request.key_bits = bits;
  request.alg = PSA_ALG_ECDSA(bits == 256u   ? PSA_ALG_SHA_256
                              : bits == 384u ? PSA_ALG_SHA_384
                                             : PSA_ALG_SHA_512);
  request.public_key =
      (mbedtls_psa_async_crypto_const_buffer_t){public_key, coordinate_length * 2u + 1u};
  request.hash =
      (mbedtls_psa_async_crypto_const_buffer_t){hash, bits == 521u ? 64u : coordinate_length};
  request.signature =
      (mbedtls_psa_async_crypto_buffer_t){(uint8_t*)(signature), coordinate_length * 2u};
  operation->curve = *curve;
  request.prime_curve = &operation->curve;
  return start_generic(operation, &request, MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_DIRECT);
}

static bool prepare_ecdsa_sign(size_t bits, const uint8_t* private_key, const uint8_t* hash,
                               uint8_t* signature, mbedtls_psa_async_tls_callback_t callback,
                               void* context) {
  mbedtls_psa_async_tls_generic_operation_t* operation = allocate_generic(callback, context);
  const mbedtls_psa_async_crypto_prime_curve_t* curve = curve_for_bits(bits);
  const size_t coordinate_length = (bits + 7u) / 8u;
  if (operation == NULL || curve == NULL || private_key == NULL || hash == NULL ||
      signature == NULL) {
    return false;
  }
  operation->curve = *curve;
  operation->private_key = private_key;
  operation->hash = hash;
  operation->signature = signature;
  operation->coordinate_length = coordinate_length;
  operation->key_bits = bits;
  operation->hash_length = bits == 521u ? 64u : coordinate_length;
  mbedtls_psa_async_crypto_request_t request = {0};
  request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RANDOM;
  request.output = (mbedtls_psa_async_crypto_buffer_t){operation->nonce, coordinate_length};
  return start_generic(operation, &request, MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_SIGNATURE_RANDOM);
}

static psa_algorithm_t tls_aead_algorithm(int algorithm) {
  return algorithm >= 1 && algorithm <= 2   ? PSA_ALG_GCM
         : algorithm >= 3 && algorithm <= 6 ? PSA_ALG_CCM
                                            : (psa_algorithm_t)0u;
}

static bool prepare_aead(bool encrypting, int algorithm, const uint8_t* key, size_t key_length,
                         const uint8_t* nonce, size_t nonce_length, const uint8_t* aad,
                         size_t aad_length, const uint8_t* input, uint8_t* output, size_t length,
                         const uint8_t* input_tag, uint8_t* output_tag, size_t tag_length,
                         mbedtls_psa_async_tls_callback_t callback, void* context) {
  mbedtls_psa_async_tls_generic_operation_t* operation = allocate_generic(callback, context);
  const psa_algorithm_t psa_algorithm = tls_aead_algorithm(algorithm);
  if (operation == NULL || psa_algorithm == 0u || key == NULL ||
      (key_length != 16u && key_length != 32u) || nonce == NULL || input == NULL ||
      output == NULL || (encrypting ? output_tag == NULL : input_tag == NULL)) {
    return false;
  }
  mbedtls_psa_async_crypto_request_t request = {0};
  request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_AEAD;
  request.key_type = PSA_KEY_TYPE_AES;
  request.key_bits = key_length * 8u;
  request.alg = psa_algorithm;
  request.direction =
      encrypting ? MBEDTLS_PSA_ASYNC_CRYPTO_ENCRYPT : MBEDTLS_PSA_ASYNC_CRYPTO_DECRYPT;
  request.key = (mbedtls_psa_async_crypto_const_buffer_t){key, key_length};
  request.nonce = (mbedtls_psa_async_crypto_const_buffer_t){nonce, nonce_length};
  request.additional_data = (mbedtls_psa_async_crypto_const_buffer_t){aad, aad_length};
  request.input = (mbedtls_psa_async_crypto_const_buffer_t){input, length};
  request.output = (mbedtls_psa_async_crypto_buffer_t){output, length};
  request.input_tag =
      (mbedtls_psa_async_crypto_const_buffer_t){input_tag, encrypting ? 0u : tag_length};
  request.output_tag =
      (mbedtls_psa_async_crypto_buffer_t){output_tag, encrypting ? tag_length : 0u};
  return start_generic(operation, &request, MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_DIRECT);
}

static void service_generic(mbedtls_psa_async_tls_generic_operation_t* operation) {
  if (operation->stage == MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_IDLE) {
    return;
  }
  const psa_status_t status =
      mbedtls_psa_async_crypto_complete(provider, &operation->provider_operation);
  if (status == PSA_OPERATION_INCOMPLETE) {
    return;
  }
  if (status != PSA_SUCCESS) {
    finish_generic(operation, false);
    return;
  }
  if (operation->stage == MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_SIGNATURE_RANDOM) {
    memset(&operation->provider_operation, 0, sizeof(operation->provider_operation));
    mbedtls_psa_async_crypto_request_t request = {0};
    request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_SIGN_HASH;
    request.key_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    request.key_bits = operation->key_bits;
    request.alg = PSA_ALG_ECDSA(operation->hash_length == 32u   ? PSA_ALG_SHA_256
                                : operation->hash_length == 48u ? PSA_ALG_SHA_384
                                                                : PSA_ALG_SHA_512);
    request.private_key = (mbedtls_psa_async_crypto_const_buffer_t){operation->private_key,
                                                                    operation->coordinate_length};
    request.nonce_scalar =
        (mbedtls_psa_async_crypto_const_buffer_t){operation->nonce, operation->coordinate_length};
    request.hash =
        (mbedtls_psa_async_crypto_const_buffer_t){operation->hash, operation->hash_length};
    request.signature = (mbedtls_psa_async_crypto_buffer_t){operation->signature,
                                                            operation->coordinate_length * 2u};
    request.prime_curve = &operation->curve;
    mbedtls_psa_async_tls_callback_t callback = operation->callback;
    void* context = operation->callback_context;
    if (!start_generic(operation, &request, MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_DIRECT) &&
        callback != NULL) {
      callback(0, context);
    }
    return;
  }
  finish_generic(operation, true);
}

static mbedtls_md_type_t hash_algorithm(int hash_bits) {
  switch (hash_bits) {
  case 256:
    return MBEDTLS_MD_SHA256;
  case 384:
    return MBEDTLS_MD_SHA384;
  case 512:
    return MBEDTLS_MD_SHA512;
  default:
    return MBEDTLS_MD_NONE;
  }
}

static size_t hash_length(int hash_bits) {
  return hash_bits == 256 ? 32u : hash_bits == 384 ? 48u : hash_bits == 512 ? 64u : 0u;
}

static bool export_integer(const mbedtls_mpi* value, uint8_t* output, size_t output_size,
                           size_t* value_size, bool pad_to_output) {
  *value_size = mbedtls_mpi_size(value);
  if (*value_size == 0u || *value_size > output_size) {
    return false;
  }
  const size_t write_size = pad_to_output ? output_size : *value_size;
  return mbedtls_mpi_write_binary(value, output, write_size) == 0;
}

static bool prepare_rsa(bool signing, bool pss, int hash_bits, const uint8_t* key,
                        size_t key_length, const uint8_t* hash, size_t digest_length,
                        const uint8_t* signature, uint8_t* signature_output,
                        size_t signature_length, mbedtls_psa_async_tls_callback_t callback,
                        void* context) {
  if (provider == NULL || rsa_operation.stage != MBEDTLS_PSA_CRYPTO_ASYNC_TLS_RSA_IDLE || key == NULL ||
      key_length == 0u || hash == NULL || callback == NULL ||
      digest_length != hash_length(hash_bits) || signature_length == 0u ||
      signature_length > MBEDTLS_PSA_CRYPTO_ASYNC_TLS_MAX_RSA_BYTES || (!signing && signature == NULL) ||
      (signing && signature_output == NULL)) {
    return false;
  }

  mbedtls_rsa_init(&rsa_operation.rsa);
  rsa_operation.rsa_initialized = true;
  rsa_operation.signing = signing;
  rsa_operation.pss = pss;
  rsa_operation.hash_algorithm = hash_algorithm(hash_bits);
  rsa_operation.hash = hash;
  rsa_operation.hash_length = digest_length;
  rsa_operation.signature_output = signature_output;
  rsa_operation.callback = callback;
  rsa_operation.callback_context = context;
  rsa_operation.owner = active_call_owner;
  if (rsa_operation.hash_algorithm == MBEDTLS_MD_NONE ||
      (signing ? mbedtls_rsa_parse_key(&rsa_operation.rsa, key, key_length)
               : mbedtls_rsa_parse_pubkey(&rsa_operation.rsa, key, key_length)) != 0 ||
      mbedtls_rsa_set_padding(&rsa_operation.rsa, pss ? MBEDTLS_RSA_PKCS_V21 : MBEDTLS_RSA_PKCS_V15,
                              rsa_operation.hash_algorithm) != 0) {
    reset_rsa();
    return false;
  }

  rsa_operation.modulus_length = mbedtls_rsa_get_len(&rsa_operation.rsa);
  if (rsa_operation.modulus_length != signature_length ||
      rsa_operation.modulus_length > MBEDTLS_PSA_CRYPTO_ASYNC_TLS_MAX_RSA_BYTES ||
      (rsa_operation.modulus_length & 0x03u) != 0u) {
    reset_rsa();
    return false;
  }

  size_t modulus_size = 0u;
  size_t exponent_size = 0u;
  if (!export_integer(&rsa_operation.rsa.MBEDTLS_PRIVATE(N), rsa_operation.modulus,
                      rsa_operation.modulus_length, &modulus_size, true) ||
      !export_integer(
          signing ? &rsa_operation.rsa.MBEDTLS_PRIVATE(D) : &rsa_operation.rsa.MBEDTLS_PRIVATE(E),
          rsa_operation.exponent, rsa_operation.modulus_length, &exponent_size, signing)) {
    reset_rsa();
    return false;
  }

  if (!signing) {
    memcpy(rsa_operation.signature, signature, signature_length);
    memset(&rsa_operation.request, 0, sizeof(rsa_operation.request));
    rsa_operation.request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RAW_RSA;
    rsa_operation.request.modulus = (mbedtls_psa_async_crypto_const_buffer_t){
        rsa_operation.modulus, rsa_operation.modulus_length};
    rsa_operation.request.exponent =
        (mbedtls_psa_async_crypto_const_buffer_t){rsa_operation.exponent, exponent_size};
    rsa_operation.request.input =
        (mbedtls_psa_async_crypto_const_buffer_t){rsa_operation.signature, signature_length};
    rsa_operation.request.output =
        (mbedtls_psa_async_crypto_buffer_t){rsa_operation.encoded, rsa_operation.modulus_length};
    rsa_operation.request.rsa_mode = MBEDTLS_PSA_ASYNC_CRYPTO_RSA_MODE_REGULAR;
    rsa_operation.request.rsa_window = MBEDTLS_PSA_ASYNC_CRYPTO_RSA_WINDOW_1;
    if (mbedtls_psa_async_crypto_start(provider, &rsa_operation.provider_operation,
                                       &rsa_operation.request) != PSA_SUCCESS) {
      reset_rsa();
      return false;
    }
    rsa_operation.stage = MBEDTLS_PSA_CRYPTO_ASYNC_TLS_RSA_EXPONENTIATION;
    return true;
  }

  if (pss) {
    memset(&rsa_operation.request, 0, sizeof(rsa_operation.request));
    rsa_operation.request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RANDOM;
    rsa_operation.request.output =
        (mbedtls_psa_async_crypto_buffer_t){rsa_operation.salt, digest_length};
    if (mbedtls_psa_async_crypto_start(provider, &rsa_operation.provider_operation,
                                       &rsa_operation.request) != PSA_SUCCESS) {
      reset_rsa();
      return false;
    }
    rsa_operation.stage = MBEDTLS_PSA_CRYPTO_ASYNC_TLS_RSA_RANDOM;
    return true;
  }

  if (mbedtls_rsa_rsassa_pkcs1_v15_encode(&rsa_operation.rsa, rsa_operation.hash_algorithm,
                                          (unsigned int)(digest_length), hash,
                                          rsa_operation.encoded) != 0) {
    reset_rsa();
    return false;
  }
  memset(&rsa_operation.request, 0, sizeof(rsa_operation.request));
  rsa_operation.request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RAW_RSA;
  rsa_operation.request.modulus = (mbedtls_psa_async_crypto_const_buffer_t){
      rsa_operation.modulus, rsa_operation.modulus_length};
  rsa_operation.request.exponent = (mbedtls_psa_async_crypto_const_buffer_t){
      rsa_operation.exponent, rsa_operation.modulus_length};
  rsa_operation.request.input = (mbedtls_psa_async_crypto_const_buffer_t){
      rsa_operation.encoded, rsa_operation.modulus_length};
  rsa_operation.request.output =
      (mbedtls_psa_async_crypto_buffer_t){signature_output, rsa_operation.modulus_length};
  rsa_operation.request.rsa_mode = MBEDTLS_PSA_ASYNC_CRYPTO_RSA_MODE_REGULAR;
  rsa_operation.request.rsa_window = MBEDTLS_PSA_ASYNC_CRYPTO_RSA_WINDOW_1;
  if (mbedtls_psa_async_crypto_start(provider, &rsa_operation.provider_operation,
                                     &rsa_operation.request) != PSA_SUCCESS) {
    reset_rsa();
    return false;
  }
  rsa_operation.stage = MBEDTLS_PSA_CRYPTO_ASYNC_TLS_RSA_EXPONENTIATION;
  return true;
}

static bool verify_encoded(void) {
  if (rsa_operation.pss) {
    return mbedtls_rsa_rsassa_pss_verify_ext_from_encoded(
               &rsa_operation.rsa, rsa_operation.hash_algorithm,
               (unsigned int)(rsa_operation.hash_length), rsa_operation.hash,
               rsa_operation.hash_algorithm, MBEDTLS_RSA_SALT_LEN_ANY, rsa_operation.encoded) == 0;
  }

  uint8_t expected[MBEDTLS_PSA_CRYPTO_ASYNC_TLS_MAX_RSA_BYTES] = {0};
  const bool valid =
      mbedtls_rsa_rsassa_pkcs1_v15_encode(&rsa_operation.rsa, rsa_operation.hash_algorithm,
                                          (unsigned int)(rsa_operation.hash_length),
                                          rsa_operation.hash, expected) == 0 &&
      memcmp(expected, rsa_operation.encoded, rsa_operation.modulus_length) == 0;
  zeroize(expected, sizeof(expected));
  return valid;
}

int mbedtls_psa_async_tls_bind(mbedtls_psa_async_crypto_provider_t* selected_provider) {
  if (selected_provider == NULL || (provider != NULL && provider != selected_provider)) {
    return 0;
  }
  if (provider == NULL &&
      mbedtls_psa_async_crypto_bind_provider(selected_provider) != PSA_SUCCESS) {
    return 0;
  }
  provider = selected_provider;
  ++provider_bindings;
  return 1;
}

int mbedtls_psa_async_tls_unbind(mbedtls_psa_async_crypto_provider_t* selected_provider) {
  if (provider != selected_provider || provider_bindings == 0u) {
    return 0;
  }
  if (provider_bindings > 1u) {
    --provider_bindings;
    return 1;
  }
  if (mbedtls_psa_async_tls_busy()) {
    return 0;
  }
  if (mbedtls_psa_async_crypto_unbind_provider(selected_provider) != PSA_SUCCESS) {
    return 0;
  }
  provider_bindings = 0u;
  provider = NULL;
  return 1;
}

int mbedtls_psa_async_tls_begin_call(void* owner) {
  if (owner == NULL || active_call_owner != NULL) {
    return 0;
  }
  active_call_owner = owner;
  return 1;
}

void mbedtls_psa_async_tls_end_call(void* owner) {
  if (active_call_owner == owner) {
    active_call_owner = NULL;
  }
}

void mbedtls_psa_async_tls_service(void) {
  if (provider == NULL) {
    return;
  }
  for (size_t index = 0u; index < MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_OPERATION_CAPACITY; ++index) {
    service_generic(&generic_operations[index]);
  }
  if (rsa_operation.stage == MBEDTLS_PSA_CRYPTO_ASYNC_TLS_RSA_IDLE) {
    return;
  }
  const psa_status_t status =
      mbedtls_psa_async_crypto_complete(provider, &rsa_operation.provider_operation);
  if (status == PSA_OPERATION_INCOMPLETE) {
    return;
  }
  if (status != PSA_SUCCESS) {
    finish_rsa(false);
    return;
  }

  if (rsa_operation.stage == MBEDTLS_PSA_CRYPTO_ASYNC_TLS_RSA_RANDOM) {
    if (mbedtls_rsa_rsassa_pss_encode_ext_with_salt(
            &rsa_operation.rsa, rsa_operation.hash_algorithm,
            (unsigned int)(rsa_operation.hash_length), rsa_operation.hash, MBEDTLS_RSA_SALT_LEN_ANY,
            rsa_operation.salt, rsa_operation.hash_length, rsa_operation.encoded) != 0) {
      finish_rsa(false);
      return;
    }
    memset(&rsa_operation.provider_operation, 0, sizeof(rsa_operation.provider_operation));
    memset(&rsa_operation.request, 0, sizeof(rsa_operation.request));
    rsa_operation.request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RAW_RSA;
    rsa_operation.request.modulus = (mbedtls_psa_async_crypto_const_buffer_t){
        rsa_operation.modulus, rsa_operation.modulus_length};
    rsa_operation.request.exponent = (mbedtls_psa_async_crypto_const_buffer_t){
        rsa_operation.exponent, rsa_operation.modulus_length};
    rsa_operation.request.input = (mbedtls_psa_async_crypto_const_buffer_t){
        rsa_operation.encoded, rsa_operation.modulus_length};
    rsa_operation.request.output = (mbedtls_psa_async_crypto_buffer_t){
        rsa_operation.signature_output, rsa_operation.modulus_length};
    rsa_operation.request.rsa_mode = MBEDTLS_PSA_ASYNC_CRYPTO_RSA_MODE_REGULAR;
    rsa_operation.request.rsa_window = MBEDTLS_PSA_ASYNC_CRYPTO_RSA_WINDOW_1;
    if (mbedtls_psa_async_crypto_start(provider, &rsa_operation.provider_operation,
                                       &rsa_operation.request) != PSA_SUCCESS) {
      finish_rsa(false);
      return;
    }
    rsa_operation.stage = MBEDTLS_PSA_CRYPTO_ASYNC_TLS_RSA_EXPONENTIATION;
    return;
  }

  finish_rsa(rsa_operation.signing || verify_encoded());
}

void mbedtls_psa_async_tls_abort(void) {
  for (size_t index = 0u; index < MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_OPERATION_CAPACITY; ++index) {
    if (provider != NULL && generic_operations[index].stage != MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_IDLE) {
      (void)mbedtls_psa_async_crypto_abort(provider, &generic_operations[index].provider_operation);
    }
    zeroize(&generic_operations[index], sizeof(generic_operations[index]));
  }
  if (provider != NULL && rsa_operation.stage != MBEDTLS_PSA_CRYPTO_ASYNC_TLS_RSA_IDLE) {
    (void)mbedtls_psa_async_crypto_abort(provider, &rsa_operation.provider_operation);
  }
  reset_rsa();
}

void mbedtls_psa_async_tls_abort_owner(void* owner) {
  if (owner == NULL) {
    return;
  }
  for (size_t index = 0u; index < MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_OPERATION_CAPACITY; ++index) {
    mbedtls_psa_async_tls_generic_operation_t* operation = &generic_operations[index];
    if (operation->stage == MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_IDLE || operation->owner != owner) {
      continue;
    }
    if (provider != NULL) {
      (void)mbedtls_psa_async_crypto_abort(provider, &operation->provider_operation);
    }
    zeroize(operation, sizeof(*operation));
  }
  if (rsa_operation.stage != MBEDTLS_PSA_CRYPTO_ASYNC_TLS_RSA_IDLE && rsa_operation.owner == owner) {
    if (provider != NULL) {
      (void)mbedtls_psa_async_crypto_abort(provider, &rsa_operation.provider_operation);
    }
    reset_rsa();
  }
}

int mbedtls_psa_async_tls_busy(void) {
  for (size_t index = 0u; index < MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_OPERATION_CAPACITY; ++index) {
    if (generic_operations[index].stage != MBEDTLS_PSA_CRYPTO_ASYNC_TLS_GENERIC_IDLE) {
      return 1;
    }
  }
  return rsa_operation.stage != MBEDTLS_PSA_CRYPTO_ASYNC_TLS_RSA_IDLE ? 1 : 0;
}

void mbedtls_psa_async_tls_set_trusted_time(uint64_t unix_time) {
  current_trusted_time = unix_time;
}

void mbedtls_psa_async_tls_clear_trusted_time(void) {
  current_trusted_time = 0u;
}

uint64_t mbedtls_psa_async_tls_get_trusted_time(void) {
  return current_trusted_time;
}

time_t mbedtls_platform_time(time_t* current_time) {
  const time_t now = (time_t)(mbedtls_psa_async_tls_get_trusted_time());
  if (current_time != NULL) {
    *current_time = now;
  }
  return now;
}

int mbedtls_psa_async_tls_random_start(uint8_t* output, size_t length,
                                        mbedtls_psa_async_tls_callback_t callback, void* context) {
  return prepare_random(output, length, callback, context) ? 1 : 0;
}

int mbedtls_psa_async_tls_ecdh_p256_public_key_start(const uint8_t private_key[32],
                                                      uint8_t public_key[65],
                                                      mbedtls_psa_async_tls_callback_t callback,
                                                      void* context) {
  return prepare_ecdh_public(256u, private_key, public_key, callback, context) ? 1 : 0;
}

int mbedtls_psa_async_tls_ecdh_p384_public_key_start(const uint8_t private_key[48],
                                                      uint8_t public_key[97],
                                                      mbedtls_psa_async_tls_callback_t callback,
                                                      void* context) {
  return prepare_ecdh_public(384u, private_key, public_key, callback, context) ? 1 : 0;
}

int mbedtls_psa_async_tls_ecdh_p521_public_key_start(const uint8_t private_key[66],
                                                      uint8_t public_key[133],
                                                      mbedtls_psa_async_tls_callback_t callback,
                                                      void* context) {
  return prepare_ecdh_public(521u, private_key, public_key, callback, context) ? 1 : 0;
}

int mbedtls_psa_async_tls_ecdh_p256_start(const uint8_t private_key[32],
                                           const uint8_t peer_public_key[65],
                                           uint8_t shared_secret[32],
                                           mbedtls_psa_async_tls_callback_t callback,
                                           void* context) {
  return prepare_ecdh(256u, private_key, peer_public_key, shared_secret, callback, context) ? 1 : 0;
}

int mbedtls_psa_async_tls_ecdh_p384_start(const uint8_t private_key[48],
                                           const uint8_t peer_public_key[97],
                                           uint8_t shared_secret[48],
                                           mbedtls_psa_async_tls_callback_t callback,
                                           void* context) {
  return prepare_ecdh(384u, private_key, peer_public_key, shared_secret, callback, context) ? 1 : 0;
}

int mbedtls_psa_async_tls_ecdh_p521_start(const uint8_t private_key[66],
                                           const uint8_t peer_public_key[133],
                                           uint8_t shared_secret[66],
                                           mbedtls_psa_async_tls_callback_t callback,
                                           void* context) {
  return prepare_ecdh(521u, private_key, peer_public_key, shared_secret, callback, context) ? 1 : 0;
}

#define MBEDTLS_PSA_CRYPTO_ASYNC_TLS_ECDSA_HOOKS(bits, key_bytes, hash_bytes, signature_bytes)            \
  int mbedtls_psa_async_tls_ecdsa_p##bits##_sign_start(                                            \
      const uint8_t private_key[key_bytes], const uint8_t hash[hash_bytes],                        \
      uint8_t signature[signature_bytes], mbedtls_psa_async_tls_callback_t callback,               \
      void* context) {                                                                             \
    return prepare_ecdsa_sign(bits##u, private_key, hash, signature, callback, context) ? 1 : 0;   \
  }                                                                                                \
  int mbedtls_psa_async_tls_ecdsa_p##bits##_verify_start(                                          \
      const uint8_t public_key[(key_bytes * 2u) + 1u], const uint8_t hash[hash_bytes],             \
      const uint8_t signature[signature_bytes], mbedtls_psa_async_tls_callback_t callback,         \
      void* context) {                                                                             \
    return prepare_ecdsa_verify(bits##u, public_key, hash, signature, callback, context) ? 1 : 0;  \
  }

MBEDTLS_PSA_CRYPTO_ASYNC_TLS_ECDSA_HOOKS(256, 32, 32, 64)
MBEDTLS_PSA_CRYPTO_ASYNC_TLS_ECDSA_HOOKS(384, 48, 48, 96)
MBEDTLS_PSA_CRYPTO_ASYNC_TLS_ECDSA_HOOKS(521, 66, 64, 132)

#undef MBEDTLS_PSA_CRYPTO_ASYNC_TLS_ECDSA_HOOKS

int mbedtls_psa_async_tls_aead_encrypt_start(int algorithm, const uint8_t* key, size_t key_length,
                                              const uint8_t* nonce, size_t nonce_length,
                                              const uint8_t* aad, size_t aad_length,
                                              const uint8_t* plaintext, uint8_t* ciphertext,
                                              size_t length, uint8_t* tag, size_t tag_length,
                                              mbedtls_psa_async_tls_callback_t callback,
                                              void* context) {
  return prepare_aead(true, algorithm, key, key_length, nonce, nonce_length, aad, aad_length,
                      plaintext, ciphertext, length, NULL, tag, tag_length, callback, context)
             ? 1
             : 0;
}

int mbedtls_psa_async_tls_aead_decrypt_start(int algorithm, const uint8_t* key, size_t key_length,
                                              const uint8_t* nonce, size_t nonce_length,
                                              const uint8_t* aad, size_t aad_length,
                                              const uint8_t* ciphertext, uint8_t* plaintext,
                                              size_t length, const uint8_t* tag, size_t tag_length,
                                              mbedtls_psa_async_tls_callback_t callback,
                                              void* context) {
  return prepare_aead(false, algorithm, key, key_length, nonce, nonce_length, aad, aad_length,
                      ciphertext, plaintext, length, tag, NULL, tag_length, callback, context)
             ? 1
             : 0;
}

int mbedtls_psa_async_tls_aes_gcm128_encrypt_start(const uint8_t key[16], const uint8_t nonce[12],
                                                    const uint8_t* aad, size_t aad_length,
                                                    const uint8_t* plaintext, uint8_t* ciphertext,
                                                    size_t length, uint8_t tag[16],
                                                    mbedtls_psa_async_tls_callback_t callback,
                                                    void* context) {
  return mbedtls_psa_async_tls_aead_encrypt_start(1, key, 16u, nonce, 12u, aad, aad_length,
                                                   plaintext, ciphertext, length, tag, 16u,
                                                   callback, context);
}

int mbedtls_psa_async_tls_aes_gcm128_decrypt_start(const uint8_t key[16], const uint8_t nonce[12],
                                                    const uint8_t* aad, size_t aad_length,
                                                    const uint8_t* ciphertext, uint8_t* plaintext,
                                                    size_t length, const uint8_t tag[16],
                                                    mbedtls_psa_async_tls_callback_t callback,
                                                    void* context) {
  return mbedtls_psa_async_tls_aead_decrypt_start(1, key, 16u, nonce, 12u, aad, aad_length,
                                                   ciphertext, plaintext, length, tag, 16u,
                                                   callback, context);
}

int mbedtls_psa_async_tls_rsa_pss_verify_start(int hash_bits, const uint8_t* public_key,
                                                size_t public_key_length, const uint8_t* hash,
                                                size_t hash_length, const uint8_t* signature,
                                                size_t signature_length,
                                                mbedtls_psa_async_tls_callback_t callback,
                                                void* context) {
  return prepare_rsa(false, true, hash_bits, public_key, public_key_length, hash, hash_length,
                     signature, NULL, signature_length, callback, context)
             ? 1
             : 0;
}

int mbedtls_psa_async_tls_rsa_pkcs1_verify_start(int hash_bits, const uint8_t* public_key,
                                                  size_t public_key_length, const uint8_t* hash,
                                                  size_t hash_length, const uint8_t* signature,
                                                  size_t signature_length,
                                                  mbedtls_psa_async_tls_callback_t callback,
                                                  void* context) {
  return prepare_rsa(false, false, hash_bits, public_key, public_key_length, hash, hash_length,
                     signature, NULL, signature_length, callback, context)
             ? 1
             : 0;
}

int mbedtls_psa_async_tls_rsa_pss_sign_start(int hash_bits, const uint8_t* private_key,
                                              size_t private_key_length, const uint8_t* hash,
                                              size_t hash_length, uint8_t* signature,
                                              size_t signature_length,
                                              mbedtls_psa_async_tls_callback_t callback,
                                              void* context) {
  return prepare_rsa(true, true, hash_bits, private_key, private_key_length, hash, hash_length,
                     NULL, signature, signature_length, callback, context)
             ? 1
             : 0;
}

int mbedtls_psa_async_tls_rsa_pkcs1_sign_start(int hash_bits, const uint8_t* private_key,
                                                size_t private_key_length, const uint8_t* hash,
                                                size_t hash_length, uint8_t* signature,
                                                size_t signature_length,
                                                mbedtls_psa_async_tls_callback_t callback,
                                                void* context) {
  return prepare_rsa(true, false, hash_bits, private_key, private_key_length, hash, hash_length,
                     NULL, signature, signature_length, callback, context)
             ? 1
             : 0;
}
