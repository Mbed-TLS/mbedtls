/**
 * This file is intended to be used to build PSA external test driver
 * libraries (libtestdriver1).
 *
 * It is intended to be appended by the test build system to the
 * crypto_config.h file of the Mbed TLS library the test library will be
 * linked to (see `tests/Makefile` libtestdriver1 target). This is done in
 * order to insert it at the right time: after the main configuration
 * (PSA_WANT) but before the logic that determines what built-ins to enable
 * based on PSA_WANT and MBEDTLS_PSA_ACCEL macros.
 *
 * It reverses the PSA_ACCEL_* macros defining the cryptographic operations
 * that will be accelerated in the main library:
 * - When something is accelerated in the main library, we need it supported
 *   in libtestdriver1, so we disable the accel macro in order to the built-in
 *   to be enabled.
 * - When something is NOT accelerated in the main library, we don't need it
 *   in libtestdriver1, so we enable its accel macro in order to the built-in
 *   to be disabled, to keep libtestdriver1 minimal. (We can't adjust the
 *   PSA_WANT macros as they need to be the same between libtestdriver1 and
 *   the main library, since they determine the ABI between the two.)
 */

#include "psa/crypto_legacy.h"

#if defined(PSA_WANT_ALG_CBC_NO_PADDING)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CBC_NO_PADDING)
#undef MBEDTLS_PSA_ACCEL_ALG_CBC_NO_PADDING
#else
#define MBEDTLS_PSA_ACCEL_ALG_CBC_NO_PADDING 1
#endif
#endif

#if defined(PSA_WANT_ALG_CBC_PKCS7)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CBC_PKCS7)
#undef MBEDTLS_PSA_ACCEL_ALG_CBC_PKCS7
#else
#define MBEDTLS_PSA_ACCEL_ALG_CBC_PKCS7 1
#endif
#endif

#if defined(PSA_WANT_ALG_CFB)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CFB)
#undef MBEDTLS_PSA_ACCEL_ALG_CFB
#else
#define MBEDTLS_PSA_ACCEL_ALG_CFB 1
#endif
#endif

#if defined(PSA_WANT_ALG_CMAC)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CMAC)
#undef MBEDTLS_PSA_ACCEL_ALG_CMAC
#else
#define MBEDTLS_PSA_ACCEL_ALG_CMAC 1
#endif
#endif

#if defined(PSA_WANT_ALG_CTR)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CTR)
#undef MBEDTLS_PSA_ACCEL_ALG_CTR
#else
#define MBEDTLS_PSA_ACCEL_ALG_CTR 1
#endif
#endif

#if defined(PSA_WANT_ALG_STREAM_CIPHER)
#if defined(MBEDTLS_PSA_ACCEL_ALG_STREAM_CIPHER)
#undef MBEDTLS_PSA_ACCEL_ALG_STREAM_CIPHER
#else
#define MBEDTLS_PSA_ACCEL_ALG_STREAM_CIPHER 1
#endif
#endif

#if defined(PSA_WANT_ALG_ECB_NO_PADDING)
#if defined(MBEDTLS_PSA_ACCEL_ALG_ECB_NO_PADDING)
#undef MBEDTLS_PSA_ACCEL_ALG_ECB_NO_PADDING
#else
#define MBEDTLS_PSA_ACCEL_ALG_ECB_NO_PADDING 1
#endif
#endif

#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256)
#if defined(MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_256)
#undef MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_256
#else
#define MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_256 1
#endif
#endif

#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384)
#if defined(MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_384)
#undef MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_384
#else
#define MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_384 1
#endif
#endif

#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512)
#if defined(MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_512)
#undef MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_512
#else
#define MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_512 1
#endif
#endif

#if defined(PSA_WANT_ECC_MONTGOMERY_255)
#if defined(MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_255)
#undef MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_255
#else
#define MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_255 1
#endif
#endif

#if defined(PSA_WANT_ECC_MONTGOMERY_448)
#if defined(MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_448)
#undef MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_448
#else
#define MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_448 1
#endif
#endif

#if defined(PSA_WANT_ECC_SECP_K1_192)
#if defined(MBEDTLS_PSA_ACCEL_ECC_SECP_K1_192)
#undef MBEDTLS_PSA_ACCEL_ECC_SECP_K1_192
#else
#define MBEDTLS_PSA_ACCEL_ECC_SECP_K1_192 1
#endif
#endif

#if defined(PSA_WANT_ECC_SECP_K1_224)
#if defined(MBEDTLS_PSA_ACCEL_ECC_SECP_K1_224)
#undef MBEDTLS_PSA_ACCEL_ECC_SECP_K1_224
#else
#define MBEDTLS_PSA_ACCEL_ECC_SECP_K1_224 1
#endif
#endif

#if defined(PSA_WANT_ECC_SECP_K1_256)
#if defined(MBEDTLS_PSA_ACCEL_ECC_SECP_K1_256)
#undef MBEDTLS_PSA_ACCEL_ECC_SECP_K1_256
#else
#define MBEDTLS_PSA_ACCEL_ECC_SECP_K1_256 1
#endif
#endif

#if defined(PSA_WANT_ECC_SECP_R1_192)
#if defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_192)
#undef MBEDTLS_PSA_ACCEL_ECC_SECP_R1_192
#else
#define MBEDTLS_PSA_ACCEL_ECC_SECP_R1_192 1
#endif
#endif

#if defined(PSA_WANT_ECC_SECP_R1_224)
#if defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_224)
#undef MBEDTLS_PSA_ACCEL_ECC_SECP_R1_224
#else
#define MBEDTLS_PSA_ACCEL_ECC_SECP_R1_224 1
#endif
#endif

#if defined(PSA_WANT_ECC_SECP_R1_256)
#if defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_256)
#undef MBEDTLS_PSA_ACCEL_ECC_SECP_R1_256
#else
#define MBEDTLS_PSA_ACCEL_ECC_SECP_R1_256 1
#endif
#endif

#if defined(PSA_WANT_ECC_SECP_R1_384)
#if defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_384)
#undef MBEDTLS_PSA_ACCEL_ECC_SECP_R1_384
#else
#define MBEDTLS_PSA_ACCEL_ECC_SECP_R1_384 1
#endif
#endif

#if defined(PSA_WANT_ECC_SECP_R1_521)
#if defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_521)
#undef MBEDTLS_PSA_ACCEL_ECC_SECP_R1_521
#else
#define MBEDTLS_PSA_ACCEL_ECC_SECP_R1_521 1
#endif
#endif

#if defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
#if defined(MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA)
#undef MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA
#else
#define MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA 1
#endif
#endif

#if defined(PSA_WANT_ALG_ECDSA)
#if defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA)
#undef MBEDTLS_PSA_ACCEL_ALG_ECDSA
#else
#define MBEDTLS_PSA_ACCEL_ALG_ECDSA 1
#endif
#endif

#if defined(PSA_WANT_ALG_ECDH)
#if defined(MBEDTLS_PSA_ACCEL_ALG_ECDH)
#undef MBEDTLS_PSA_ACCEL_ALG_ECDH
#else
#define MBEDTLS_PSA_ACCEL_ALG_ECDH 1
#endif
#endif

#if defined(PSA_WANT_DH_RFC7919_2048)
#if defined(MBEDTLS_PSA_ACCEL_DH_RFC7919_2048)
#undef MBEDTLS_PSA_ACCEL_DH_RFC7919_2048
#else
#define MBEDTLS_PSA_ACCEL_DH_RFC7919_2048
#endif
#endif

#if defined(PSA_WANT_DH_RFC7919_3072)
#if defined(MBEDTLS_PSA_ACCEL_DH_RFC7919_3072)
#undef MBEDTLS_PSA_ACCEL_DH_RFC7919_3072
#else
#define MBEDTLS_PSA_ACCEL_DH_RFC7919_3072
#endif
#endif

#if defined(PSA_WANT_DH_RFC7919_4096)
#if defined(MBEDTLS_PSA_ACCEL_DH_RFC7919_4096)
#undef MBEDTLS_PSA_ACCEL_DH_RFC7919_4096
#else
#define MBEDTLS_PSA_ACCEL_DH_RFC7919_4096
#endif
#endif

#if defined(PSA_WANT_DH_RFC7919_6144)
#if defined(MBEDTLS_PSA_ACCEL_DH_RFC7919_6144)
#undef MBEDTLS_PSA_ACCEL_DH_RFC7919_6144
#else
#define MBEDTLS_PSA_ACCEL_DH_RFC7919_6144
#endif
#endif

#if defined(PSA_WANT_DH_RFC7919_8192)
#if defined(MBEDTLS_PSA_ACCEL_DH_RFC7919_8192)
#undef MBEDTLS_PSA_ACCEL_DH_RFC7919_8192
#else
#define MBEDTLS_PSA_ACCEL_DH_RFC7919_8192
#endif
#endif

#if defined(PSA_WANT_ALG_FFDH)
#if defined(MBEDTLS_PSA_ACCEL_ALG_FFDH)
#undef MBEDTLS_PSA_ACCEL_ALG_FFDH
#else
#define MBEDTLS_PSA_ACCEL_ALG_FFDH 1
#endif
#endif

#if defined(PSA_WANT_ALG_MD5)
#if defined(MBEDTLS_PSA_ACCEL_ALG_MD5)
#undef MBEDTLS_PSA_ACCEL_ALG_MD5
#else
#define MBEDTLS_PSA_ACCEL_ALG_MD5 1
#endif
#endif

#if defined(PSA_WANT_ALG_OFB)
#if defined(MBEDTLS_PSA_ACCEL_ALG_OFB)
#undef MBEDTLS_PSA_ACCEL_ALG_OFB
#else
#define MBEDTLS_PSA_ACCEL_ALG_OFB 1
#endif
#endif

#if defined(PSA_WANT_ALG_RIPEMD160)
#if defined(MBEDTLS_PSA_ACCEL_ALG_RIPEMD160)
#undef MBEDTLS_PSA_ACCEL_ALG_RIPEMD160
#else
#define MBEDTLS_PSA_ACCEL_ALG_RIPEMD160 1
#endif
#endif

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
#if defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN)
#undef MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN
#else
#define MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN 1
#endif
#endif

#if defined(PSA_WANT_ALG_RSA_PSS)
#if defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PSS)
#undef MBEDTLS_PSA_ACCEL_ALG_RSA_PSS
#else
#define MBEDTLS_PSA_ACCEL_ALG_RSA_PSS 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA_1)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_1)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA_1
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA_1 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA_224)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_224)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA_224
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA_224 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA_256)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_256)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA_256
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA_256 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA_384)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_384)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA_384
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA_384 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA_512)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_512)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA_512
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA_512 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA3_224)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_224)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA3_224
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA3_224 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA3_256)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_256)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA3_256
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA3_256 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA3_384)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_384)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA3_384
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA3_384 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA3_512)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_512)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA3_512
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA3_512 1
#endif
#endif

#if defined(PSA_WANT_ALG_XTS)
#if defined(MBEDTLS_PSA_ACCEL_ALG_XTS)
#undef MBEDTLS_PSA_ACCEL_ALG_XTS
#else
#define MBEDTLS_PSA_ACCEL_ALG_XTS 1
#endif
#endif

#if defined(PSA_WANT_ALG_CHACHA20_POLY1305)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305)
#undef MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305
#else
#define MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305 1
#endif
#endif

#if defined(PSA_WANT_ALG_JPAKE)
#if defined(MBEDTLS_PSA_ACCEL_ALG_JPAKE)
#undef MBEDTLS_PSA_ACCEL_ALG_JPAKE
#else
#define MBEDTLS_PSA_ACCEL_ALG_JPAKE 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_AES)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_AES)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_AES
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_AES 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_ARIA)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ARIA)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_ARIA
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ARIA 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_CAMELLIA)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_CAMELLIA)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_CAMELLIA
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_CAMELLIA 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_BASIC)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_BASIC
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_BASIC 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_IMPORT)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_IMPORT
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_IMPORT 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_EXPORT)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_EXPORT
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_EXPORT 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_GENERATE
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_DERIVE)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_DERIVE
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_DERIVE 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_BASIC)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR_BASIC)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR_BASIC
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR_BASIC 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_IMPORT)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR_IMPORT)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR_IMPORT
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR_IMPORT 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_EXPORT)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR_EXPORT)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR_EXPORT
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR_EXPORT 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_GENERATE)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR_GENERATE)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR_GENERATE
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_KEY_PAIR_GENERATE 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_BASIC)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_BASIC
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_BASIC 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_IMPORT)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_IMPORT
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_IMPORT 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_EXPORT)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_EXPORT
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_EXPORT 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_GENERATE)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_GENERATE
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_GENERATE 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_DH_PUBLIC_KEY)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_PUBLIC_KEY)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_PUBLIC_KEY
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_DH_PUBLIC_KEY 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_CHACHA20)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_CHACHA20)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_CHACHA20
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_CHACHA20 1
#endif
#endif


#if defined(PSA_WANT_ALG_TLS12_PRF)
#if defined(MBEDTLS_PSA_ACCEL_ALG_TLS12_PRF)
#undef MBEDTLS_PSA_ACCEL_ALG_TLS12_PRF
#else
#define MBEDTLS_PSA_ACCEL_ALG_TLS12_PRF 1
#endif
#endif

#if defined(PSA_WANT_ALG_TLS12_PSK_TO_MS)
#if defined(MBEDTLS_PSA_ACCEL_ALG_TLS12_PSK_TO_MS)
#undef MBEDTLS_PSA_ACCEL_ALG_TLS12_PSK_TO_MS
#else
#define MBEDTLS_PSA_ACCEL_ALG_TLS12_PSK_TO_MS 1
#endif
#endif

#if defined(PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS)
#if defined(MBEDTLS_PSA_ACCEL_ALG_TLS12_ECJPAKE_TO_PMS)
#undef MBEDTLS_PSA_ACCEL_ALG_TLS12_ECJPAKE_TO_PMS
#else
#define MBEDTLS_PSA_ACCEL_ALG_TLS12_ECJPAKE_TO_PMS 1
#endif
#endif

#if defined(PSA_WANT_ALG_GCM)
#if defined(MBEDTLS_PSA_ACCEL_ALG_GCM)
#undef MBEDTLS_PSA_ACCEL_ALG_GCM
#else
#define MBEDTLS_PSA_ACCEL_ALG_GCM 1
#endif
#endif

#if defined(PSA_WANT_ALG_CCM)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CCM)
#undef MBEDTLS_PSA_ACCEL_ALG_CCM
#else
#define MBEDTLS_PSA_ACCEL_ALG_CCM 1
#endif
#endif

#if defined(PSA_WANT_ALG_CCM_STAR_NO_TAG)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CCM_STAR_NO_TAG)
#undef MBEDTLS_PSA_ACCEL_ALG_CCM_STAR_NO_TAG
#else
#define MBEDTLS_PSA_ACCEL_ALG_CCM_STAR_NO_TAG 1
#endif
#endif

#if defined(PSA_WANT_ALG_CBC_MAC)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CBC_MAC)
#undef MBEDTLS_PSA_ACCEL_ALG_CBC_MAC
#else
#define MBEDTLS_PSA_ACCEL_ALG_CBC_MAC 1
#endif
#endif

#if defined(PSA_WANT_ALG_HMAC)
#if defined(MBEDTLS_PSA_ACCEL_ALG_HMAC)
#undef MBEDTLS_PSA_ACCEL_ALG_HMAC
#else
#define MBEDTLS_PSA_ACCEL_ALG_HMAC 1
#endif
#endif

#if defined(PSA_WANT_ALG_HKDF)
#if defined(MBEDTLS_PSA_ACCEL_ALG_HKDF)
#undef MBEDTLS_PSA_ACCEL_ALG_HKDF
#else
#define MBEDTLS_PSA_ACCEL_ALG_HKDF 1
#endif
#endif

#if defined(PSA_WANT_ALG_HKDF_EXTRACT)
#if defined(MBEDTLS_PSA_ACCEL_ALG_HKDF_EXTRACT)
#undef MBEDTLS_PSA_ACCEL_ALG_HKDF_EXTRACT
#else
#define MBEDTLS_PSA_ACCEL_ALG_HKDF_EXTRACT 1
#endif
#endif

#if defined(PSA_WANT_ALG_HKDF_EXPAND)
#if defined(MBEDTLS_PSA_ACCEL_ALG_HKDF_EXPAND)
#undef MBEDTLS_PSA_ACCEL_ALG_HKDF_EXPAND
#else
#define MBEDTLS_PSA_ACCEL_ALG_HKDF_EXPAND 1
#endif
#endif

#if defined(PSA_WANT_ALG_RSA_OAEP)
#if defined(MBEDTLS_PSA_ACCEL_ALG_RSA_OAEP)
#undef MBEDTLS_PSA_ACCEL_ALG_RSA_OAEP
#else
#define MBEDTLS_PSA_ACCEL_ALG_RSA_OAEP 1
#endif
#endif

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_CRYPT)
#if defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_CRYPT)
#undef MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_CRYPT
#else
#define MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_CRYPT 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_DERIVE)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_DERIVE)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_DERIVE
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_DERIVE 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_HMAC)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_HMAC)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_HMAC
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_HMAC 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_DES)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_DES)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_DES
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_DES 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_RAW_DATA)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RAW_DATA)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_RAW_DATA
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_RAW_DATA 1
#endif
#endif
