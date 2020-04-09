/*
 *  Error message information
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ERROR_STRERROR_DUMMY)
#include <string.h>
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_snprintf snprintf
#define mbedtls_time_t   time_t
#endif

#if defined(MBEDTLS_ERROR_C)

#include <stdio.h>

#if defined(MBEDTLS_AES_C)
#include "mbedtls/aes.h"
#endif

#if defined(MBEDTLS_ARC4_C)
#include "mbedtls/arc4.h"
#endif

#if defined(MBEDTLS_ARIA_C)
#include "mbedtls/aria.h"
#endif

#if defined(MBEDTLS_BASE64_C)
#include "mbedtls/base64.h"
#endif

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

#if defined(MBEDTLS_BLOWFISH_C)
#include "mbedtls/blowfish.h"
#endif

#if defined(MBEDTLS_CAMELLIA_C)
#include "mbedtls/camellia.h"
#endif

#if defined(MBEDTLS_CCM_C)
#include "mbedtls/ccm.h"
#endif

#if defined(MBEDTLS_CHACHA20_C)
#include "mbedtls/chacha20.h"
#endif

#if defined(MBEDTLS_CHACHAPOLY_C)
#include "mbedtls/chachapoly.h"
#endif

#if defined(MBEDTLS_CIPHER_C)
#include "mbedtls/cipher.h"
#endif

#if defined(MBEDTLS_CMAC_C)
#include "mbedtls/cmac.h"
#endif

#if defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/ctr_drbg.h"
#endif

#if defined(MBEDTLS_DES_C)
#include "mbedtls/des.h"
#endif

#if defined(MBEDTLS_DHM_C)
#include "mbedtls/dhm.h"
#endif

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_ENTROPY_C)
#include "mbedtls/entropy.h"
#endif

#if defined(MBEDTLS_ERROR_C)
#include "mbedtls/error.h"
#endif

#if defined(MBEDTLS_GCM_C)
#include "mbedtls/gcm.h"
#endif

#if defined(MBEDTLS_HKDF_C)
#include "mbedtls/hkdf.h"
#endif

#if defined(MBEDTLS_HMAC_DRBG_C)
#include "mbedtls/hmac_drbg.h"
#endif

#if defined(MBEDTLS_MD_C)
#include "mbedtls/md.h"
#endif

#if defined(MBEDTLS_MD2_C)
#include "mbedtls/md2.h"
#endif

#if defined(MBEDTLS_MD4_C)
#include "mbedtls/md4.h"
#endif

#if defined(MBEDTLS_MD5_C)
#include "mbedtls/md5.h"
#endif

#if defined(MBEDTLS_NET_C)
#include "mbedtls/net_sockets.h"
#endif

#if defined(MBEDTLS_OID_C)
#include "mbedtls/oid.h"
#endif

#if defined(MBEDTLS_PADLOCK_C)
#include "mbedtls/padlock.h"
#endif

#if defined(MBEDTLS_PEM_PARSE_C) || defined(MBEDTLS_PEM_WRITE_C)
#include "mbedtls/pem.h"
#endif

#if defined(MBEDTLS_PK_C)
#include "mbedtls/pk.h"
#endif

#if defined(MBEDTLS_PKCS12_C)
#include "mbedtls/pkcs12.h"
#endif

#if defined(MBEDTLS_PKCS5_C)
#include "mbedtls/pkcs5.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#endif

#if defined(MBEDTLS_POLY1305_C)
#include "mbedtls/poly1305.h"
#endif

#if defined(MBEDTLS_RIPEMD160_C)
#include "mbedtls/ripemd160.h"
#endif

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif

#if defined(MBEDTLS_SHA1_C)
#include "mbedtls/sha1.h"
#endif

#if defined(MBEDTLS_SHA256_C)
#include "mbedtls/sha256.h"
#endif

#if defined(MBEDTLS_SHA512_C)
#include "mbedtls/sha512.h"
#endif

#if defined(MBEDTLS_SSL_TLS_C)
#include "mbedtls/ssl.h"
#endif

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif

#if defined(MBEDTLS_X509_USE_C) || defined(MBEDTLS_X509_CREATE_C)
#include "mbedtls/x509.h"
#endif

#if defined(MBEDTLS_XTEA_C)
#include "mbedtls/xtea.h"
#endif


typedef struct mbedtls_error
{
    int code;                   /* Error code. */
    const char * description;   /* Error description. */
} mbedtls_error_t;

static mbedtls_error_t high_level_errors[] =
{
#if defined(MBEDTLS_CIPHER_C)
    {.code = -(MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE), .description="CIPHER - The selected feature is not available"},
    {.code = -(MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA), .description="CIPHER - Bad input parameters"},
    {.code = -(MBEDTLS_ERR_CIPHER_ALLOC_FAILED), .description="CIPHER - Failed to allocate memory"},
    {.code = -(MBEDTLS_ERR_CIPHER_INVALID_PADDING), .description="CIPHER - Input data contains invalid padding and is rejected"},
    {.code = -(MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED), .description="CIPHER - Decryption of block requires a full block"},
    {.code = -(MBEDTLS_ERR_CIPHER_AUTH_FAILED), .description="CIPHER - Authentication failed (for AEAD modes)"},
    {.code = -(MBEDTLS_ERR_CIPHER_INVALID_CONTEXT), .description="CIPHER - The context is invalid. For example, because it was freed"},
    {.code = -(MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED), .description="CIPHER - Cipher hardware accelerator failed"},
#endif /* MBEDTLS_CIPHER_C */

#if defined(MBEDTLS_DHM_C)
    {.code = -(MBEDTLS_ERR_DHM_BAD_INPUT_DATA), .description="DHM - Bad input parameters"},
    {.code = -(MBEDTLS_ERR_DHM_READ_PARAMS_FAILED), .description="DHM - Reading of the DHM parameters failed"},
    {.code = -(MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED), .description="DHM - Making of the DHM parameters failed"},
    {.code = -(MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED), .description="DHM - Reading of the public values failed"},
    {.code = -(MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED), .description="DHM - Making of the public value failed"},
    {.code = -(MBEDTLS_ERR_DHM_CALC_SECRET_FAILED), .description="DHM - Calculation of the DHM secret failed"},
    {.code = -(MBEDTLS_ERR_DHM_INVALID_FORMAT), .description="DHM - The ASN.1 data is not formatted correctly"},
    {.code = -(MBEDTLS_ERR_DHM_ALLOC_FAILED), .description="DHM - Allocation of memory failed"},
    {.code = -(MBEDTLS_ERR_DHM_FILE_IO_ERROR), .description="DHM - Read or write of file failed"},
    {.code = -(MBEDTLS_ERR_DHM_HW_ACCEL_FAILED), .description="DHM - DHM hardware accelerator failed"},
    {.code = -(MBEDTLS_ERR_DHM_SET_GROUP_FAILED), .description="DHM - Setting the modulus and generator failed"},
#endif /* MBEDTLS_DHM_C */

#if defined(MBEDTLS_ECP_C)
    {.code = -(MBEDTLS_ERR_ECP_BAD_INPUT_DATA), .description="ECP - Bad input parameters to function"},
    {.code = -(MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL), .description="ECP - The buffer is too small to write to"},
    {.code = -(MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE), .description="ECP - The requested feature is not available, for example, the requested curve is not supported"},
    {.code = -(MBEDTLS_ERR_ECP_VERIFY_FAILED), .description="ECP - The signature is not valid"},
    {.code = -(MBEDTLS_ERR_ECP_ALLOC_FAILED), .description="ECP - Memory allocation failed"},
    {.code = -(MBEDTLS_ERR_ECP_RANDOM_FAILED), .description="ECP - Generation of random value, such as ephemeral key, failed"},
    {.code = -(MBEDTLS_ERR_ECP_INVALID_KEY), .description="ECP - Invalid private or public key"},
    {.code = -(MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH), .description="ECP - The buffer contains a valid signature followed by more data"},
    {.code = -(MBEDTLS_ERR_ECP_HW_ACCEL_FAILED), .description="ECP - The ECP hardware accelerator failed"},
    {.code = -(MBEDTLS_ERR_ECP_IN_PROGRESS), .description="ECP - Operation in progress, call again with the same parameters to continue"},
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_MD_C)
    {.code = -(MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE), .description="MD - The selected feature is not available"},
    {.code = -(MBEDTLS_ERR_MD_BAD_INPUT_DATA), .description="MD - Bad input parameters to function"},
    {.code = -(MBEDTLS_ERR_MD_ALLOC_FAILED), .description="MD - Failed to allocate memory"},
    {.code = -(MBEDTLS_ERR_MD_FILE_IO_ERROR), .description="MD - Opening or reading of file failed"},
    {.code = -(MBEDTLS_ERR_MD_HW_ACCEL_FAILED), .description="MD - MD hardware accelerator failed"},
#endif /* MBEDTLS_MD_C */

#if defined(MBEDTLS_PEM_PARSE_C) || defined(MBEDTLS_PEM_WRITE_C)
    {.code = -(MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT), .description="PEM - No PEM header or footer found"},
    {.code = -(MBEDTLS_ERR_PEM_INVALID_DATA), .description="PEM - PEM string is not as expected"},
    {.code = -(MBEDTLS_ERR_PEM_ALLOC_FAILED), .description="PEM - Failed to allocate memory"},
    {.code = -(MBEDTLS_ERR_PEM_INVALID_ENC_IV), .description="PEM - RSA IV is not in hex-format"},
    {.code = -(MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG), .description="PEM - Unsupported key encryption algorithm"},
    {.code = -(MBEDTLS_ERR_PEM_PASSWORD_REQUIRED), .description="PEM - Private key password can't be empty"},
    {.code = -(MBEDTLS_ERR_PEM_PASSWORD_MISMATCH), .description="PEM - Given private key password does not allow for correct decryption"},
    {.code = -(MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE), .description="PEM - Unavailable feature, e.g. hashing/encryption combination"},
    {.code = -(MBEDTLS_ERR_PEM_BAD_INPUT_DATA), .description="PEM - Bad input parameters to function"},
#endif /* MBEDTLS_PEM_PARSE_C || MBEDTLS_PEM_WRITE_C */

#if defined(MBEDTLS_PK_C)
    {.code = -(MBEDTLS_ERR_PK_ALLOC_FAILED), .description="PK - Memory allocation failed"},
    {.code = -(MBEDTLS_ERR_PK_TYPE_MISMATCH), .description="PK - Type mismatch, eg attempt to encrypt with an ECDSA key"},
    {.code = -(MBEDTLS_ERR_PK_BAD_INPUT_DATA), .description="PK - Bad input parameters to function"},
    {.code = -(MBEDTLS_ERR_PK_FILE_IO_ERROR), .description="PK - Read/write of file failed"},
    {.code = -(MBEDTLS_ERR_PK_KEY_INVALID_VERSION), .description="PK - Unsupported key version"},
    {.code = -(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT), .description="PK - Invalid key tag or value"},
    {.code = -(MBEDTLS_ERR_PK_UNKNOWN_PK_ALG), .description="PK - Key algorithm is unsupported (only RSA and EC are supported)"},
    {.code = -(MBEDTLS_ERR_PK_PASSWORD_REQUIRED), .description="PK - Private key password can't be empty"},
    {.code = -(MBEDTLS_ERR_PK_PASSWORD_MISMATCH), .description="PK - Given private key password does not allow for correct decryption"},
    {.code = -(MBEDTLS_ERR_PK_INVALID_PUBKEY), .description="PK - The pubkey tag or value is invalid (only RSA and EC are supported)"},
    {.code = -(MBEDTLS_ERR_PK_INVALID_ALG), .description="PK - The algorithm tag or value is invalid"},
    {.code = -(MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE), .description="PK - Elliptic curve is unsupported (only NIST curves are supported)"},
    {.code = -(MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE), .description="PK - Unavailable feature, e.g. RSA disabled for RSA key"},
    {.code = -(MBEDTLS_ERR_PK_SIG_LEN_MISMATCH), .description="PK - The buffer contains a valid signature followed by more data"},
    {.code = -(MBEDTLS_ERR_PK_HW_ACCEL_FAILED), .description="PK - PK hardware accelerator failed"},
#endif /* MBEDTLS_PK_C */

#if defined(MBEDTLS_PKCS12_C)
    {.code = -(MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA), .description="PKCS12 - Bad input parameters to function"},
    {.code = -(MBEDTLS_ERR_PKCS12_FEATURE_UNAVAILABLE), .description="PKCS12 - Feature not available, e.g. unsupported encryption scheme"},
    {.code = -(MBEDTLS_ERR_PKCS12_PBE_INVALID_FORMAT), .description="PKCS12 - PBE ASN.1 data not as expected"},
    {.code = -(MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH), .description="PKCS12 - Given private key password does not allow for correct decryption"},
#endif /* MBEDTLS_PKCS12_C */

#if defined(MBEDTLS_PKCS5_C)
    {.code = -(MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA), .description="PKCS5 - Bad input parameters to function"},
    {.code = -(MBEDTLS_ERR_PKCS5_INVALID_FORMAT), .description="PKCS5 - Unexpected ASN.1 data"},
    {.code = -(MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE), .description="PKCS5 - Requested encryption or digest alg not available"},
    {.code = -(MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH), .description="PKCS5 - Given private key password does not allow for correct decryption"},
#endif /* MBEDTLS_PKCS5_C */

#if defined(MBEDTLS_RSA_C)
    {.code = -(MBEDTLS_ERR_RSA_BAD_INPUT_DATA), .description="RSA - Bad input parameters to function"},
    {.code = -(MBEDTLS_ERR_RSA_INVALID_PADDING), .description="RSA - Input data contains invalid padding and is rejected"},
    {.code = -(MBEDTLS_ERR_RSA_KEY_GEN_FAILED), .description="RSA - Something failed during generation of a key"},
    {.code = -(MBEDTLS_ERR_RSA_KEY_CHECK_FAILED), .description="RSA - Key failed to pass the validity check of the library"},
    {.code = -(MBEDTLS_ERR_RSA_PUBLIC_FAILED), .description="RSA - The public key operation failed"},
    {.code = -(MBEDTLS_ERR_RSA_PRIVATE_FAILED), .description="RSA - The private key operation failed"},
    {.code = -(MBEDTLS_ERR_RSA_VERIFY_FAILED), .description="RSA - The PKCS#1 verification failed"},
    {.code = -(MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE), .description="RSA - The output buffer for decryption is not large enough"},
    {.code = -(MBEDTLS_ERR_RSA_RNG_FAILED), .description="RSA - The random generator failed to generate non-zeros"},
    {.code = -(MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION), .description="RSA - The implementation does not offer the requested operation, for example, because of security violations or lack of functionality"},
    {.code = -(MBEDTLS_ERR_RSA_HW_ACCEL_FAILED), .description="RSA - RSA hardware accelerator failed"},
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_SSL_TLS_C)
    {.code = -(MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE), .description="SSL - The requested feature is not available"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_INPUT_DATA), .description="SSL - Bad input parameters to function"},
    {.code = -(MBEDTLS_ERR_SSL_INVALID_MAC), .description="SSL - Verification of the message MAC failed"},
    {.code = -(MBEDTLS_ERR_SSL_INVALID_RECORD), .description="SSL - An invalid SSL record was received"},
    {.code = -(MBEDTLS_ERR_SSL_CONN_EOF), .description="SSL - The connection indicated an EOF"},
    {.code = -(MBEDTLS_ERR_SSL_UNKNOWN_CIPHER), .description="SSL - An unknown cipher was received"},
    {.code = -(MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN), .description="SSL - The server has no ciphersuites in common with the client"},
    {.code = -(MBEDTLS_ERR_SSL_NO_RNG), .description="SSL - No RNG was provided to the SSL module"},
    {.code = -(MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE), .description="SSL - No client certification received from the client, but required by the authentication mode"},
    {.code = -(MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE), .description="SSL - Our own certificate(s) is/are too large to send in an SSL message"},
    {.code = -(MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED), .description="SSL - The own certificate is not set, but needed by the server"},
    {.code = -(MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED), .description="SSL - The own private key or pre-shared key is not set, but needed"},
    {.code = -(MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED), .description="SSL - No CA Chain is set, but required to operate"},
    {.code = -(MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE), .description="SSL - An unexpected message was received from our peer"},
    {.code = -(MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE), .description="SSL - A fatal alert message was received from our peer"},
    {.code = -(MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED), .description="SSL - Verification of our peer failed"},
    {.code = -(MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY), .description="SSL - The peer notified us that the connection is going to be closed"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO), .description="SSL - Processing of the ClientHello handshake message failed"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO), .description="SSL - Processing of the ServerHello handshake message failed"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE), .description="SSL - Processing of the Certificate handshake message failed"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST), .description="SSL - Processing of the CertificateRequest handshake message failed"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE), .description="SSL - Processing of the ServerKeyExchange handshake message failed"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE), .description="SSL - Processing of the ServerHelloDone handshake message failed"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE), .description="SSL - Processing of the ClientKeyExchange handshake message failed"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP), .description="SSL - Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Read Public"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS), .description="SSL - Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Calculate Secret"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY), .description="SSL - Processing of the CertificateVerify handshake message failed"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC), .description="SSL - Processing of the ChangeCipherSpec handshake message failed"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_FINISHED), .description="SSL - Processing of the Finished handshake message failed"},
    {.code = -(MBEDTLS_ERR_SSL_ALLOC_FAILED), .description="SSL - Memory allocation failed"},
    {.code = -(MBEDTLS_ERR_SSL_HW_ACCEL_FAILED), .description="SSL - Hardware acceleration function returned with error"},
    {.code = -(MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH), .description="SSL - Hardware acceleration function skipped / left alone data"},
    {.code = -(MBEDTLS_ERR_SSL_COMPRESSION_FAILED), .description="SSL - Processing of the compression / decompression failed"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION), .description="SSL - Handshake protocol not within min/max boundaries"},
    {.code = -(MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET), .description="SSL - Processing of the NewSessionTicket handshake message failed"},
    {.code = -(MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED), .description="SSL - Session ticket has expired"},
    {.code = -(MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH), .description="SSL - Public key type mismatch (eg, asked for RSA key exchange and presented EC key)"},
    {.code = -(MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY), .description="SSL - Unknown identity received (eg, PSK identity)"},
    {.code = -(MBEDTLS_ERR_SSL_INTERNAL_ERROR), .description="SSL - Internal error (eg, unexpected failure in lower-level module)"},
    {.code = -(MBEDTLS_ERR_SSL_COUNTER_WRAPPING), .description="SSL - A counter would wrap (eg, too many messages exchanged)"},
    {.code = -(MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO), .description="SSL - Unexpected message at ServerHello in renegotiation"},
    {.code = -(MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED), .description="SSL - DTLS client must retry for hello verification"},
    {.code = -(MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL), .description="SSL - A buffer is too small to receive or write a message"},
    {.code = -(MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE), .description="SSL - None of the common ciphersuites is usable (eg, no suitable certificate, see debug messages)"},
    {.code = -(MBEDTLS_ERR_SSL_WANT_READ), .description="SSL - No data of requested type currently available on underlying transport"},
    {.code = -(MBEDTLS_ERR_SSL_WANT_WRITE), .description="SSL - Connection requires a write call"},
    {.code = -(MBEDTLS_ERR_SSL_TIMEOUT), .description="SSL - The operation timed out"},
    {.code = -(MBEDTLS_ERR_SSL_CLIENT_RECONNECT), .description="SSL - The client initiated a reconnect from the same port"},
    {.code = -(MBEDTLS_ERR_SSL_UNEXPECTED_RECORD), .description="SSL - Record header looks valid but is not expected"},
    {.code = -(MBEDTLS_ERR_SSL_NON_FATAL), .description="SSL - The alert message received indicates a non-fatal error"},
    {.code = -(MBEDTLS_ERR_SSL_INVALID_VERIFY_HASH), .description="SSL - Couldn't set the hash for verifying CertificateVerify"},
    {.code = -(MBEDTLS_ERR_SSL_CONTINUE_PROCESSING), .description="SSL - Internal-only message signaling that further message-processing should be done"},
    {.code = -(MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS), .description="SSL - The asynchronous operation is not completed yet"},
    {.code = -(MBEDTLS_ERR_SSL_EARLY_MESSAGE), .description="SSL - Internal-only message signaling that a message arrived early"},
    {.code = -(MBEDTLS_ERR_SSL_UNEXPECTED_CID), .description="SSL - An encrypted DTLS-frame with an unexpected CID was received"},
    {.code = -(MBEDTLS_ERR_SSL_VERSION_MISMATCH), .description="SSL - An operation failed due to an unexpected version or configuration"},
    {.code = -(MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS), .description="SSL - A cryptographic operation is in progress. Try again later"},
#endif /* MBEDTLS_SSL_TLS_C */

#if defined(MBEDTLS_X509_USE_C) || defined(MBEDTLS_X509_CREATE_C)
    {.code = -(MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE), .description="X509 - Unavailable feature, e.g. RSA hashing/encryption combination"},
    {.code = -(MBEDTLS_ERR_X509_UNKNOWN_OID), .description="X509 - Requested OID is unknown"},
    {.code = -(MBEDTLS_ERR_X509_INVALID_FORMAT), .description="X509 - The CRT/CRL/CSR format is invalid, e.g. different type expected"},
    {.code = -(MBEDTLS_ERR_X509_INVALID_VERSION), .description="X509 - The CRT/CRL/CSR version element is invalid"},
    {.code = -(MBEDTLS_ERR_X509_INVALID_SERIAL), .description="X509 - The serial tag or value is invalid"},
    {.code = -(MBEDTLS_ERR_X509_INVALID_ALG), .description="X509 - The algorithm tag or value is invalid"},
    {.code = -(MBEDTLS_ERR_X509_INVALID_NAME), .description="X509 - The name tag or value is invalid"},
    {.code = -(MBEDTLS_ERR_X509_INVALID_DATE), .description="X509 - The date tag or value is invalid"},
    {.code = -(MBEDTLS_ERR_X509_INVALID_SIGNATURE), .description="X509 - The signature tag or value invalid"},
    {.code = -(MBEDTLS_ERR_X509_INVALID_EXTENSIONS), .description="X509 - The extension tag or value is invalid"},
    {.code = -(MBEDTLS_ERR_X509_UNKNOWN_VERSION), .description="X509 - CRT/CRL/CSR has an unsupported version number"},
    {.code = -(MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG), .description="X509 - Signature algorithm (oid) is unsupported"},
    {.code = -(MBEDTLS_ERR_X509_SIG_MISMATCH), .description="X509 - Signature algorithms do not match. (see \\c ::mbedtls_x509_crt sig_oid)"},
    {.code = -(MBEDTLS_ERR_X509_CERT_VERIFY_FAILED), .description="X509 - Certificate verification failed, e.g. CRL, CA or signature check failed"},
    {.code = -(MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT), .description="X509 - Format not recognized as DER or PEM"},
    {.code = -(MBEDTLS_ERR_X509_BAD_INPUT_DATA), .description="X509 - Input invalid"},
    {.code = -(MBEDTLS_ERR_X509_ALLOC_FAILED), .description="X509 - Allocation of memory failed"},
    {.code = -(MBEDTLS_ERR_X509_FILE_IO_ERROR), .description="X509 - Read/write of file failed"},
    {.code = -(MBEDTLS_ERR_X509_BUFFER_TOO_SMALL), .description="X509 - Destination buffer is too small"},
    {.code = -(MBEDTLS_ERR_X509_FATAL_ERROR), .description="X509 - A fatal error occurred, eg the chain is too long or the vrfy callback failed"},
#endif /* MBEDTLS_X509_USE_C || MBEDTLS_X509_CREATE_C */
};

#define NUM_HIGH_LEVEL_ERRORS ( sizeof(high_level_errors)/sizeof(mbedtls_error_t) )

static mbedtls_error_t low_level_errors[] =
{
#if defined(MBEDTLS_AES_C)
    {.code = -(MBEDTLS_ERR_AES_INVALID_KEY_LENGTH), .description="AES - Invalid key length"},
    {.code = -(MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH), .description="AES - Invalid data input length"},
    {.code = -(MBEDTLS_ERR_AES_BAD_INPUT_DATA), .description="AES - Invalid input data"},
    {.code = -(MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE), .description="AES - Feature not available. For example, an unsupported AES key size"},
    {.code = -(MBEDTLS_ERR_AES_HW_ACCEL_FAILED), .description="AES - AES hardware accelerator failed"},
#endif /* MBEDTLS_AES_C */

#if defined(MBEDTLS_ARC4_C)
    {.code = -(MBEDTLS_ERR_ARC4_HW_ACCEL_FAILED), .description="ARC4 - ARC4 hardware accelerator failed"},
#endif /* MBEDTLS_ARC4_C */

#if defined(MBEDTLS_ARIA_C)
    {.code = -(MBEDTLS_ERR_ARIA_BAD_INPUT_DATA), .description="ARIA - Bad input data"},
    {.code = -(MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH), .description="ARIA - Invalid data input length"},
    {.code = -(MBEDTLS_ERR_ARIA_FEATURE_UNAVAILABLE), .description="ARIA - Feature not available. For example, an unsupported ARIA key size"},
    {.code = -(MBEDTLS_ERR_ARIA_HW_ACCEL_FAILED), .description="ARIA - ARIA hardware accelerator failed"},
#endif /* MBEDTLS_ARIA_C */

#if defined(MBEDTLS_ASN1_PARSE_C)
    {.code = -(MBEDTLS_ERR_ASN1_OUT_OF_DATA), .description="ASN1 - Out of data when parsing an ASN1 data structure"},
    {.code = -(MBEDTLS_ERR_ASN1_UNEXPECTED_TAG), .description="ASN1 - ASN1 tag was of an unexpected value"},
    {.code = -(MBEDTLS_ERR_ASN1_INVALID_LENGTH), .description="ASN1 - Error when trying to determine the length or invalid length"},
    {.code = -(MBEDTLS_ERR_ASN1_LENGTH_MISMATCH), .description="ASN1 - Actual length differs from expected length"},
    {.code = -(MBEDTLS_ERR_ASN1_INVALID_DATA), .description="ASN1 - Data is invalid"},
    {.code = -(MBEDTLS_ERR_ASN1_ALLOC_FAILED), .description="ASN1 - Memory allocation failed"},
    {.code = -(MBEDTLS_ERR_ASN1_BUF_TOO_SMALL), .description="ASN1 - Buffer too small when writing ASN.1 data structure"},
#endif /* MBEDTLS_ASN1_PARSE_C */

#if defined(MBEDTLS_BASE64_C)
    {.code = -(MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL), .description="BASE64 - Output buffer too small"},
    {.code = -(MBEDTLS_ERR_BASE64_INVALID_CHARACTER), .description="BASE64 - Invalid character in input"},
#endif /* MBEDTLS_BASE64_C */

#if defined(MBEDTLS_BIGNUM_C)
    {.code = -(MBEDTLS_ERR_MPI_FILE_IO_ERROR), .description="BIGNUM - An error occurred while reading from or writing to a file"},
    {.code = -(MBEDTLS_ERR_MPI_BAD_INPUT_DATA), .description="BIGNUM - Bad input parameters to function"},
    {.code = -(MBEDTLS_ERR_MPI_INVALID_CHARACTER), .description="BIGNUM - There is an invalid character in the digit string"},
    {.code = -(MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL), .description="BIGNUM - The buffer is too small to write to"},
    {.code = -(MBEDTLS_ERR_MPI_NEGATIVE_VALUE), .description="BIGNUM - The input arguments are negative or result in illegal output"},
    {.code = -(MBEDTLS_ERR_MPI_DIVISION_BY_ZERO), .description="BIGNUM - The input argument for division is zero, which is not allowed"},
    {.code = -(MBEDTLS_ERR_MPI_NOT_ACCEPTABLE), .description="BIGNUM - The input arguments are not acceptable"},
    {.code = -(MBEDTLS_ERR_MPI_ALLOC_FAILED), .description="BIGNUM - Memory allocation failed"},
#endif /* MBEDTLS_BIGNUM_C */

#if defined(MBEDTLS_BLOWFISH_C)
    {.code = -(MBEDTLS_ERR_BLOWFISH_BAD_INPUT_DATA), .description="BLOWFISH - Bad input data"},
    {.code = -(MBEDTLS_ERR_BLOWFISH_INVALID_INPUT_LENGTH), .description="BLOWFISH - Invalid data input length"},
    {.code = -(MBEDTLS_ERR_BLOWFISH_HW_ACCEL_FAILED), .description="BLOWFISH - Blowfish hardware accelerator failed"},
#endif /* MBEDTLS_BLOWFISH_C */

#if defined(MBEDTLS_CAMELLIA_C)
    {.code = -(MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA), .description="CAMELLIA - Bad input data"},
    {.code = -(MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH), .description="CAMELLIA - Invalid data input length"},
    {.code = -(MBEDTLS_ERR_CAMELLIA_HW_ACCEL_FAILED), .description="CAMELLIA - Camellia hardware accelerator failed"},
#endif /* MBEDTLS_CAMELLIA_C */

#if defined(MBEDTLS_CCM_C)
    {.code = -(MBEDTLS_ERR_CCM_BAD_INPUT), .description="CCM - Bad input parameters to the function"},
    {.code = -(MBEDTLS_ERR_CCM_AUTH_FAILED), .description="CCM - Authenticated decryption failed"},
    {.code = -(MBEDTLS_ERR_CCM_HW_ACCEL_FAILED), .description="CCM - CCM hardware accelerator failed"},
#endif /* MBEDTLS_CCM_C */

#if defined(MBEDTLS_CHACHA20_C)
    {.code = -(MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA), .description="CHACHA20 - Invalid input parameter(s)"},
    {.code = -(MBEDTLS_ERR_CHACHA20_FEATURE_UNAVAILABLE), .description="CHACHA20 - Feature not available. For example, s part of the API is not implemented"},
    {.code = -(MBEDTLS_ERR_CHACHA20_HW_ACCEL_FAILED), .description="CHACHA20 - Chacha20 hardware accelerator failed"},
#endif /* MBEDTLS_CHACHA20_C */

#if defined(MBEDTLS_CHACHAPOLY_C)
    {.code = -(MBEDTLS_ERR_CHACHAPOLY_BAD_STATE), .description="CHACHAPOLY - The requested operation is not permitted in the current state"},
    {.code = -(MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED), .description="CHACHAPOLY - Authenticated decryption failed: data was not authentic"},
#endif /* MBEDTLS_CHACHAPOLY_C */

#if defined(MBEDTLS_CMAC_C)
    {.code = -(MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED), .description="CMAC - CMAC hardware accelerator failed"},
#endif /* MBEDTLS_CMAC_C */

#if defined(MBEDTLS_CTR_DRBG_C)
    {.code = -(MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED), .description="CTR_DRBG - The entropy source failed"},
    {.code = -(MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG), .description="CTR_DRBG - The requested random buffer length is too big"},
    {.code = -(MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG), .description="CTR_DRBG - The input (entropy + additional data) is too large"},
    {.code = -(MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR), .description="CTR_DRBG - Read or write error in file"},
#endif /* MBEDTLS_CTR_DRBG_C */

#if defined(MBEDTLS_DES_C)
    {.code = -(MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH), .description="DES - The data input has an invalid length"},
    {.code = -(MBEDTLS_ERR_DES_HW_ACCEL_FAILED), .description="DES - DES hardware accelerator failed"},
#endif /* MBEDTLS_DES_C */

#if defined(MBEDTLS_ENTROPY_C)
    {.code = -(MBEDTLS_ERR_ENTROPY_SOURCE_FAILED), .description="ENTROPY - Critical entropy source failure"},
    {.code = -(MBEDTLS_ERR_ENTROPY_MAX_SOURCES), .description="ENTROPY - No more sources can be added"},
    {.code = -(MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED), .description="ENTROPY - No sources have been added to poll"},
    {.code = -(MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE), .description="ENTROPY - No strong sources have been added to poll"},
    {.code = -(MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR), .description="ENTROPY - Read/write error in file"},
#endif /* MBEDTLS_ENTROPY_C */

#if defined(MBEDTLS_ERROR_C)
    {.code = -(MBEDTLS_ERR_ERROR_GENERIC_ERROR), .description="ERROR - Generic error"},
    {.code = -(MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED), .description="ERROR - This is a bug in the library"},
#endif /* MBEDTLS_ERROR_C */

#if defined(MBEDTLS_GCM_C)
    {.code = -(MBEDTLS_ERR_GCM_AUTH_FAILED), .description="GCM - Authenticated decryption failed"},
    {.code = -(MBEDTLS_ERR_GCM_HW_ACCEL_FAILED), .description="GCM - GCM hardware accelerator failed"},
    {.code = -(MBEDTLS_ERR_GCM_BAD_INPUT), .description="GCM - Bad input parameters to function"},
#endif /* MBEDTLS_GCM_C */

#if defined(MBEDTLS_HKDF_C)
    {.code = -(MBEDTLS_ERR_HKDF_BAD_INPUT_DATA), .description="HKDF - Bad input parameters to function"},
#endif /* MBEDTLS_HKDF_C */

#if defined(MBEDTLS_HMAC_DRBG_C)
    {.code = -(MBEDTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG), .description="HMAC_DRBG - Too many random requested in single call"},
    {.code = -(MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG), .description="HMAC_DRBG - Input too large (Entropy + additional)"},
    {.code = -(MBEDTLS_ERR_HMAC_DRBG_FILE_IO_ERROR), .description="HMAC_DRBG - Read/write error in file"},
    {.code = -(MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED), .description="HMAC_DRBG - The entropy source failed"},
#endif /* MBEDTLS_HMAC_DRBG_C */

#if defined(MBEDTLS_MD2_C)
    {.code = -(MBEDTLS_ERR_MD2_HW_ACCEL_FAILED), .description="MD2 - MD2 hardware accelerator failed"},
#endif /* MBEDTLS_MD2_C */

#if defined(MBEDTLS_MD4_C)
    {.code = -(MBEDTLS_ERR_MD4_HW_ACCEL_FAILED), .description="MD4 - MD4 hardware accelerator failed"},
#endif /* MBEDTLS_MD4_C */

#if defined(MBEDTLS_MD5_C)
    {.code = -(MBEDTLS_ERR_MD5_HW_ACCEL_FAILED), .description="MD5 - MD5 hardware accelerator failed"},
#endif /* MBEDTLS_MD5_C */

#if defined(MBEDTLS_NET_C)
    {.code = -(MBEDTLS_ERR_NET_SOCKET_FAILED), .description="NET - Failed to open a socket"},
    {.code = -(MBEDTLS_ERR_NET_CONNECT_FAILED), .description="NET - The connection to the given server / port failed"},
    {.code = -(MBEDTLS_ERR_NET_BIND_FAILED), .description="NET - Binding of the socket failed"},
    {.code = -(MBEDTLS_ERR_NET_LISTEN_FAILED), .description="NET - Could not listen on the socket"},
    {.code = -(MBEDTLS_ERR_NET_ACCEPT_FAILED), .description="NET - Could not accept the incoming connection"},
    {.code = -(MBEDTLS_ERR_NET_RECV_FAILED), .description="NET - Reading information from the socket failed"},
    {.code = -(MBEDTLS_ERR_NET_SEND_FAILED), .description="NET - Sending information through the socket failed"},
    {.code = -(MBEDTLS_ERR_NET_CONN_RESET), .description="NET - Connection was reset by peer"},
    {.code = -(MBEDTLS_ERR_NET_UNKNOWN_HOST), .description="NET - Failed to get an IP address for the given hostname"},
    {.code = -(MBEDTLS_ERR_NET_BUFFER_TOO_SMALL), .description="NET - Buffer is too small to hold the data"},
    {.code = -(MBEDTLS_ERR_NET_INVALID_CONTEXT), .description="NET - The context is invalid, eg because it was free()ed"},
    {.code = -(MBEDTLS_ERR_NET_POLL_FAILED), .description="NET - Polling the net context failed"},
    {.code = -(MBEDTLS_ERR_NET_BAD_INPUT_DATA), .description="NET - Input invalid"},
#endif /* MBEDTLS_NET_C */

#if defined(MBEDTLS_OID_C)
    {.code = -(MBEDTLS_ERR_OID_NOT_FOUND), .description="OID - OID is not found"},
    {.code = -(MBEDTLS_ERR_OID_BUF_TOO_SMALL), .description="OID - output buffer is too small"},
#endif /* MBEDTLS_OID_C */

#if defined(MBEDTLS_PADLOCK_C)
    {.code = -(MBEDTLS_ERR_PADLOCK_DATA_MISALIGNED), .description="PADLOCK - Input data should be aligned"},
#endif /* MBEDTLS_PADLOCK_C */

#if defined(MBEDTLS_PLATFORM_C)
    {.code = -(MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED), .description="PLATFORM - Hardware accelerator failed"},
    {.code = -(MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED), .description="PLATFORM - The requested feature is not supported by the platform"},
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_POLY1305_C)
    {.code = -(MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA), .description="POLY1305 - Invalid input parameter(s)"},
    {.code = -(MBEDTLS_ERR_POLY1305_FEATURE_UNAVAILABLE), .description="POLY1305 - Feature not available. For example, s part of the API is not implemented"},
    {.code = -(MBEDTLS_ERR_POLY1305_HW_ACCEL_FAILED), .description="POLY1305 - Poly1305 hardware accelerator failed"},
#endif /* MBEDTLS_POLY1305_C */

#if defined(MBEDTLS_RIPEMD160_C)
    {.code = -(MBEDTLS_ERR_RIPEMD160_HW_ACCEL_FAILED), .description="RIPEMD160 - RIPEMD160 hardware accelerator failed"},
#endif /* MBEDTLS_RIPEMD160_C */

#if defined(MBEDTLS_SHA1_C)
    {.code = -(MBEDTLS_ERR_SHA1_HW_ACCEL_FAILED), .description="SHA1 - SHA-1 hardware accelerator failed"},
    {.code = -(MBEDTLS_ERR_SHA1_BAD_INPUT_DATA), .description="SHA1 - SHA-1 input data was malformed"},
#endif /* MBEDTLS_SHA1_C */

#if defined(MBEDTLS_SHA256_C)
    {.code = -(MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED), .description="SHA256 - SHA-256 hardware accelerator failed"},
    {.code = -(MBEDTLS_ERR_SHA256_BAD_INPUT_DATA), .description="SHA256 - SHA-256 input data was malformed"},
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA512_C)
    {.code = -(MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED), .description="SHA512 - SHA-512 hardware accelerator failed"},
    {.code = -(MBEDTLS_ERR_SHA512_BAD_INPUT_DATA), .description="SHA512 - SHA-512 input data was malformed"},
#endif /* MBEDTLS_SHA512_C */

#if defined(MBEDTLS_THREADING_C)
    {.code = -(MBEDTLS_ERR_THREADING_FEATURE_UNAVAILABLE), .description="THREADING - The selected feature is not available"},
    {.code = -(MBEDTLS_ERR_THREADING_BAD_INPUT_DATA), .description="THREADING - Bad input parameters to function"},
    {.code = -(MBEDTLS_ERR_THREADING_MUTEX_ERROR), .description="THREADING - Locking / unlocking / free failed with error code"},
#endif /* MBEDTLS_THREADING_C */

#if defined(MBEDTLS_XTEA_C)
    {.code = -(MBEDTLS_ERR_XTEA_INVALID_INPUT_LENGTH), .description="XTEA - The data input has an invalid length"},
    {.code = -(MBEDTLS_ERR_XTEA_HW_ACCEL_FAILED), .description="XTEA - XTEA hardware accelerator failed"},
#endif /* MBEDTLS_XTEA_C */
};

#define NUM_LOW_LEVEL_ERRORS  ( sizeof(low_level_errors)/sizeof(mbedtls_error_t) )

const char * mbedtls_high_level_strerr( int error_code )
{
    size_t i;
    const char *error_description = NULL;

    for(i = 0; i < NUM_HIGH_LEVEL_ERRORS; i++ )
    {
        if( high_level_errors[i].code == error_code )
        {
            error_description = high_level_errors[i].description;
            break;
        }
    }

    return error_description;
}

const char * mbedtls_low_level_strerr( int error_code )
{
    size_t i;
    const char *error_description = NULL;

    for(i = 0; i < NUM_LOW_LEVEL_ERRORS; i++ )
    {
        if( low_level_errors[i].code == error_code )
        {
            error_description = low_level_errors[i].description;
            break;
        }
    }

    return error_description;
}

void mbedtls_strerror( int ret, char *buf, size_t buflen )
{
    size_t len;
    int use_ret;
    const char * high_level_error_description = NULL;
    const char * low_level_error_description = NULL;

    if( buflen == 0 )
        return;

    memset( buf, 0x00, buflen );

    if( ret < 0 )
        ret = -ret;

    if( ret & 0xFF80 )
    {
        use_ret = ret & 0xFF80;

        // Translate high level error code.
        high_level_error_description = mbedtls_high_level_strerr(use_ret);

        if( high_level_error_description == NULL )
            mbedtls_snprintf( buf, buflen, "UNKNOWN ERROR CODE (%04X)", use_ret );
        else
            mbedtls_snprintf( buf, buflen, "%s", high_level_error_description );

        // Early return in case of a fatal error - do not try to translate low
        // level code.
        if(use_ret == -(MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE))
            return;
    }

    use_ret = ret & ~0xFF80;

    if( use_ret == 0 )
        return;

    // If high level code is present, make a concatenation between both
    // error strings.
    //
    len = strlen( buf );

    if( len > 0 )
    {
        if( buflen - len < 5 )
            return;

        mbedtls_snprintf( buf + len, buflen - len, " : " );

        buf += len + 3;
        buflen -= len + 3;
    }

    // Translate low level error code.
    low_level_error_description = mbedtls_low_level_strerr( use_ret );

    if( low_level_error_description == NULL )
        mbedtls_snprintf( buf, buflen, "UNKNOWN ERROR CODE (%04X)", use_ret );
    else
        mbedtls_snprintf( buf, buflen, "%s", low_level_error_description );
}

#else /* MBEDTLS_ERROR_C */

#if defined(MBEDTLS_ERROR_STRERROR_DUMMY)

/*
 * Provide an non-function in case MBEDTLS_ERROR_C is not defined
 */
void mbedtls_strerror( int ret, char *buf, size_t buflen )
{
    ((void) ret);

    if( buflen > 0 )
        buf[0] = '\0';
}

#endif /* MBEDTLS_ERROR_STRERROR_DUMMY */

#endif /* MBEDTLS_ERROR_C */
