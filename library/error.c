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


const char * mbedtls_high_level_strerr( int error_code )
{
    int high_level_error_code;
    const char *error_description = NULL;

    if( error_code < 0 )
        error_code = -error_code;

    /* Extract the high-level part from the error code. */
    high_level_error_code = error_code & 0xFF80;

    switch( high_level_error_code )
    {
        /* Begin Auto-Generated Code. */
#if defined(MBEDTLS_CIPHER_C)
        case -(MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE):
            error_description = "CIPHER - The selected feature is not available";
            break;
        case -(MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA):
            error_description = "CIPHER - Bad input parameters";
            break;
        case -(MBEDTLS_ERR_CIPHER_ALLOC_FAILED):
            error_description = "CIPHER - Failed to allocate memory";
            break;
        case -(MBEDTLS_ERR_CIPHER_INVALID_PADDING):
            error_description = "CIPHER - Input data contains invalid padding and is rejected";
            break;
        case -(MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED):
            error_description = "CIPHER - Decryption of block requires a full block";
            break;
        case -(MBEDTLS_ERR_CIPHER_AUTH_FAILED):
            error_description = "CIPHER - Authentication failed (for AEAD modes)";
            break;
        case -(MBEDTLS_ERR_CIPHER_INVALID_CONTEXT):
            error_description = "CIPHER - The context is invalid. For example, because it was freed";
            break;
        case -(MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED):
            error_description = "CIPHER - Cipher hardware accelerator failed";
            break;
#endif /* MBEDTLS_CIPHER_C */

#if defined(MBEDTLS_DHM_C)
        case -(MBEDTLS_ERR_DHM_BAD_INPUT_DATA):
            error_description = "DHM - Bad input parameters";
            break;
        case -(MBEDTLS_ERR_DHM_READ_PARAMS_FAILED):
            error_description = "DHM - Reading of the DHM parameters failed";
            break;
        case -(MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED):
            error_description = "DHM - Making of the DHM parameters failed";
            break;
        case -(MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED):
            error_description = "DHM - Reading of the public values failed";
            break;
        case -(MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED):
            error_description = "DHM - Making of the public value failed";
            break;
        case -(MBEDTLS_ERR_DHM_CALC_SECRET_FAILED):
            error_description = "DHM - Calculation of the DHM secret failed";
            break;
        case -(MBEDTLS_ERR_DHM_INVALID_FORMAT):
            error_description = "DHM - The ASN.1 data is not formatted correctly";
            break;
        case -(MBEDTLS_ERR_DHM_ALLOC_FAILED):
            error_description = "DHM - Allocation of memory failed";
            break;
        case -(MBEDTLS_ERR_DHM_FILE_IO_ERROR):
            error_description = "DHM - Read or write of file failed";
            break;
        case -(MBEDTLS_ERR_DHM_HW_ACCEL_FAILED):
            error_description = "DHM - DHM hardware accelerator failed";
            break;
        case -(MBEDTLS_ERR_DHM_SET_GROUP_FAILED):
            error_description = "DHM - Setting the modulus and generator failed";
            break;
#endif /* MBEDTLS_DHM_C */

#if defined(MBEDTLS_ECP_C)
        case -(MBEDTLS_ERR_ECP_BAD_INPUT_DATA):
            error_description = "ECP - Bad input parameters to function";
            break;
        case -(MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL):
            error_description = "ECP - The buffer is too small to write to";
            break;
        case -(MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE):
            error_description = "ECP - The requested feature is not available, for example, the requested curve is not supported";
            break;
        case -(MBEDTLS_ERR_ECP_VERIFY_FAILED):
            error_description = "ECP - The signature is not valid";
            break;
        case -(MBEDTLS_ERR_ECP_ALLOC_FAILED):
            error_description = "ECP - Memory allocation failed";
            break;
        case -(MBEDTLS_ERR_ECP_RANDOM_FAILED):
            error_description = "ECP - Generation of random value, such as ephemeral key, failed";
            break;
        case -(MBEDTLS_ERR_ECP_INVALID_KEY):
            error_description = "ECP - Invalid private or public key";
            break;
        case -(MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH):
            error_description = "ECP - The buffer contains a valid signature followed by more data";
            break;
        case -(MBEDTLS_ERR_ECP_HW_ACCEL_FAILED):
            error_description = "ECP - The ECP hardware accelerator failed";
            break;
        case -(MBEDTLS_ERR_ECP_IN_PROGRESS):
            error_description = "ECP - Operation in progress, call again with the same parameters to continue";
            break;
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_MD_C)
        case -(MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE):
            error_description = "MD - The selected feature is not available";
            break;
        case -(MBEDTLS_ERR_MD_BAD_INPUT_DATA):
            error_description = "MD - Bad input parameters to function";
            break;
        case -(MBEDTLS_ERR_MD_ALLOC_FAILED):
            error_description = "MD - Failed to allocate memory";
            break;
        case -(MBEDTLS_ERR_MD_FILE_IO_ERROR):
            error_description = "MD - Opening or reading of file failed";
            break;
        case -(MBEDTLS_ERR_MD_HW_ACCEL_FAILED):
            error_description = "MD - MD hardware accelerator failed";
            break;
#endif /* MBEDTLS_MD_C */

#if defined(MBEDTLS_PEM_PARSE_C) || defined(MBEDTLS_PEM_WRITE_C)
        case -(MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT):
            error_description = "PEM - No PEM header or footer found";
            break;
        case -(MBEDTLS_ERR_PEM_INVALID_DATA):
            error_description = "PEM - PEM string is not as expected";
            break;
        case -(MBEDTLS_ERR_PEM_ALLOC_FAILED):
            error_description = "PEM - Failed to allocate memory";
            break;
        case -(MBEDTLS_ERR_PEM_INVALID_ENC_IV):
            error_description = "PEM - RSA IV is not in hex-format";
            break;
        case -(MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG):
            error_description = "PEM - Unsupported key encryption algorithm";
            break;
        case -(MBEDTLS_ERR_PEM_PASSWORD_REQUIRED):
            error_description = "PEM - Private key password can't be empty";
            break;
        case -(MBEDTLS_ERR_PEM_PASSWORD_MISMATCH):
            error_description = "PEM - Given private key password does not allow for correct decryption";
            break;
        case -(MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE):
            error_description = "PEM - Unavailable feature, e.g. hashing/encryption combination";
            break;
        case -(MBEDTLS_ERR_PEM_BAD_INPUT_DATA):
            error_description = "PEM - Bad input parameters to function";
            break;
#endif /* MBEDTLS_PEM_PARSE_C || MBEDTLS_PEM_WRITE_C */

#if defined(MBEDTLS_PK_C)
        case -(MBEDTLS_ERR_PK_ALLOC_FAILED):
            error_description = "PK - Memory allocation failed";
            break;
        case -(MBEDTLS_ERR_PK_TYPE_MISMATCH):
            error_description = "PK - Type mismatch, eg attempt to encrypt with an ECDSA key";
            break;
        case -(MBEDTLS_ERR_PK_BAD_INPUT_DATA):
            error_description = "PK - Bad input parameters to function";
            break;
        case -(MBEDTLS_ERR_PK_FILE_IO_ERROR):
            error_description = "PK - Read/write of file failed";
            break;
        case -(MBEDTLS_ERR_PK_KEY_INVALID_VERSION):
            error_description = "PK - Unsupported key version";
            break;
        case -(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT):
            error_description = "PK - Invalid key tag or value";
            break;
        case -(MBEDTLS_ERR_PK_UNKNOWN_PK_ALG):
            error_description = "PK - Key algorithm is unsupported (only RSA and EC are supported)";
            break;
        case -(MBEDTLS_ERR_PK_PASSWORD_REQUIRED):
            error_description = "PK - Private key password can't be empty";
            break;
        case -(MBEDTLS_ERR_PK_PASSWORD_MISMATCH):
            error_description = "PK - Given private key password does not allow for correct decryption";
            break;
        case -(MBEDTLS_ERR_PK_INVALID_PUBKEY):
            error_description = "PK - The pubkey tag or value is invalid (only RSA and EC are supported)";
            break;
        case -(MBEDTLS_ERR_PK_INVALID_ALG):
            error_description = "PK - The algorithm tag or value is invalid";
            break;
        case -(MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE):
            error_description = "PK - Elliptic curve is unsupported (only NIST curves are supported)";
            break;
        case -(MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE):
            error_description = "PK - Unavailable feature, e.g. RSA disabled for RSA key";
            break;
        case -(MBEDTLS_ERR_PK_SIG_LEN_MISMATCH):
            error_description = "PK - The buffer contains a valid signature followed by more data";
            break;
        case -(MBEDTLS_ERR_PK_HW_ACCEL_FAILED):
            error_description = "PK - PK hardware accelerator failed";
            break;
#endif /* MBEDTLS_PK_C */

#if defined(MBEDTLS_PKCS12_C)
        case -(MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA):
            error_description = "PKCS12 - Bad input parameters to function";
            break;
        case -(MBEDTLS_ERR_PKCS12_FEATURE_UNAVAILABLE):
            error_description = "PKCS12 - Feature not available, e.g. unsupported encryption scheme";
            break;
        case -(MBEDTLS_ERR_PKCS12_PBE_INVALID_FORMAT):
            error_description = "PKCS12 - PBE ASN.1 data not as expected";
            break;
        case -(MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH):
            error_description = "PKCS12 - Given private key password does not allow for correct decryption";
            break;
#endif /* MBEDTLS_PKCS12_C */

#if defined(MBEDTLS_PKCS5_C)
        case -(MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA):
            error_description = "PKCS5 - Bad input parameters to function";
            break;
        case -(MBEDTLS_ERR_PKCS5_INVALID_FORMAT):
            error_description = "PKCS5 - Unexpected ASN.1 data";
            break;
        case -(MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE):
            error_description = "PKCS5 - Requested encryption or digest alg not available";
            break;
        case -(MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH):
            error_description = "PKCS5 - Given private key password does not allow for correct decryption";
            break;
#endif /* MBEDTLS_PKCS5_C */

#if defined(MBEDTLS_RSA_C)
        case -(MBEDTLS_ERR_RSA_BAD_INPUT_DATA):
            error_description = "RSA - Bad input parameters to function";
            break;
        case -(MBEDTLS_ERR_RSA_INVALID_PADDING):
            error_description = "RSA - Input data contains invalid padding and is rejected";
            break;
        case -(MBEDTLS_ERR_RSA_KEY_GEN_FAILED):
            error_description = "RSA - Something failed during generation of a key";
            break;
        case -(MBEDTLS_ERR_RSA_KEY_CHECK_FAILED):
            error_description = "RSA - Key failed to pass the validity check of the library";
            break;
        case -(MBEDTLS_ERR_RSA_PUBLIC_FAILED):
            error_description = "RSA - The public key operation failed";
            break;
        case -(MBEDTLS_ERR_RSA_PRIVATE_FAILED):
            error_description = "RSA - The private key operation failed";
            break;
        case -(MBEDTLS_ERR_RSA_VERIFY_FAILED):
            error_description = "RSA - The PKCS#1 verification failed";
            break;
        case -(MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE):
            error_description = "RSA - The output buffer for decryption is not large enough";
            break;
        case -(MBEDTLS_ERR_RSA_RNG_FAILED):
            error_description = "RSA - The random generator failed to generate non-zeros";
            break;
        case -(MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION):
            error_description = "RSA - The implementation does not offer the requested operation, for example, because of security violations or lack of functionality";
            break;
        case -(MBEDTLS_ERR_RSA_HW_ACCEL_FAILED):
            error_description = "RSA - RSA hardware accelerator failed";
            break;
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_SSL_TLS_C)
        case -(MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE):
            error_description = "SSL - The requested feature is not available";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_INPUT_DATA):
            error_description = "SSL - Bad input parameters to function";
            break;
        case -(MBEDTLS_ERR_SSL_INVALID_MAC):
            error_description = "SSL - Verification of the message MAC failed";
            break;
        case -(MBEDTLS_ERR_SSL_INVALID_RECORD):
            error_description = "SSL - An invalid SSL record was received";
            break;
        case -(MBEDTLS_ERR_SSL_CONN_EOF):
            error_description = "SSL - The connection indicated an EOF";
            break;
        case -(MBEDTLS_ERR_SSL_UNKNOWN_CIPHER):
            error_description = "SSL - An unknown cipher was received";
            break;
        case -(MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN):
            error_description = "SSL - The server has no ciphersuites in common with the client";
            break;
        case -(MBEDTLS_ERR_SSL_NO_RNG):
            error_description = "SSL - No RNG was provided to the SSL module";
            break;
        case -(MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE):
            error_description = "SSL - No client certification received from the client, but required by the authentication mode";
            break;
        case -(MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE):
            error_description = "SSL - Our own certificate(s) is/are too large to send in an SSL message";
            break;
        case -(MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED):
            error_description = "SSL - The own certificate is not set, but needed by the server";
            break;
        case -(MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED):
            error_description = "SSL - The own private key or pre-shared key is not set, but needed";
            break;
        case -(MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED):
            error_description = "SSL - No CA Chain is set, but required to operate";
            break;
        case -(MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE):
            error_description = "SSL - An unexpected message was received from our peer";
            break;
        case -(MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE):
            error_description = "SSL - A fatal alert message was received from our peer";
            break;
        case -(MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED):
            error_description = "SSL - Verification of our peer failed";
            break;
        case -(MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY):
            error_description = "SSL - The peer notified us that the connection is going to be closed";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO):
            error_description = "SSL - Processing of the ClientHello handshake message failed";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO):
            error_description = "SSL - Processing of the ServerHello handshake message failed";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE):
            error_description = "SSL - Processing of the Certificate handshake message failed";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST):
            error_description = "SSL - Processing of the CertificateRequest handshake message failed";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE):
            error_description = "SSL - Processing of the ServerKeyExchange handshake message failed";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE):
            error_description = "SSL - Processing of the ServerHelloDone handshake message failed";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE):
            error_description = "SSL - Processing of the ClientKeyExchange handshake message failed";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP):
            error_description = "SSL - Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Read Public";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS):
            error_description = "SSL - Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Calculate Secret";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY):
            error_description = "SSL - Processing of the CertificateVerify handshake message failed";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC):
            error_description = "SSL - Processing of the ChangeCipherSpec handshake message failed";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_FINISHED):
            error_description = "SSL - Processing of the Finished handshake message failed";
            break;
        case -(MBEDTLS_ERR_SSL_ALLOC_FAILED):
            error_description = "SSL - Memory allocation failed";
            break;
        case -(MBEDTLS_ERR_SSL_HW_ACCEL_FAILED):
            error_description = "SSL - Hardware acceleration function returned with error";
            break;
        case -(MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH):
            error_description = "SSL - Hardware acceleration function skipped / left alone data";
            break;
        case -(MBEDTLS_ERR_SSL_COMPRESSION_FAILED):
            error_description = "SSL - Processing of the compression / decompression failed";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION):
            error_description = "SSL - Handshake protocol not within min/max boundaries";
            break;
        case -(MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET):
            error_description = "SSL - Processing of the NewSessionTicket handshake message failed";
            break;
        case -(MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED):
            error_description = "SSL - Session ticket has expired";
            break;
        case -(MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH):
            error_description = "SSL - Public key type mismatch (eg, asked for RSA key exchange and presented EC key)";
            break;
        case -(MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY):
            error_description = "SSL - Unknown identity received (eg, PSK identity)";
            break;
        case -(MBEDTLS_ERR_SSL_INTERNAL_ERROR):
            error_description = "SSL - Internal error (eg, unexpected failure in lower-level module)";
            break;
        case -(MBEDTLS_ERR_SSL_COUNTER_WRAPPING):
            error_description = "SSL - A counter would wrap (eg, too many messages exchanged)";
            break;
        case -(MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO):
            error_description = "SSL - Unexpected message at ServerHello in renegotiation";
            break;
        case -(MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED):
            error_description = "SSL - DTLS client must retry for hello verification";
            break;
        case -(MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL):
            error_description = "SSL - A buffer is too small to receive or write a message";
            break;
        case -(MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE):
            error_description = "SSL - None of the common ciphersuites is usable (eg, no suitable certificate, see debug messages)";
            break;
        case -(MBEDTLS_ERR_SSL_WANT_READ):
            error_description = "SSL - No data of requested type currently available on underlying transport";
            break;
        case -(MBEDTLS_ERR_SSL_WANT_WRITE):
            error_description = "SSL - Connection requires a write call";
            break;
        case -(MBEDTLS_ERR_SSL_TIMEOUT):
            error_description = "SSL - The operation timed out";
            break;
        case -(MBEDTLS_ERR_SSL_CLIENT_RECONNECT):
            error_description = "SSL - The client initiated a reconnect from the same port";
            break;
        case -(MBEDTLS_ERR_SSL_UNEXPECTED_RECORD):
            error_description = "SSL - Record header looks valid but is not expected";
            break;
        case -(MBEDTLS_ERR_SSL_NON_FATAL):
            error_description = "SSL - The alert message received indicates a non-fatal error";
            break;
        case -(MBEDTLS_ERR_SSL_INVALID_VERIFY_HASH):
            error_description = "SSL - Couldn't set the hash for verifying CertificateVerify";
            break;
        case -(MBEDTLS_ERR_SSL_CONTINUE_PROCESSING):
            error_description = "SSL - Internal-only message signaling that further message-processing should be done";
            break;
        case -(MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS):
            error_description = "SSL - The asynchronous operation is not completed yet";
            break;
        case -(MBEDTLS_ERR_SSL_EARLY_MESSAGE):
            error_description = "SSL - Internal-only message signaling that a message arrived early";
            break;
        case -(MBEDTLS_ERR_SSL_UNEXPECTED_CID):
            error_description = "SSL - An encrypted DTLS-frame with an unexpected CID was received";
            break;
        case -(MBEDTLS_ERR_SSL_VERSION_MISMATCH):
            error_description = "SSL - An operation failed due to an unexpected version or configuration";
            break;
        case -(MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS):
            error_description = "SSL - A cryptographic operation is in progress. Try again later";
            break;
#endif /* MBEDTLS_SSL_TLS_C */

#if defined(MBEDTLS_X509_USE_C) || defined(MBEDTLS_X509_CREATE_C)
        case -(MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE):
            error_description = "X509 - Unavailable feature, e.g. RSA hashing/encryption combination";
            break;
        case -(MBEDTLS_ERR_X509_UNKNOWN_OID):
            error_description = "X509 - Requested OID is unknown";
            break;
        case -(MBEDTLS_ERR_X509_INVALID_FORMAT):
            error_description = "X509 - The CRT/CRL/CSR format is invalid, e.g. different type expected";
            break;
        case -(MBEDTLS_ERR_X509_INVALID_VERSION):
            error_description = "X509 - The CRT/CRL/CSR version element is invalid";
            break;
        case -(MBEDTLS_ERR_X509_INVALID_SERIAL):
            error_description = "X509 - The serial tag or value is invalid";
            break;
        case -(MBEDTLS_ERR_X509_INVALID_ALG):
            error_description = "X509 - The algorithm tag or value is invalid";
            break;
        case -(MBEDTLS_ERR_X509_INVALID_NAME):
            error_description = "X509 - The name tag or value is invalid";
            break;
        case -(MBEDTLS_ERR_X509_INVALID_DATE):
            error_description = "X509 - The date tag or value is invalid";
            break;
        case -(MBEDTLS_ERR_X509_INVALID_SIGNATURE):
            error_description = "X509 - The signature tag or value invalid";
            break;
        case -(MBEDTLS_ERR_X509_INVALID_EXTENSIONS):
            error_description = "X509 - The extension tag or value is invalid";
            break;
        case -(MBEDTLS_ERR_X509_UNKNOWN_VERSION):
            error_description = "X509 - CRT/CRL/CSR has an unsupported version number";
            break;
        case -(MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG):
            error_description = "X509 - Signature algorithm (oid) is unsupported";
            break;
        case -(MBEDTLS_ERR_X509_SIG_MISMATCH):
            error_description = "X509 - Signature algorithms do not match. (see \\c ::mbedtls_x509_crt sig_oid)";
            break;
        case -(MBEDTLS_ERR_X509_CERT_VERIFY_FAILED):
            error_description = "X509 - Certificate verification failed, e.g. CRL, CA or signature check failed";
            break;
        case -(MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT):
            error_description = "X509 - Format not recognized as DER or PEM";
            break;
        case -(MBEDTLS_ERR_X509_BAD_INPUT_DATA):
            error_description = "X509 - Input invalid";
            break;
        case -(MBEDTLS_ERR_X509_ALLOC_FAILED):
            error_description = "X509 - Allocation of memory failed";
            break;
        case -(MBEDTLS_ERR_X509_FILE_IO_ERROR):
            error_description = "X509 - Read/write of file failed";
            break;
        case -(MBEDTLS_ERR_X509_BUFFER_TOO_SMALL):
            error_description = "X509 - Destination buffer is too small";
            break;
        case -(MBEDTLS_ERR_X509_FATAL_ERROR):
            error_description = "X509 - A fatal error occurred, eg the chain is too long or the vrfy callback failed";
            break;
#endif /* MBEDTLS_X509_USE_C || MBEDTLS_X509_CREATE_C */
        /* End Auto-Generated Code. */

        default:
            break;
    }

    return error_description;
}

const char * mbedtls_low_level_strerr( int error_code )
{
    int low_level_error_code;
    const char *error_description = NULL;

    if( error_code < 0 )
        error_code = -error_code;

    /* Extract the low-level part from the error code. */
    low_level_error_code = error_code & ~0xFF80;

    switch( low_level_error_code )
    {
        /* Begin Auto-Generated Code. */
#if defined(MBEDTLS_AES_C)
        case -(MBEDTLS_ERR_AES_INVALID_KEY_LENGTH):
            error_description = "AES - Invalid key length";
            break;
        case -(MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH):
            error_description = "AES - Invalid data input length";
            break;
        case -(MBEDTLS_ERR_AES_BAD_INPUT_DATA):
            error_description = "AES - Invalid input data";
            break;
        case -(MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE):
            error_description = "AES - Feature not available. For example, an unsupported AES key size";
            break;
        case -(MBEDTLS_ERR_AES_HW_ACCEL_FAILED):
            error_description = "AES - AES hardware accelerator failed";
            break;
#endif /* MBEDTLS_AES_C */

#if defined(MBEDTLS_ARC4_C)
        case -(MBEDTLS_ERR_ARC4_HW_ACCEL_FAILED):
            error_description = "ARC4 - ARC4 hardware accelerator failed";
            break;
#endif /* MBEDTLS_ARC4_C */

#if defined(MBEDTLS_ARIA_C)
        case -(MBEDTLS_ERR_ARIA_BAD_INPUT_DATA):
            error_description = "ARIA - Bad input data";
            break;
        case -(MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH):
            error_description = "ARIA - Invalid data input length";
            break;
        case -(MBEDTLS_ERR_ARIA_FEATURE_UNAVAILABLE):
            error_description = "ARIA - Feature not available. For example, an unsupported ARIA key size";
            break;
        case -(MBEDTLS_ERR_ARIA_HW_ACCEL_FAILED):
            error_description = "ARIA - ARIA hardware accelerator failed";
            break;
#endif /* MBEDTLS_ARIA_C */

#if defined(MBEDTLS_ASN1_PARSE_C)
        case -(MBEDTLS_ERR_ASN1_OUT_OF_DATA):
            error_description = "ASN1 - Out of data when parsing an ASN1 data structure";
            break;
        case -(MBEDTLS_ERR_ASN1_UNEXPECTED_TAG):
            error_description = "ASN1 - ASN1 tag was of an unexpected value";
            break;
        case -(MBEDTLS_ERR_ASN1_INVALID_LENGTH):
            error_description = "ASN1 - Error when trying to determine the length or invalid length";
            break;
        case -(MBEDTLS_ERR_ASN1_LENGTH_MISMATCH):
            error_description = "ASN1 - Actual length differs from expected length";
            break;
        case -(MBEDTLS_ERR_ASN1_INVALID_DATA):
            error_description = "ASN1 - Data is invalid";
            break;
        case -(MBEDTLS_ERR_ASN1_ALLOC_FAILED):
            error_description = "ASN1 - Memory allocation failed";
            break;
        case -(MBEDTLS_ERR_ASN1_BUF_TOO_SMALL):
            error_description = "ASN1 - Buffer too small when writing ASN.1 data structure";
            break;
#endif /* MBEDTLS_ASN1_PARSE_C */

#if defined(MBEDTLS_BASE64_C)
        case -(MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL):
            error_description = "BASE64 - Output buffer too small";
            break;
        case -(MBEDTLS_ERR_BASE64_INVALID_CHARACTER):
            error_description = "BASE64 - Invalid character in input";
            break;
#endif /* MBEDTLS_BASE64_C */

#if defined(MBEDTLS_BIGNUM_C)
        case -(MBEDTLS_ERR_MPI_FILE_IO_ERROR):
            error_description = "BIGNUM - An error occurred while reading from or writing to a file";
            break;
        case -(MBEDTLS_ERR_MPI_BAD_INPUT_DATA):
            error_description = "BIGNUM - Bad input parameters to function";
            break;
        case -(MBEDTLS_ERR_MPI_INVALID_CHARACTER):
            error_description = "BIGNUM - There is an invalid character in the digit string";
            break;
        case -(MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL):
            error_description = "BIGNUM - The buffer is too small to write to";
            break;
        case -(MBEDTLS_ERR_MPI_NEGATIVE_VALUE):
            error_description = "BIGNUM - The input arguments are negative or result in illegal output";
            break;
        case -(MBEDTLS_ERR_MPI_DIVISION_BY_ZERO):
            error_description = "BIGNUM - The input argument for division is zero, which is not allowed";
            break;
        case -(MBEDTLS_ERR_MPI_NOT_ACCEPTABLE):
            error_description = "BIGNUM - The input arguments are not acceptable";
            break;
        case -(MBEDTLS_ERR_MPI_ALLOC_FAILED):
            error_description = "BIGNUM - Memory allocation failed";
            break;
#endif /* MBEDTLS_BIGNUM_C */

#if defined(MBEDTLS_BLOWFISH_C)
        case -(MBEDTLS_ERR_BLOWFISH_BAD_INPUT_DATA):
            error_description = "BLOWFISH - Bad input data";
            break;
        case -(MBEDTLS_ERR_BLOWFISH_INVALID_INPUT_LENGTH):
            error_description = "BLOWFISH - Invalid data input length";
            break;
        case -(MBEDTLS_ERR_BLOWFISH_HW_ACCEL_FAILED):
            error_description = "BLOWFISH - Blowfish hardware accelerator failed";
            break;
#endif /* MBEDTLS_BLOWFISH_C */

#if defined(MBEDTLS_CAMELLIA_C)
        case -(MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA):
            error_description = "CAMELLIA - Bad input data";
            break;
        case -(MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH):
            error_description = "CAMELLIA - Invalid data input length";
            break;
        case -(MBEDTLS_ERR_CAMELLIA_HW_ACCEL_FAILED):
            error_description = "CAMELLIA - Camellia hardware accelerator failed";
            break;
#endif /* MBEDTLS_CAMELLIA_C */

#if defined(MBEDTLS_CCM_C)
        case -(MBEDTLS_ERR_CCM_BAD_INPUT):
            error_description = "CCM - Bad input parameters to the function";
            break;
        case -(MBEDTLS_ERR_CCM_AUTH_FAILED):
            error_description = "CCM - Authenticated decryption failed";
            break;
        case -(MBEDTLS_ERR_CCM_HW_ACCEL_FAILED):
            error_description = "CCM - CCM hardware accelerator failed";
            break;
#endif /* MBEDTLS_CCM_C */

#if defined(MBEDTLS_CHACHA20_C)
        case -(MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA):
            error_description = "CHACHA20 - Invalid input parameter(s)";
            break;
        case -(MBEDTLS_ERR_CHACHA20_FEATURE_UNAVAILABLE):
            error_description = "CHACHA20 - Feature not available. For example, s part of the API is not implemented";
            break;
        case -(MBEDTLS_ERR_CHACHA20_HW_ACCEL_FAILED):
            error_description = "CHACHA20 - Chacha20 hardware accelerator failed";
            break;
#endif /* MBEDTLS_CHACHA20_C */

#if defined(MBEDTLS_CHACHAPOLY_C)
        case -(MBEDTLS_ERR_CHACHAPOLY_BAD_STATE):
            error_description = "CHACHAPOLY - The requested operation is not permitted in the current state";
            break;
        case -(MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED):
            error_description = "CHACHAPOLY - Authenticated decryption failed: data was not authentic";
            break;
#endif /* MBEDTLS_CHACHAPOLY_C */

#if defined(MBEDTLS_CMAC_C)
        case -(MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED):
            error_description = "CMAC - CMAC hardware accelerator failed";
            break;
#endif /* MBEDTLS_CMAC_C */

#if defined(MBEDTLS_CTR_DRBG_C)
        case -(MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED):
            error_description = "CTR_DRBG - The entropy source failed";
            break;
        case -(MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG):
            error_description = "CTR_DRBG - The requested random buffer length is too big";
            break;
        case -(MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG):
            error_description = "CTR_DRBG - The input (entropy + additional data) is too large";
            break;
        case -(MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR):
            error_description = "CTR_DRBG - Read or write error in file";
            break;
#endif /* MBEDTLS_CTR_DRBG_C */

#if defined(MBEDTLS_DES_C)
        case -(MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH):
            error_description = "DES - The data input has an invalid length";
            break;
        case -(MBEDTLS_ERR_DES_HW_ACCEL_FAILED):
            error_description = "DES - DES hardware accelerator failed";
            break;
#endif /* MBEDTLS_DES_C */

#if defined(MBEDTLS_ENTROPY_C)
        case -(MBEDTLS_ERR_ENTROPY_SOURCE_FAILED):
            error_description = "ENTROPY - Critical entropy source failure";
            break;
        case -(MBEDTLS_ERR_ENTROPY_MAX_SOURCES):
            error_description = "ENTROPY - No more sources can be added";
            break;
        case -(MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED):
            error_description = "ENTROPY - No sources have been added to poll";
            break;
        case -(MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE):
            error_description = "ENTROPY - No strong sources have been added to poll";
            break;
        case -(MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR):
            error_description = "ENTROPY - Read/write error in file";
            break;
#endif /* MBEDTLS_ENTROPY_C */

#if defined(MBEDTLS_ERROR_C)
        case -(MBEDTLS_ERR_ERROR_GENERIC_ERROR):
            error_description = "ERROR - Generic error";
            break;
        case -(MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED):
            error_description = "ERROR - This is a bug in the library";
            break;
#endif /* MBEDTLS_ERROR_C */

#if defined(MBEDTLS_GCM_C)
        case -(MBEDTLS_ERR_GCM_AUTH_FAILED):
            error_description = "GCM - Authenticated decryption failed";
            break;
        case -(MBEDTLS_ERR_GCM_HW_ACCEL_FAILED):
            error_description = "GCM - GCM hardware accelerator failed";
            break;
        case -(MBEDTLS_ERR_GCM_BAD_INPUT):
            error_description = "GCM - Bad input parameters to function";
            break;
#endif /* MBEDTLS_GCM_C */

#if defined(MBEDTLS_HKDF_C)
        case -(MBEDTLS_ERR_HKDF_BAD_INPUT_DATA):
            error_description = "HKDF - Bad input parameters to function";
            break;
#endif /* MBEDTLS_HKDF_C */

#if defined(MBEDTLS_HMAC_DRBG_C)
        case -(MBEDTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG):
            error_description = "HMAC_DRBG - Too many random requested in single call";
            break;
        case -(MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG):
            error_description = "HMAC_DRBG - Input too large (Entropy + additional)";
            break;
        case -(MBEDTLS_ERR_HMAC_DRBG_FILE_IO_ERROR):
            error_description = "HMAC_DRBG - Read/write error in file";
            break;
        case -(MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED):
            error_description = "HMAC_DRBG - The entropy source failed";
            break;
#endif /* MBEDTLS_HMAC_DRBG_C */

#if defined(MBEDTLS_MD2_C)
        case -(MBEDTLS_ERR_MD2_HW_ACCEL_FAILED):
            error_description = "MD2 - MD2 hardware accelerator failed";
            break;
#endif /* MBEDTLS_MD2_C */

#if defined(MBEDTLS_MD4_C)
        case -(MBEDTLS_ERR_MD4_HW_ACCEL_FAILED):
            error_description = "MD4 - MD4 hardware accelerator failed";
            break;
#endif /* MBEDTLS_MD4_C */

#if defined(MBEDTLS_MD5_C)
        case -(MBEDTLS_ERR_MD5_HW_ACCEL_FAILED):
            error_description = "MD5 - MD5 hardware accelerator failed";
            break;
#endif /* MBEDTLS_MD5_C */

#if defined(MBEDTLS_NET_C)
        case -(MBEDTLS_ERR_NET_SOCKET_FAILED):
            error_description = "NET - Failed to open a socket";
            break;
        case -(MBEDTLS_ERR_NET_CONNECT_FAILED):
            error_description = "NET - The connection to the given server / port failed";
            break;
        case -(MBEDTLS_ERR_NET_BIND_FAILED):
            error_description = "NET - Binding of the socket failed";
            break;
        case -(MBEDTLS_ERR_NET_LISTEN_FAILED):
            error_description = "NET - Could not listen on the socket";
            break;
        case -(MBEDTLS_ERR_NET_ACCEPT_FAILED):
            error_description = "NET - Could not accept the incoming connection";
            break;
        case -(MBEDTLS_ERR_NET_RECV_FAILED):
            error_description = "NET - Reading information from the socket failed";
            break;
        case -(MBEDTLS_ERR_NET_SEND_FAILED):
            error_description = "NET - Sending information through the socket failed";
            break;
        case -(MBEDTLS_ERR_NET_CONN_RESET):
            error_description = "NET - Connection was reset by peer";
            break;
        case -(MBEDTLS_ERR_NET_UNKNOWN_HOST):
            error_description = "NET - Failed to get an IP address for the given hostname";
            break;
        case -(MBEDTLS_ERR_NET_BUFFER_TOO_SMALL):
            error_description = "NET - Buffer is too small to hold the data";
            break;
        case -(MBEDTLS_ERR_NET_INVALID_CONTEXT):
            error_description = "NET - The context is invalid, eg because it was free()ed";
            break;
        case -(MBEDTLS_ERR_NET_POLL_FAILED):
            error_description = "NET - Polling the net context failed";
            break;
        case -(MBEDTLS_ERR_NET_BAD_INPUT_DATA):
            error_description = "NET - Input invalid";
            break;
#endif /* MBEDTLS_NET_C */

#if defined(MBEDTLS_OID_C)
        case -(MBEDTLS_ERR_OID_NOT_FOUND):
            error_description = "OID - OID is not found";
            break;
        case -(MBEDTLS_ERR_OID_BUF_TOO_SMALL):
            error_description = "OID - output buffer is too small";
            break;
#endif /* MBEDTLS_OID_C */

#if defined(MBEDTLS_PADLOCK_C)
        case -(MBEDTLS_ERR_PADLOCK_DATA_MISALIGNED):
            error_description = "PADLOCK - Input data should be aligned";
            break;
#endif /* MBEDTLS_PADLOCK_C */

#if defined(MBEDTLS_PLATFORM_C)
        case -(MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED):
            error_description = "PLATFORM - Hardware accelerator failed";
            break;
        case -(MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED):
            error_description = "PLATFORM - The requested feature is not supported by the platform";
            break;
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_POLY1305_C)
        case -(MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA):
            error_description = "POLY1305 - Invalid input parameter(s)";
            break;
        case -(MBEDTLS_ERR_POLY1305_FEATURE_UNAVAILABLE):
            error_description = "POLY1305 - Feature not available. For example, s part of the API is not implemented";
            break;
        case -(MBEDTLS_ERR_POLY1305_HW_ACCEL_FAILED):
            error_description = "POLY1305 - Poly1305 hardware accelerator failed";
            break;
#endif /* MBEDTLS_POLY1305_C */

#if defined(MBEDTLS_RIPEMD160_C)
        case -(MBEDTLS_ERR_RIPEMD160_HW_ACCEL_FAILED):
            error_description = "RIPEMD160 - RIPEMD160 hardware accelerator failed";
            break;
#endif /* MBEDTLS_RIPEMD160_C */

#if defined(MBEDTLS_SHA1_C)
        case -(MBEDTLS_ERR_SHA1_HW_ACCEL_FAILED):
            error_description = "SHA1 - SHA-1 hardware accelerator failed";
            break;
        case -(MBEDTLS_ERR_SHA1_BAD_INPUT_DATA):
            error_description = "SHA1 - SHA-1 input data was malformed";
            break;
#endif /* MBEDTLS_SHA1_C */

#if defined(MBEDTLS_SHA256_C)
        case -(MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED):
            error_description = "SHA256 - SHA-256 hardware accelerator failed";
            break;
        case -(MBEDTLS_ERR_SHA256_BAD_INPUT_DATA):
            error_description = "SHA256 - SHA-256 input data was malformed";
            break;
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA512_C)
        case -(MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED):
            error_description = "SHA512 - SHA-512 hardware accelerator failed";
            break;
        case -(MBEDTLS_ERR_SHA512_BAD_INPUT_DATA):
            error_description = "SHA512 - SHA-512 input data was malformed";
            break;
#endif /* MBEDTLS_SHA512_C */

#if defined(MBEDTLS_THREADING_C)
        case -(MBEDTLS_ERR_THREADING_FEATURE_UNAVAILABLE):
            error_description = "THREADING - The selected feature is not available";
            break;
        case -(MBEDTLS_ERR_THREADING_BAD_INPUT_DATA):
            error_description = "THREADING - Bad input parameters to function";
            break;
        case -(MBEDTLS_ERR_THREADING_MUTEX_ERROR):
            error_description = "THREADING - Locking / unlocking / free failed with error code";
            break;
#endif /* MBEDTLS_THREADING_C */

#if defined(MBEDTLS_XTEA_C)
        case -(MBEDTLS_ERR_XTEA_INVALID_INPUT_LENGTH):
            error_description = "XTEA - The data input has an invalid length";
            break;
        case -(MBEDTLS_ERR_XTEA_HW_ACCEL_FAILED):
            error_description = "XTEA - XTEA hardware accelerator failed";
            break;
#endif /* MBEDTLS_XTEA_C */
        /* End Auto-Generated Code. */

        default:
            break;
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
        high_level_error_description = mbedtls_high_level_strerr( ret );

        if( high_level_error_description == NULL )
            mbedtls_snprintf( buf, buflen, "UNKNOWN ERROR CODE (%04X)", (unsigned int) use_ret );
        else
            mbedtls_snprintf( buf, buflen, "%s", high_level_error_description );

#if defined(MBEDTLS_SSL_TLS_C)
        // Early return in case of a fatal error - do not try to translate low
        // level code.
        if(use_ret == -(MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE))
            return;
#endif /* MBEDTLS_SSL_TLS_C */
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
    low_level_error_description = mbedtls_low_level_strerr( ret );

    if( low_level_error_description == NULL )
        mbedtls_snprintf( buf, buflen, "UNKNOWN ERROR CODE (%04X)", (unsigned int) use_ret );
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
