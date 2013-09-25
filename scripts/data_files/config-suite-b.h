/*
 * Minimal configuration for TLS NSA Suite B Profile (RFC 6460)
 *
 * Can be activated with:
 *      cd scripts
 *      ./activate-config.pl data_files/config-mini-tls1_1.h
 */

/* PolarSSL feature support */
#define POLARSSL_ECP_DP_SECP256R1_ENABLED
#define POLARSSL_ECP_DP_SECP384R1_ENABLED
#define POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define POLARSSL_SSL_PROTO_TLS1_2

/* PolarSSL modules */
#define POLARSSL_AES_C
#define POLARSSL_ASN1_PARSE_C
#define POLARSSL_ASN1_WRITE_C
#define POLARSSL_BIGNUM_C
#define POLARSSL_CIPHER_C
#define POLARSSL_CTR_DRBG_C
#define POLARSSL_ECDH_C
#define POLARSSL_ECDSA_C
#define POLARSSL_ECP_C
#define POLARSSL_ENTROPY_C
#define POLARSSL_GCM_C
#define POLARSSL_MD_C
#define POLARSSL_NET_C
#define POLARSSL_OID_C
#define POLARSSL_PK_C
#define POLARSSL_PK_PARSE_C
#define POLARSSL_SHA256_C
#define POLARSSL_SHA512_C
#define POLARSSL_SSL_CLI_C
#define POLARSSL_SSL_SRV_C
#define POLARSSL_SSL_TLS_C
#define POLARSSL_X509_CRT_PARSE_C
#define POLARSSL_X509_USE_C

/* For test certificates */
#define POLARSSL_BASE64_C
#define POLARSSL_CERTS_C
#define POLARSSL_PEM_PARSE_C

/* For testing with compat.sh */
#define POLARSSL_FS_IO

/* marker for activate-config.pl
 * \} name SECTION: PolarSSL modules */
