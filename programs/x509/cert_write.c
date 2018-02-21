/*
 *  Certificate generation and signing
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

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_X509_CRT_WRITE_C) || \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) || \
    !defined(MBEDTLS_ERROR_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_PEM_WRITE_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_X509_CRT_WRITE_C and/or MBEDTLS_X509_CRT_PARSE_C and/or "
            "MBEDTLS_FS_IO and/or MBEDTLS_SHA256_C and/or "
            "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
            "MBEDTLS_ERROR_C not defined.\n");
    return( 0 );
}
#else

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"
#include "mbedtls/pk_info.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <Windows.h>
#endif

#if defined(MBEDTLS_X509_CSR_PARSE_C)
#define USAGE_CSR                                                           \
    "    request_file=%%s         default: (empty)\n"                           \
    "                            If request_file is specified, subject_key,\n"  \
    "                            subject_pwd and subject_name are ignored!\n"
#else
#define USAGE_CSR ""
#endif /* MBEDTLS_X509_CSR_PARSE_C */

#define DFL_ISSUER_CRT          ""
#define DFL_REQUEST_FILE        ""
#define DFL_SUBJECT_KEY         "subject.key"
#define DFL_ISSUER_KEY          "ca.key"
#define DFL_SUBJECT_PWD         ""
#define DFL_ISSUER_PWD          ""
#define DFL_OUTPUT_FILENAME     "cert.crt"
#define DFL_SUBJECT_NAME        "CN=Cert,O=mbed TLS,C=UK"
#define DFL_ISSUER_NAME         "CN=CA,O=mbed TLS,C=UK"
#define DFL_NOT_BEFORE          "20010101000000"
#define DFL_NOT_AFTER           "20301231235959"
#define DFL_SERIAL              "1"
#define DFL_SELFSIGN            0
#define DFL_IS_CA               0
#define DFL_MAX_PATHLEN         -1
#define DFL_KEY_USAGE           0
#define DFL_NS_CERT_TYPE        0
#define DFL_VERSION             3
#define DFL_AUTH_IDENT          1
#define DFL_SUBJ_IDENT          1
#define DFL_CONSTRAINTS         1
#define DFL_DIGEST              MBEDTLS_MD_SHA256

#define UNUSED(x) ((void)(x))

#define USAGE \
    "\n usage: cert_write param=<>...\n"                \
    "\n acceptable parameters:\n"                       \
    USAGE_CSR                                           \
    "    subject_key=%%s          default: subject.key\n"   \
    "    subject_pwd=%%s          default: (empty)\n"       \
    "    subject_name=%%s         default: CN=Cert,O=mbed TLS,C=UK\n"   \
    "\n"                                                \
    "    issuer_crt=%%s           default: (empty)\n"       \
    "                            If issuer_crt is specified, issuer_name is\n"  \
    "                            ignored!\n"                \
    "    issuer_name=%%s          default: CN=CA,O=mbed TLS,C=UK\n"     \
    "\n"                                                \
    "    selfsign=%%d             default: 0 (false)\n"     \
    "                            If selfsign is enabled, issuer_name and\n" \
    "                            issuer_key are required (issuer_crt and\n" \
    "                            subject_* are ignored\n"   \
    "    issuer_key=%%s           default: ca.key\n"        \
    "    issuer_pwd=%%s           default: (empty)\n"       \
    "    output_file=%%s          default: cert.crt\n"      \
    "    serial=%%s               default: 1\n"             \
    "    not_before=%%s           default: 20010101000000\n"\
    "    not_after=%%s            default: 20301231235959\n"\
    "    is_ca=%%d                default: 0 (disabled)\n"  \
    "    max_pathlen=%%d          default: -1 (none)\n"     \
    "    md=%%s                   default: SHA256\n"        \
    "                            Supported values:\n"       \
    "                            MD5, SHA1, SHA256, SHA512\n"\
    "    version=%%d              default: 3\n"            \
    "                            Possible values: 1, 2, 3\n"\
    "    subject_identifier=%%s   default: 1\n"             \
    "                            Possible values: 0, 1\n"   \
    "                            (Considered for v3 only)\n"\
    "    authority_identifier=%%s default: 1\n"             \
    "                            Possible values: 0, 1\n"   \
    "                            (Considered for v3 only)\n"\
    "    basic_constraints=%%d    default: 1\n"             \
    "                            Possible values: 0, 1\n"   \
    "                            (Considered for v3 only)\n"\
    "    key_usage=%%s            default: (empty)\n"       \
    "                            Comma-separated-list of values:\n"     \
    "                            digital_signature\n"     \
    "                            non_repudiation\n"       \
    "                            key_encipherment\n"      \
    "                            data_encipherment\n"     \
    "                            key_agreement\n"         \
    "                            key_cert_sign\n"  \
    "                            crl_sign\n"              \
    "                            (Considered for v3 only)\n"\
    "    ns_cert_type=%%s         default: (empty)\n"       \
    "                            Comma-separated-list of values:\n"     \
    "                            ssl_client\n"            \
    "                            ssl_server\n"            \
    "                            email\n"                 \
    "                            object_signing\n"        \
    "                            ssl_ca\n"                \
    "                            email_ca\n"              \
    "                            object_signing_ca\n"     \
    "\n"

/*
 * global options
 */
struct options
{
    const char *issuer_crt;     /* filename of the issuer certificate   */
    const char *request_file;   /* filename of the certificate request  */
    const char *subject_key;    /* filename of the subject key file     */
    const char *issuer_key;     /* filename of the issuer key file      */
    const char *subject_pwd;    /* password for the subject key file    */
    const char *issuer_pwd;     /* password for the issuer key file     */
    const char *output_file;    /* where to store the constructed key file  */
    const char *subject_name;   /* subject name for certificate         */
    const char *issuer_name;    /* issuer name for certificate          */
    const char *not_before;     /* validity period not before           */
    const char *not_after;      /* validity period not after            */
    const char *serial;         /* serial number string                 */
    int selfsign;               /* selfsign the certificate             */
    int is_ca;                  /* is a CA certificate                  */
    int max_pathlen;            /* maximum CA path length               */
    int authority_identifier;   /* add authority identifier to CRT      */
    int subject_identifier;     /* add subject identifier to CRT        */
    int basic_constraints;      /* add basic constraints ext to CRT     */
    int version;                /* CRT version                          */
    mbedtls_md_type_t md;       /* Hash used for signing                */
    unsigned char key_usage;    /* key usage flags                      */
    unsigned char ns_cert_type; /* NS cert type                         */
} opt;

#if defined(_WIN32)
/** Below are the constants used for remote Opaque key implementation.
 */

/* Remote cryptoprocessor sync pattern. Sent to sync with the device before
 * sending commands. */
#define REMOTE_KEY_MAGIC_PATTERN    "rEmOtEkEy" 
#define REMOTE_KEY_CMD_TAG          "//opaque_pk/ATCA"
#define REMOTE_KEY_ID_MIN           0
#define REMOTE_KEY_ID_MAX           7
#define REMOTE_KEY_SERIAL_BAUD      CBR_9600

#define REMOTE_KEY_FUNC_GET_PUBKEY  0xA
#define REMOTE_KEY_FUNC_SIGN        0xB

int is_remote_key( const char *remote_info )
{
    size_t tag_len = strlen( REMOTE_KEY_CMD_TAG );
    if ( strlen( remote_info ) > tag_len &&
            strncmp( remote_info, REMOTE_KEY_CMD_TAG, tag_len ) == 0 )
        return( 1 );
    return( 0 );
}

int parse_remote_info( const char *remote_info, int *key_idx, const char **serial_port )
{
    int offset = 0;
    int remote_info_len = strlen( remote_info );

    if( is_remote_key( remote_info ) == 0 )
        return( -1 );

    offset = strlen( REMOTE_KEY_CMD_TAG );
    offset++; // Skip the delimiter. FUTURE: Add validation.
    if( offset >= remote_info_len )
        return( -1 );
    *key_idx = (int) remote_info[offset++];
    offset++; // Skip the delimiter
    if( offset >= remote_info_len )
        return( -1 );
    *key_idx = *key_idx - 48; // ascii to decimal

    if ( *key_idx < REMOTE_KEY_ID_MIN || *key_idx > REMOTE_KEY_ID_MAX )
    {
        mbedtls_printf( " failed\n  !  Invalid remote key index %d\n\n", *key_idx );
        return( -1 );
    }
    *serial_port = remote_info + offset;
    printf( "Got key id %d and com port %s\n", *key_idx, *serial_port );
    return( 0 );
}

/**
  * @brief  Send a command to remote cryptoprocessor and receive response.
  *
  * It
  *     - first sends a sync pattern 'rEmOtEkEy' and waits for an echo to sync
  * with the remote.
  *     - Then it sends the tx buf supplied by the caller.
  *     - It waits for a 4 byte length indicator. Value 0 means error.
  *     - Finally it reads no. of bytes specified in received Length indicator
  *       and fills received data in rx_buf and returns.
  *     Note: success is considered when a length indicator > 0 is received and
  *     data size == length indicator is successfully received.
  * 
  *
  * @param serial_port  Serial port to send & recv data.
  * @param tx_buf       Command Tx buffer
  * @param tx_buf_len   Tx buffer length
  * @param rx_buf       Out response Rx buffer
  * @param rx_buf_len   Rx buffer length
  * @param rx_len       Received data length
  *
  * @retval 0 if success, or -1.
  */
int serial_xfer( const char * serial_port, const unsigned char * tx_buf,
                 size_t tx_buf_len, unsigned char * rx_buf, size_t rx_buf_len,
                 size_t * rx_len )
{
    char c, comm_name[20]; /* \\\\.\\COMxy = 11 characters at least */
    HANDLE h_comm;
    DCB dcb_config;
    COMMTIMEOUTS comm_timeout;
    DWORD xfer_len;
    unsigned char len_buf[sizeof(size_t)];
    int ret = -1;
    size_t len = 0, sync_pattern_idx = 0;

    do
    {
        sprintf( comm_name, "\\\\.\\%s", serial_port );

        h_comm = CreateFile( comm_name, GENERIC_READ | GENERIC_WRITE, 0, 0,
                OPEN_EXISTING, 0, 0 );
        if ( h_comm == INVALID_HANDLE_VALUE )
        {
            mbedtls_printf( " failed\n  ! failed to open port %s %lu\n\n", serial_port, GetLastError() );
            break;
        }

        if( GetCommState( h_comm, &dcb_config ) )
        {
            dcb_config.BaudRate = REMOTE_KEY_SERIAL_BAUD;
            dcb_config.Parity = NOPARITY;
            dcb_config.ByteSize = 8;
            dcb_config.StopBits = ONESTOPBIT;
            dcb_config.fOutxCtsFlow = FALSE;         // No CTS output flow control
            dcb_config.fOutxDsrFlow = FALSE;         // No DSR output flow control
            dcb_config.fDtrControl = DTR_CONTROL_DISABLE; // DTR flow control type
            dcb_config.fDsrSensitivity = FALSE;      // DSR sensitivity
            dcb_config.fTXContinueOnXoff = TRUE;     // XOFF continues Tx
            dcb_config.fOutX = FALSE;                // No XON/XOFF out flow control
            dcb_config.fInX = FALSE;                 // No XON/XOFF in flow control
            dcb_config.fErrorChar = FALSE;           // Disable error replacement
            dcb_config.fNull = FALSE;                // Disable null stripping
            dcb_config.fRtsControl = RTS_CONTROL_DISABLE; // RTS flow control
            dcb_config.fAbortOnError = FALSE;        // Do not abort reads/writes on error
        }
        else
        {
            mbedtls_printf( " failed\n  ! GetCommState returned error %lu\n\n", GetLastError() );
            break;
        }

        if( !SetCommState( h_comm, &dcb_config ) )
        {
            mbedtls_printf( " failed\n  ! SetCommState returned error %lu\n\n", GetLastError() );
            break;
        }

        if( GetCommTimeouts( h_comm, &comm_timeout ) )
        {
            comm_timeout.ReadIntervalTimeout = 1000;
            comm_timeout.ReadTotalTimeoutMultiplier = 10;
            comm_timeout.ReadTotalTimeoutConstant = 1000;
            comm_timeout.WriteTotalTimeoutConstant = 1000;
            comm_timeout.WriteTotalTimeoutMultiplier = 10;
        }
        else
        {
            mbedtls_printf( " failed\n  ! GetCommTimeouts returned error %lu\n\n", GetLastError() );
            break;
        }

        if( !SetCommTimeouts( h_comm, &comm_timeout ) )
        {
            mbedtls_printf( " failed\n  ! SetCommTimeouts returned error %lu\n\n", GetLastError() );
            break;
        }


        /* Flush data on serial before sending sync pattern */
        while( ReadFile( h_comm, &c, sizeof(c), &xfer_len, NULL ) && xfer_len != 0 );
        /* Sync with peer */
        if( !WriteFile( h_comm, REMOTE_KEY_MAGIC_PATTERN, strlen(REMOTE_KEY_MAGIC_PATTERN), 
                    &xfer_len, NULL ) )
        {
            mbedtls_printf( " failed\n  ! WriteFile returned error %lu\n\n", GetLastError() );
            break;
        }

        while( sync_pattern_idx != strlen(REMOTE_KEY_MAGIC_PATTERN) )
        {
            if( !ReadFile( h_comm, &c, sizeof(c), &xfer_len, NULL ) )
            {
                mbedtls_printf( " failed\n  ! ReadFile returned error %lu\n\n", GetLastError() );
                break;
            }
            if ( c == REMOTE_KEY_MAGIC_PATTERN[sync_pattern_idx] )
                sync_pattern_idx++;
            else
                sync_pattern_idx = 0;
        }

        /* Exit if there was a read error */
        if ( sync_pattern_idx != strlen(REMOTE_KEY_MAGIC_PATTERN) )
        {
            mbedtls_printf("Failedi to sync!\n");
            break;
        }

        {
            size_t i;
            printf("Tx: ");
            for (i = 0; i < tx_buf_len; i++)
                printf ("0x%02x ", (tx_buf)[i]);
            printf("\n");
        }
        if( !WriteFile( h_comm, tx_buf, tx_buf_len, 
                    &xfer_len, NULL ) )
        {
            mbedtls_printf( " failed\n  ! WriteFile returned error %lu\n\n", GetLastError() );
            break;
        }

        /* Read LI (length indicator) */
        if( !ReadFile( h_comm, len_buf, sizeof(len_buf), &xfer_len, NULL ) ) /* Serial error */
        {
            mbedtls_printf( " failed\n  ! ReadFile returned error %lu\n\n", GetLastError() );
            break;
        }

        *rx_len = ( len_buf[0] << 24 ) | ( len_buf[1] << 16 ) | ( len_buf[2] << 8 ) | len_buf[3];
        if ( *rx_len == 0 ) /* LI == 0 indicates remote error */
        {
            mbedtls_printf( " failed\n  ! Received length indicator == 0\n\n" );
            break;
        }
        if ( *rx_len > rx_buf_len ) /* Buffer too small */
        {
            mbedtls_printf( " failed\n  ! Buffer too small to hold received data\n\n" );
            break;
        }
        /* Read payload */
        len = 0;
        while( len < *rx_len )
        {
            if( !ReadFile( h_comm, rx_buf + len, *rx_len - len, &xfer_len, NULL ) )
            {
                mbedtls_printf( " failed\n  ! ReadFile returned error %lu\n\n", GetLastError() );
                break;
            }
            len += xfer_len;
        }
        if( len < *rx_len ) /* Serial error */
        {
            mbedtls_printf( " failed\n  ! ReadFile returned error %lu\n\n", GetLastError() );
            break;
        }
        printf("Received LI 0x%02x 0x%02x 0x%02x 0x%02x \n", len_buf[0], len_buf[1], len_buf[2], len_buf[3]);
        {
            size_t i;
            printf("Rx: ");
            for (i = 0; i < *rx_len; i++)
                printf ("0x%02x ", (rx_buf)[i]);
            printf("\n");
        }

        ret = 0;
    } while( 0 );

    if( h_comm != INVALID_HANDLE_VALUE )
    {
        CloseHandle( h_comm );
        h_comm = INVALID_HANDLE_VALUE;
    }

    return( ret );
}

/** Load a transparent public key context with public key from remote device
 *  over serial.
 *  This function sends:
 *      rEmOtEkEy<char encoded function code=GetPubKey><char encoded private key ID>
 *  Receives:
 *      <4 bytes length indicator in network order><concatenated public key>
 */
int load_pubkey_from_remote( const char * remote_info, mbedtls_pk_context * ctx )
{
    int key_idx = 0, offset = 0, ret = 0;
    const char * serial_port = NULL;
    unsigned char func_buffer[10];
    unsigned char pub_key_buf[100];
    size_t rx_len = 0;
    static mbedtls_ecp_keypair ecp_key;

    if( parse_remote_info( remote_info, &key_idx, &serial_port ) != 0 )
        return( -1 );

    /* Prepare command */
    offset = 0;
    func_buffer[offset++] = REMOTE_KEY_FUNC_GET_PUBKEY;
    func_buffer[offset++] = key_idx;

    if( serial_xfer( serial_port, func_buffer, offset, pub_key_buf, sizeof( pub_key_buf ), &rx_len ) != 0 )
    {
        mbedtls_printf( " failed\n  !  Serial error trying to get pulic key\n\n" );
        return( -1 );
    }

    /* Import public key from received binary */
    mbedtls_ecp_keypair_init(&ecp_key);
    ret = mbedtls_ecp_group_load(&ecp_key.grp, MBEDTLS_ECP_DP_SECP256R1);
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  Failed to load ecp group\n\n" );
        return( ret );
    }
    ret = mbedtls_ecp_point_read_binary(&ecp_key.grp, &ecp_key.Q, pub_key_buf, rx_len );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  Failed to read ecp key from binary\n\n" );
        return( ret );
    }
    ctx->pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY );
    ctx->pk_ctx = &ecp_key;
    return( 0 );
}

/**
 * @brief           Tell if the context can do the operation given by type
 *
 * @param ctx       PK Context
 * @param type      Target type
 *
 * @return          0 if context can't do the operations,
 *                  1 otherwise.
 */
static int remote_can_do_func(const void *ctx, mbedtls_pk_type_t type)
{
    UNUSED(ctx);
    /* At the moment only ECDSA is supported */
    return (MBEDTLS_PK_ECDSA == type);
}

typedef struct
{
    const char     *serial_port;
    unsigned char   key_idx;
} remote_serial_pk_context;

/**
  * @brief  Sign using remote cryptoprocessor accessed over serial.
  *
  * @param ctx       ECDSA context
  * @param md_alg    Hash Algorithm that was used to hash the message.
  *                  Only SHA256 is supported.
  * @param hash      Message hash
  * @param hash_len  Length of hash
  * @param sig       Buffer that will hold the signature
  * @param sig_len   Length of the signature written
  * @param f_rng     RNG function
  * @param p_rng     RNG parameter
  *
  * @retval 0 if successful, or 1.
  */
static int remote_sign_func(void *ctx, mbedtls_md_type_t md_alg,
                            const unsigned char *hash, size_t hash_len,
                            unsigned char *sig, size_t *sig_len,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    remote_serial_pk_context * remote_ctx = (remote_serial_pk_context *)ctx;
    /* Required buffer = func 1 byte + key Id 1 byte + hash len 4 bytes + hash */
    unsigned char func_buffer[MBEDTLS_MD_MAX_SIZE + 4 + 1 + 1];
    size_t offset = 0; 

    UNUSED( f_rng );
    UNUSED( p_rng );

    if( md_alg != MBEDTLS_MD_SHA256 )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( hash_len + 4 + 1 + 1 > sizeof( func_buffer ) )
    {
        return( MBEDTLS_ERR_PK_BUFFER_TOO_SMALL );
    }

    func_buffer[offset++] = REMOTE_KEY_FUNC_SIGN;
    func_buffer[offset++] = remote_ctx->key_idx;
    func_buffer[offset++] = hash_len >> 24;
    func_buffer[offset++] = hash_len >> 16;
    func_buffer[offset++] = hash_len >> 8;
    func_buffer[offset++] = hash_len;

    memcpy( func_buffer + offset, hash, hash_len );
    offset += hash_len;

    if( serial_xfer( remote_ctx->serial_port, func_buffer, offset, sig,
                     MBEDTLS_ECDSA_MAX_SIG_LEN(256), sig_len ) != 0 )
    {
        mbedtls_printf( " failed\n  !  Serial error in signing\n\n" );
        return( -1 );
    }

    return( 0 );
}

void remote_free( void *ctx )
{
    /* Nothing to free since remote context is statically allocated.
     * Within this app there is no need to scrub the memory.
     */
    UNUSED( ctx );
}

int mbedtls_pk_remote_setup( mbedtls_pk_context * ctx, const char * serial_port,
                             unsigned char key_idx )
{
    /* allocate remote serial context */
    static remote_serial_pk_context remote;
    /* Opaque private key */
    static const mbedtls_pk_info_t remote_pk_info =
    {
        /* MBEDTLS_PK_ECKEY, */
        MBEDTLS_PK_OPAQUE,
        "RemoteSerial",
        NULL,
        remote_can_do_func,
        NULL,
        NULL,
        remote_sign_func,
        NULL,
        NULL,
        NULL,
        NULL,
        remote_free,
        NULL
    };


    if ( ctx == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    remote.serial_port = serial_port;
    remote.key_idx = key_idx;
    ctx->pk_ctx = (void *)&remote;
    ctx->pk_info = &remote_pk_info;

    return( 0 );
}

int setup_opaque_privkey( const char * remote_info, mbedtls_pk_context * ctx )
{
    int key_idx = 0, ret = 0;
    const char * serial_port = NULL;

    if( parse_remote_info( remote_info, &key_idx, &serial_port ) != 0 )
        return( -1 );

    ret = mbedtls_pk_remote_setup( ctx, serial_port, key_idx );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! remote pk setup failure \n\n" );
        return( ret );
    }

    return( 0 );
}
#endif /* _WIN32 */

int write_certificate( mbedtls_x509write_cert *crt, const char *output_file,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    FILE *f;
    unsigned char output_buf[4096];
    size_t len = 0;

    memset( output_buf, 0, 4096 );
    if( ( ret = mbedtls_x509write_crt_pem( crt, output_buf, 4096,
                                           f_rng, p_rng ) ) < 0 )
        return( ret );

    len = strlen( (char *) output_buf );

    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( output_buf, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

int main( int argc, char *argv[] )
{
    int ret = 0;
    mbedtls_x509_crt issuer_crt;
    mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
    mbedtls_pk_context *issuer_key = &loaded_issuer_key,
                *subject_key = &loaded_subject_key;
    char buf[1024];
    char issuer_name[256];
    int i;
    char *p, *q, *r;
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    char subject_name[256];
    mbedtls_x509_csr csr;
#endif
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "crt example app";

    /*
     * Set to sane values
     */
    mbedtls_x509write_crt_init( &crt );
    mbedtls_pk_init( &loaded_issuer_key );
    mbedtls_pk_init( &loaded_subject_key );
    mbedtls_mpi_init( &serial );
    mbedtls_ctr_drbg_init( &ctr_drbg );
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    mbedtls_x509_csr_init( &csr );
#endif
    mbedtls_x509_crt_init( &issuer_crt );
    memset( buf, 0, 1024 );

    if( argc == 0 )
    {
    usage:
        mbedtls_printf( USAGE );
        ret = 1;
        goto exit;
    }

    opt.issuer_crt          = DFL_ISSUER_CRT;
    opt.request_file        = DFL_REQUEST_FILE;
    opt.subject_key         = DFL_SUBJECT_KEY;
    opt.issuer_key          = DFL_ISSUER_KEY;
    opt.subject_pwd         = DFL_SUBJECT_PWD;
    opt.issuer_pwd          = DFL_ISSUER_PWD;
    opt.output_file         = DFL_OUTPUT_FILENAME;
    opt.subject_name        = DFL_SUBJECT_NAME;
    opt.issuer_name         = DFL_ISSUER_NAME;
    opt.not_before          = DFL_NOT_BEFORE;
    opt.not_after           = DFL_NOT_AFTER;
    opt.serial              = DFL_SERIAL;
    opt.selfsign            = DFL_SELFSIGN;
    opt.is_ca               = DFL_IS_CA;
    opt.max_pathlen         = DFL_MAX_PATHLEN;
    opt.key_usage           = DFL_KEY_USAGE;
    opt.ns_cert_type        = DFL_NS_CERT_TYPE;
    opt.version             = DFL_VERSION - 1;
    opt.md                  = DFL_DIGEST;
    opt.subject_identifier   = DFL_SUBJ_IDENT;
    opt.authority_identifier = DFL_AUTH_IDENT;
    opt.basic_constraints    = DFL_CONSTRAINTS;

    for( i = 1; i < argc; i++ )
    {

        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "request_file" ) == 0 )
            opt.request_file = q;
        else if( strcmp( p, "subject_key" ) == 0 )
            opt.subject_key = q;
        else if( strcmp( p, "issuer_key" ) == 0 )
            opt.issuer_key = q;
        else if( strcmp( p, "subject_pwd" ) == 0 )
            opt.subject_pwd = q;
        else if( strcmp( p, "issuer_pwd" ) == 0 )
            opt.issuer_pwd = q;
        else if( strcmp( p, "issuer_crt" ) == 0 )
            opt.issuer_crt = q;
        else if( strcmp( p, "output_file" ) == 0 )
            opt.output_file = q;
        else if( strcmp( p, "subject_name" ) == 0 )
        {
            opt.subject_name = q;
        }
        else if( strcmp( p, "issuer_name" ) == 0 )
        {
            opt.issuer_name = q;
        }
        else if( strcmp( p, "not_before" ) == 0 )
        {
            opt.not_before = q;
        }
        else if( strcmp( p, "not_after" ) == 0 )
        {
            opt.not_after = q;
        }
        else if( strcmp( p, "serial" ) == 0 )
        {
            opt.serial = q;
        }
        else if( strcmp( p, "authority_identifier" ) == 0 )
        {
            opt.authority_identifier = atoi( q );
            if( opt.authority_identifier != 0 &&
                opt.authority_identifier != 1 )
            {
                mbedtls_printf( "Invalid argument for option %s\n", p );
                goto usage;
            }
        }
        else if( strcmp( p, "subject_identifier" ) == 0 )
        {
            opt.subject_identifier = atoi( q );
            if( opt.subject_identifier != 0 &&
                opt.subject_identifier != 1 )
            {
                mbedtls_printf( "Invalid argument for option %s\n", p );
                goto usage;
            }
        }
        else if( strcmp( p, "basic_constraints" ) == 0 )
        {
            opt.basic_constraints = atoi( q );
            if( opt.basic_constraints != 0 &&
                opt.basic_constraints != 1 )
            {
                mbedtls_printf( "Invalid argument for option %s\n", p );
                goto usage;
            }
        }
        else if( strcmp( p, "md" ) == 0 )
        {
            if( strcmp( q, "SHA1" ) == 0 )
                opt.md = MBEDTLS_MD_SHA1;
            else if( strcmp( q, "SHA256" ) == 0 )
                opt.md = MBEDTLS_MD_SHA256;
            else if( strcmp( q, "SHA512" ) == 0 )
                opt.md = MBEDTLS_MD_SHA512;
            else if( strcmp( q, "MD5" ) == 0 )
                opt.md = MBEDTLS_MD_MD5;
            else
            {
                mbedtls_printf( "Invalid argument for option %s\n", p );
                goto usage;
            }
        }
        else if( strcmp( p, "version" ) == 0 )
        {
            opt.version = atoi( q );
            if( opt.version < 1 || opt.version > 3 )
            {
                mbedtls_printf( "Invalid argument for option %s\n", p );
                goto usage;
            }
            opt.version--;
        }
        else if( strcmp( p, "selfsign" ) == 0 )
        {
            opt.selfsign = atoi( q );
            if( opt.selfsign < 0 || opt.selfsign > 1 )
            {
                mbedtls_printf( "Invalid argument for option %s\n", p );
                goto usage;
            }
        }
        else if( strcmp( p, "is_ca" ) == 0 )
        {
            opt.is_ca = atoi( q );
            if( opt.is_ca < 0 || opt.is_ca > 1 )
            {
                mbedtls_printf( "Invalid argument for option %s\n", p );
                goto usage;
            }
        }
        else if( strcmp( p, "max_pathlen" ) == 0 )
        {
            opt.max_pathlen = atoi( q );
            if( opt.max_pathlen < -1 || opt.max_pathlen > 127 )
            {
                mbedtls_printf( "Invalid argument for option %s\n", p );
                goto usage;
            }
        }
        else if( strcmp( p, "key_usage" ) == 0 )
        {
            while( q != NULL )
            {
                if( ( r = strchr( q, ',' ) ) != NULL )
                    *r++ = '\0';

                if( strcmp( q, "digital_signature" ) == 0 )
                    opt.key_usage |= MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
                else if( strcmp( q, "non_repudiation" ) == 0 )
                    opt.key_usage |= MBEDTLS_X509_KU_NON_REPUDIATION;
                else if( strcmp( q, "key_encipherment" ) == 0 )
                    opt.key_usage |= MBEDTLS_X509_KU_KEY_ENCIPHERMENT;
                else if( strcmp( q, "data_encipherment" ) == 0 )
                    opt.key_usage |= MBEDTLS_X509_KU_DATA_ENCIPHERMENT;
                else if( strcmp( q, "key_agreement" ) == 0 )
                    opt.key_usage |= MBEDTLS_X509_KU_KEY_AGREEMENT;
                else if( strcmp( q, "key_cert_sign" ) == 0 )
                    opt.key_usage |= MBEDTLS_X509_KU_KEY_CERT_SIGN;
                else if( strcmp( q, "crl_sign" ) == 0 )
                    opt.key_usage |= MBEDTLS_X509_KU_CRL_SIGN;
                else
                {
                    mbedtls_printf( "Invalid argument for option %s\n", p );
                    goto usage;
                }

                q = r;
            }
        }
        else if( strcmp( p, "ns_cert_type" ) == 0 )
        {
            while( q != NULL )
            {
                if( ( r = strchr( q, ',' ) ) != NULL )
                    *r++ = '\0';

                if( strcmp( q, "ssl_client" ) == 0 )
                    opt.ns_cert_type |= MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT;
                else if( strcmp( q, "ssl_server" ) == 0 )
                    opt.ns_cert_type |= MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER;
                else if( strcmp( q, "email" ) == 0 )
                    opt.ns_cert_type |= MBEDTLS_X509_NS_CERT_TYPE_EMAIL;
                else if( strcmp( q, "object_signing" ) == 0 )
                    opt.ns_cert_type |= MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING;
                else if( strcmp( q, "ssl_ca" ) == 0 )
                    opt.ns_cert_type |= MBEDTLS_X509_NS_CERT_TYPE_SSL_CA;
                else if( strcmp( q, "email_ca" ) == 0 )
                    opt.ns_cert_type |= MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA;
                else if( strcmp( q, "object_signing_ca" ) == 0 )
                    opt.ns_cert_type |= MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA;
                else
                {
                    mbedtls_printf( "Invalid argument for option %s\n", p );
                    goto usage;
                }

                q = r;
            }
        }
        else
            goto usage;
    }

    mbedtls_printf("\n");

    /*
     * 0. Seed the PRNG
     */
    mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_ctr_drbg_seed returned %d - %s\n",
                        ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    // Parse serial to MPI
    //
    mbedtls_printf( "  . Reading serial number..." );
    fflush( stdout );

    if( ( ret = mbedtls_mpi_read_string( &serial, 10, opt.serial ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_mpi_read_string "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    // Parse issuer certificate if present
    //
    if( !opt.selfsign && strlen( opt.issuer_crt ) )
    {
        /*
         * 1.0.a. Load the certificates
         */
        mbedtls_printf( "  . Loading the issuer certificate ..." );
        fflush( stdout );

        if( ( ret = mbedtls_x509_crt_parse_file( &issuer_crt, opt.issuer_crt ) ) != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse_file "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        ret = mbedtls_x509_dn_gets( issuer_name, sizeof(issuer_name),
                                 &issuer_crt.subject );
        if( ret < 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509_dn_gets "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        opt.issuer_name = issuer_name;

        mbedtls_printf( " ok\n" );
    }

#if defined(MBEDTLS_X509_CSR_PARSE_C)
    // Parse certificate request if present
    //
    if( !opt.selfsign && strlen( opt.request_file ) )
    {
        /*
         * 1.0.b. Load the CSR
         */
        mbedtls_printf( "  . Loading the certificate request ..." );
        fflush( stdout );

        if( ( ret = mbedtls_x509_csr_parse_file( &csr, opt.request_file ) ) != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509_csr_parse_file "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        ret = mbedtls_x509_dn_gets( subject_name, sizeof(subject_name),
                                 &csr.subject );
        if( ret < 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509_dn_gets "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        opt.subject_name = subject_name;
        subject_key = &csr.pk;

        mbedtls_printf( " ok\n" );
    }
#endif /* MBEDTLS_X509_CSR_PARSE_C */

    /*
     * 1.1. Load the keys
     */
    if( !opt.selfsign && !strlen( opt.request_file ) )
    {
        mbedtls_printf( "  . Loading the subject key ..." );
        fflush( stdout );

#if defined(_WIN32)
        if ( is_remote_key( opt.subject_key ) )
        {
            ret = load_pubkey_from_remote( opt.subject_key, &loaded_subject_key );
            if ( ret != 0 )
                goto exit;
        }
        else
#endif
        {
            ret = mbedtls_pk_parse_keyfile( &loaded_subject_key, opt.subject_key,
                    opt.subject_pwd );
            if( ret != 0 )
            {
                mbedtls_strerror( ret, buf, 1024 );
                mbedtls_printf( " failed\n  !  mbedtls_pk_parse_keyfile "
                        "returned -0x%04x - %s\n\n", -ret, buf );
                goto exit;
            }
        }

        mbedtls_printf( " ok\n" );
    }

    mbedtls_printf( "  . Loading the issuer key ..." );
    fflush( stdout );

#if defined(_WIN32)
    if ( is_remote_key( opt.issuer_key ) )
    {
        ret = setup_opaque_privkey( opt.issuer_key, &loaded_issuer_key );
        if ( ret != 0 )
            goto exit;
    }
    else
#endif
    {
        ret = mbedtls_pk_parse_keyfile( &loaded_issuer_key, opt.issuer_key,
                opt.issuer_pwd );
    }

    if( ret != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_keyfile "
                        "returned -x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    // Check if key and issuer certificate match
    //
    if( strlen( opt.issuer_crt ) )
    {
        if( !mbedtls_pk_can_do( &issuer_crt.pk, MBEDTLS_PK_RSA ) ||
            mbedtls_mpi_cmp_mpi( &mbedtls_pk_rsa( issuer_crt.pk )->N,
                         &mbedtls_pk_rsa( *issuer_key )->N ) != 0 ||
            mbedtls_mpi_cmp_mpi( &mbedtls_pk_rsa( issuer_crt.pk )->E,
                         &mbedtls_pk_rsa( *issuer_key )->E ) != 0 )
        {
            mbedtls_printf( " failed\n  !  issuer_key does not match "
                            "issuer certificate\n\n" );
            ret = -1;
            goto exit;
        }
    }

    mbedtls_printf( " ok\n" );

    if( opt.selfsign )
    {
        opt.subject_name = opt.issuer_name;
        subject_key = issuer_key;
    }

    mbedtls_x509write_crt_set_subject_key( &crt, subject_key );
    mbedtls_x509write_crt_set_issuer_key( &crt, issuer_key );

    /*
     * 1.0. Check the names for validity
     */
    if( ( ret = mbedtls_x509write_crt_set_subject_name( &crt, opt.subject_name ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_subject_name "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    if( ( ret = mbedtls_x509write_crt_set_issuer_name( &crt, opt.issuer_name ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_issuer_name "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( "  . Setting certificate values ..." );
    fflush( stdout );

    mbedtls_x509write_crt_set_version( &crt, opt.version );
    mbedtls_x509write_crt_set_md_alg( &crt, opt.md );

    ret = mbedtls_x509write_crt_set_serial( &crt, &serial );
    if( ret != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_serial "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    ret = mbedtls_x509write_crt_set_validity( &crt, opt.not_before, opt.not_after );
    if( ret != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_validity "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    if( opt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        opt.basic_constraints != 0 )
    {
        mbedtls_printf( "  . Adding the Basic Constraints extension ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_basic_constraints( &crt, opt.is_ca,
                                                           opt.max_pathlen );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  x509write_crt_set_basic_contraints "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }

#if defined(MBEDTLS_SHA1_C)
    if( opt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        opt.subject_identifier != 0 )
    {
        mbedtls_printf( "  . Adding the Subject Key Identifier ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_subject_key_identifier( &crt );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_subject"
                            "_key_identifier returned -0x%04x - %s\n\n",
                            -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }

    if( opt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        opt.authority_identifier != 0 )
    {
        mbedtls_printf( "  . Adding the Authority Key Identifier ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_authority_key_identifier( &crt );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_authority_"
                            "key_identifier returned -0x%04x - %s\n\n",
                            -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }
#endif /* MBEDTLS_SHA1_C */

    if( opt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        opt.key_usage != 0 )
    {
        mbedtls_printf( "  . Adding the Key Usage extension ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_key_usage( &crt, opt.key_usage );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_key_usage "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }

    if( opt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        opt.ns_cert_type != 0 )
    {
        mbedtls_printf( "  . Adding the NS Cert Type extension ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_ns_cert_type( &crt, opt.ns_cert_type );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_ns_cert_type "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }

    /*
     * 1.2. Writing the request
     */
    mbedtls_printf( "  . Writing the certificate..." );
    fflush( stdout );

    if( ( ret = write_certificate( &crt, opt.output_file,
                                   mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  write_certificate -0x%04x - %s\n\n",
                        -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

exit:
    mbedtls_x509write_crt_free( &crt );
    mbedtls_pk_free( &loaded_subject_key );
    mbedtls_pk_free( &loaded_issuer_key );
    mbedtls_mpi_free( &serial );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}

#endif /* MBEDTLS_X509_CRT_WRITE_C && MBEDTLS_X509_CRT_PARSE_C &&
          MBEDTLS_FS_IO && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          MBEDTLS_ERROR_C && MBEDTLS_PEM_WRITE_C */
