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
 *
 *  This code is based on https://github.com/sftcd/happykey
 *  Special thanks goes to Stephen Farrell for his support and the permission
 *  to re-use the code in Mbed TLS. 
 *
 */
/**
 * \file 
 * Example application using HPKE
 */

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "psa/crypto.h"

#include "mbedtls/debug.h"

#include "mbedtls/base64.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#endif

#include <ctype.h>
#include "mbedtls/pk.h"
#include "mbedtls/hpke.h"

/* biggest/default buffer we use */
#define HPKE_MAXSIZE (2*1024)

#define DFL_OPERATION_ENCRYPT         1
#define DFL_OPERATION_DECRYPT         0

#define USAGE \
    "    HPKE test application                                                  \n" \
    "                                                                           \n" \
    " For encryption use the following parameters:                              \n" \
    "    doing_enc=%%d        1 (encrypt)                                       \n" \
    "    pkR_filename=%%s     File with the public key of the recipient         \n" \
    "    input_filename=%%s   File with input-plaintext                         \n" \
    "    output_filename=%%s  File to which the output will be written to       \n" \
    "    pkE_filename=%%s     File to which the ephemeral PK will be written to \n" \
    "    mode=%%s             HPKE mode (base, psk, auth, pskauth)              \n" \
    "    suite=%%s            HPKE ciphersuite using a comma separated list     \n" \
    "                         For example, '0x10,1,1' refers to                 \n" \
    "                              KEM: P256                                    \n" \
    "                              KDF: HKDF-SHA256                             \n" \
    "                              AEAD: AES-128-GCM                            \n" \
    "                                                                           \n" \
    " For decryption use the following parameters:                              \n" \
    "    doing_enc=%%d        0 (decrypt)                                       \n" \
    "    skR_filename=%%s     File with own secret key                          \n" \
    "    mode=%%s             HPKE mode (base, psk, auth, pskauth)              \n" \
    "    suite=%%s            HPKE ciphersuite using a comma separated list     \n" \
    "    pkE_filename=%%s     File with ephemeral public key                    \n" \
    "    input_filename=%%s   File with input-ciphertext                        \n" \
    "    output_filename=%%s  File to which the plaintext will be written to    \n" \
    "                                                                           \n" \
    " Optional parameters:                                                      \n" \
    "    info_in=%%s          Additional info to bind to key                    \n" \
    "                         (file name or actual value)                       \n" \
    "    pskid=%%s            PSK id string                                     \n" \
    "    psk_in=%%s           PSK file name or base64 or ascii-hex encoded value\n" \
    "    aad_in=%%s           Additional authenticated data file name or value  \n" \
    "    use_pkE_handle=%%s   Utilize handle to key                             \n" \
    "                         (value != 0 means use key handle)                 \n" \
"\n"

/*
 * \brief strip out newlines from input
 *
 * This could be more generic and strip all whitespace
 * but not sure that'd be right. So this'll do for now:-)
 *
 * \param len is the string length on input and output
 * \param buf is the string
 * \return void
 */
static void strip_newlines(size_t *len, char *buf)
{
    size_t writep=0;
    size_t nlen=*len;
    size_t elen=nlen;
    for (size_t i=0;i!=nlen;i++) {
        if (buf[i]!='\n' && buf[i]!='\r') {
            buf[writep++]=buf[i];
        } else {
            elen--;
        }
    }
    if (writep<*len) buf[writep]='\0';
    *len=elen;
    return;
}

static int write_to_file( const char *outp, size_t outlen, unsigned char *outbuf )
{
    FILE *fp;
    size_t frv;

#if defined(_MSC_VER)
    errno_t err;
    err = fopen_s( &fp, outp, "wb" );

    if( err != 0 )
    {
        mbedtls_printf(  "Can't open (%s) - exiting\n", outp);
        return(EXIT_FAILURE);
    }
#else
    fp = fopen( outp, "wb" );

    if (!fp)
    {
        mbedtls_printf(  "Can't open (%s) - exiting\n", outp);
        return(EXIT_FAILURE);
    }
#endif

    frv = fwrite( outbuf, 1, outlen, fp );
    
    mbedtls_printf( "wrote %lu bytes to file %s\n",(unsigned long) frv, outp);
    
    if( ferror(fp) )
    {
        fclose( fp );
        return( EXIT_FAILURE );
    }

    fclose( fp );

    return( 0 );
}

static int read_from_file( const char *inp, size_t *outlen, unsigned char **outbuf )
{
    unsigned char tbuf[HPKE_MAXSIZE];
    size_t toutlen=HPKE_MAXSIZE;
    FILE *fp;

#if defined(_MSC_VER)
    errno_t err;
    err = fopen_s( &fp, inp, "rb" );

    if (err != 0)
    {
        mbedtls_printf(  "Can't open (%s) - exiting\n", inp);
        return(EXIT_FAILURE);
    }
#else
    fp = fopen( inp, "rb" );

    if( !fp )
    {
        mbedtls_printf(  "Can't open (%s) - exiting\n", inp);
        return( EXIT_FAILURE );
    }
#endif /* _MSC_VER */

    toutlen = fread( tbuf, 1, HPKE_MAXSIZE, fp );
    
    fprintf( stderr, "got %lu bytes from file %s\n", (unsigned long) toutlen, inp );
    
    if( ferror(fp) )
    {
        fclose( fp );
        return( EXIT_FAILURE );
    }

    fclose( fp );

    *outbuf = mbedtls_calloc( 1, toutlen );

    if( outbuf == NULL )
    {
        return( EXIT_FAILURE );
    }

    memcpy( *outbuf, tbuf, toutlen );

    *outlen = toutlen;

    return( 0 );
}

/*
 * \brief map a user-supplied input to a buffer or stream
 *
 * We'll check for a file name, base64 or ascii-hex encoding
 *
 * \param inp is the input ptr
 * \param outlen is an output length of buffer
 * \param outbuf is an output buffer
 * \param strip whether to strip newlines from input 
 * \return 1 for good, not 1 for bad
 */
static int map_input(const char *inp, size_t *outlen, unsigned char **outbuf, int strip)
{
    if (!outlen || !outbuf) return(__LINE__);
    /* on-stack buffer/length to handle various cases */
    size_t toutlen=HPKE_MAXSIZE;
    int res;
    int is_file = -1;
    FILE* fp;
#if defined(_MSC_VER)
    errno_t err;
#endif /* _MSC_VER */

    char tbuf[HPKE_MAXSIZE];
    memset(tbuf,0,HPKE_MAXSIZE); /* need this so valgrind doesn't complain about b64 strspn below with short values */
    /* asci hex is easy:-) either case allowed*/
    const char *AH_alphabet="0123456789ABCDEFabcdef\n";
    /* and base64 isn't much harder */
    const char *B64_alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n";

    /* if no input, try stdin */
    if (!inp) {
        toutlen=fread(tbuf,1,HPKE_MAXSIZE,stdin);
        mbedtls_printf( "got %lu bytes from stdin\n",(unsigned long)toutlen);
        if (!feof(stdin)) return(__LINE__);
    } else {
        toutlen=strlen(inp);
        if (toutlen>HPKE_MAXSIZE) return(__LINE__);

#if defined(_MSC_VER)
        /* check if inp is file name */
        err = fopen_s( &fp, inp, "rb" );

        if (err == 0) is_file = 1; // it is a file
#else
        fp = fopen( inp, "r" );

        if (fp) is_file = 1; // it is a file
#endif /* _MSC_VER */

        if( is_file == 1 )
        {
            /* that worked - so read file up to max into buffer */
            toutlen=fread(tbuf,1,HPKE_MAXSIZE,fp);
            mbedtls_printf( "got %lu bytes from file %s\n",(unsigned long)toutlen,inp);
            if (ferror(fp)) { fclose(fp); return(__LINE__); }
            fclose(fp);
        } else {
            mbedtls_printf( "got %lu bytes direct from command line %s\n",
                            (unsigned long)toutlen,inp);
            memcpy(tbuf,inp,toutlen);
        }
    }
    if (toutlen>HPKE_MAXSIZE) return(__LINE__);

    /* ascii-hex or b64 decode as needed */
    /* try from most constrained to least in that order */
    if (strip) {
        if (toutlen<=strspn(tbuf,AH_alphabet)) {
            strip_newlines(&toutlen,tbuf);
            int adr=hpke_ah_decode(toutlen,tbuf,outlen,outbuf);
            if (!adr) return(__LINE__);
            if (adr==1) {
                mbedtls_printf( "ah_decode worked for %s - going with that\n",tbuf);
                return(1);
            }
        } 
        if (toutlen<=strspn(tbuf,B64_alphabet)) {
            strip_newlines(&toutlen,tbuf);
            *outbuf=mbedtls_calloc(1, toutlen);
            if (!*outbuf) return(__LINE__);
            // BASE64 encoding/decoding
            res=mbedtls_base64_decode( *outbuf, toutlen, outlen,  (unsigned char *)tbuf, toutlen );
            
            if (res==0) {
                mbedtls_printf( "base64 decode ok for %s - using the %lu bytes that provided\n",
                           tbuf,(unsigned long)*outlen);
                return(1);
            } else {
                /* base64 decode failed so maybe the content was good as-is */
                mbedtls_free(*outbuf);
                *outbuf=NULL;
            }
        }
        mbedtls_printf( "decodes failed for %s - going with original\n",tbuf);
    } else {
        mbedtls_printf( "going with original: %s\n",tbuf);
    } 
    /* fallback to assuming input is good, as-is */
    /* Mbed TLS library requires a non-null-terminated string */
    *outbuf=mbedtls_calloc(1, toutlen+1);
    
    if (!*outbuf) return(__LINE__);
    memcpy(*outbuf,tbuf,toutlen);
    outbuf[toutlen]='\0'; // null terminate
    *outlen=toutlen+1;
    return(1);
}

/*
 * global options
 */
struct options
{
    int doing_enc;
    char* pkE_filename;
    char* pkR_filename;
    char* skR_filename;
    char* aad_in;
    char* info_in;
    char* input_filename;
    char* output_filename;
    int hpke_mode;
    char* pskid;
    char* psk_in;
    char* suitestr;
    hpke_suite_t hpke_suite;
    int use_pkE_handle;
} opt;

int main(int argc, char** argv)
{
    // PSA-based Variable
    psa_status_t status;

    // Return value
    int ret = 0;

    // Loop index
    int i;

    // Buffers
    uint8_t* pkR = NULL;
    size_t pkR_len;
    uint8_t* plaintext = NULL;
    size_t plaintext_len;
    uint8_t* ciphertext = NULL;
    size_t ciphertext_len = 0;

    // Parsing of command line parameters
    char* p, * q;

    // Variables for use with private key import
    psa_key_handle_t skR_handle = 0;
    psa_key_type_t type;
    psa_key_attributes_t attr_private_key = PSA_KEY_ATTRIBUTES_INIT;

    // Initializing input parameters
    opt.doing_enc = DFL_OPERATION_ENCRYPT;
    opt.pkE_filename = NULL;
    opt.pkR_filename = NULL;
    opt.skR_filename = NULL;
    opt.aad_in = NULL;
    opt.info_in = NULL;
    opt.input_filename = NULL;
    opt.output_filename = NULL;
    opt.hpke_mode = HPKE_MODE_BASE;
    opt.pskid = NULL;
    opt.psk_in = NULL;
    opt.suitestr = NULL;
    opt.hpke_suite.kdf_id = HPKE_KDF_ID_HKDF_SHA256;
    opt.hpke_suite.kem_id = HPKE_KEM_ID_P256;
    opt.hpke_suite.aead_id = HPKE_AEAD_ID_AES_GCM_128;
    opt.use_pkE_handle = 0;

    size_t publen = 0; unsigned char* pub = NULL;
    size_t skR_len = 0; unsigned char* skR = NULL;
    size_t aadlen = 0; unsigned char* aad = NULL;
    size_t infolen = 0; unsigned char* info = NULL;
    size_t psklen = 0; unsigned char* psk = NULL;

    // pkE handle
    psa_key_attributes_t skE_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t skE_handle = 0;
    size_t key_len;

    if( argc == 1 )
    {
    usage:
        if( ret == 0 )
            ret = 1;

        mbedtls_printf( USAGE );
        goto exit;
    }

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "aad_in" ) == 0 )
            opt.aad_in = q;
        else if( strcmp( p, "suite" ) == 0 )
        {
            if( hpke_str2suite( q, &opt.hpke_suite ) != 1 )
            {
                mbedtls_printf( "bad ciphersuite string\n" );
                goto usage;
            }
        }
        else if(strcmp( p, "doing_enc" ) == 0 )
        {
            switch( atoi( q ) )
            {
            case DFL_OPERATION_DECRYPT:
                opt.doing_enc = DFL_OPERATION_DECRYPT;
                break;
            case DFL_OPERATION_ENCRYPT:
                opt.doing_enc = DFL_OPERATION_ENCRYPT;
                break;
            default:
                mbedtls_printf( "invalid unknown operation (encryption/decryption)\n" );
                goto usage;
            }
        }
        else if(strcmp( p, "use_pkE_handle" ) == 0 )
        {
            switch( atoi( q ) )
            {
            case 0:
                opt.use_pkE_handle = 0;
                break;
            default:
                opt.use_pkE_handle = 1;
            }
        }
        else if( strcmp( p, "info_in" ) == 0)
            opt.info_in = q;
        else if( strcmp( p, "input_filename" ) == 0)
            opt.input_filename = q;
        else if( strcmp( p, "mode" ) == 0)
        {
            if( strcmp( q, HPKE_MODESTR_BASE ) == 0)
                opt.hpke_mode = HPKE_MODE_BASE;
            else if( strcmp( q, HPKE_MODESTR_PSK ) == 0)
                opt.hpke_mode = HPKE_MODE_PSK;
            else if( strcmp( q, HPKE_MODESTR_AUTH ) == 0)
                opt.hpke_mode = HPKE_MODE_AUTH;
            else if( strcmp( q, HPKE_MODESTR_PSKAUTH ) == 0)
                opt.hpke_mode = HPKE_MODE_PSKAUTH;
            else
            {
                mbedtls_printf( "unkown HPKE mode\n" );
                goto usage;
            }
        }
        else if( strcmp( p, "pskid" ) == 0 )
            opt.pskid = q;
        else if( strcmp( p, "output_filename" ) == 0 )
            opt.output_filename = q;
        else if( strcmp( p, "pkR_filename" ) == 0 )
            opt.pkR_filename = q;
        else if( strcmp( p, "pkE_filename" ) == 0 )
            opt.pkE_filename = q;
        else if( strcmp( p, "skR_filename" ) == 0 )
            opt.skR_filename = q;
        else if( strcmp( p, "psk_in" ) == 0 )
            opt.psk_in = q;
        else
            goto usage;
    }

    if( opt.aad_in && map_input(opt.aad_in, &aadlen, &aad, 1) != 1)
    {
        mbedtls_printf("bad aad_in value\n");
        goto usage;
    }

    if( opt.info_in && map_input( opt.info_in, &infolen, &info, 1 ) !=1 )
    {
        mbedtls_printf( "bad info_in value\n" );
        goto usage;
    }

    // Initialize the PSA
    status = psa_crypto_init( );

    if ( status != PSA_SUCCESS )
    {
        mbedtls_printf( "Unable to initialize crypto (%d) - exiting\n", status );
        ret = status;
        goto exit;
    }

    // Encryption
    if( opt.doing_enc == DFL_OPERATION_ENCRYPT )
    {
        size_t pkE_len = PSA_EXPORT_PUBLIC_KEY_MAX_SIZE;
        uint8_t pkE[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = { 0 };

        if( opt.psk_in && map_input( opt.psk_in, &psklen, &psk, 1 ) != 1 )
        {
            mbedtls_printf("bad psk_in value\n");
            goto usage;
        }

        // Load pkR
        if( opt.doing_enc && !opt.pkR_filename )
        {
            mbedtls_printf( "no recipient public key (pkR_filename) provided\n" );
            goto usage;
        }

        if( opt.pkR_filename != NULL )
        {
            ret = read_from_file( opt.pkR_filename, &pkR_len, &pkR );

            if( ret != 0 )
            {
                mbedtls_printf( "bad pkR_filename value: %s\n", opt.pkR_filename );
                goto usage;
            }
        }

        // Load plaintext
        if( opt.doing_enc && !opt.input_filename )
        {
            mbedtls_printf( "No plaintext file (input_filename) provided\n" );
            goto usage;
        }

        if( opt.input_filename != NULL )
        {
            ret = read_from_file( opt.input_filename, &plaintext_len, &plaintext );

            if( ret != 0 )
            {
                mbedtls_printf( "bad -i value: %s\n", opt.input_filename );
                goto usage;
            }
        }

        // Allocate memory for ciphertext
        ciphertext_len = PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE( plaintext_len );
        ciphertext = mbedtls_calloc( 1, ciphertext_len );

        if( ciphertext == NULL )
        {
            mbedtls_printf( "not enough memory for ciphertext\n" );
            ret = -1;
            goto exit;
        }

        if( opt.use_pkE_handle != 0 )
        {
            switch( opt.hpke_suite.kem_id )
            {
                case HPKE_KEM_ID_P256:
                    type = PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 );
                    key_len = 256;
                    break;
                case HPKE_KEM_ID_P384:
                    type = PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 );
                    key_len = 384;
                    break;
                case HPKE_KEM_ID_P521:
                    type = PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 );
                    key_len = 521;
                    break;
                case HPKE_KEM_ID_25519: // not implemented yet
                case HPKE_KEM_ID_448: // not implemented yet
                default:
                    mbedtls_printf( "Unsupported KEM (%d) - exiting\n", opt.hpke_suite.kem_id );
                    goto usage;
            }

            /* Generate pkE/skE key pair */
            psa_set_key_usage_flags( &skE_attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm( &skE_attributes, PSA_ALG_ECDH );
            psa_set_key_type( &skE_attributes, type );
            psa_set_key_bits( &skE_attributes, key_len );

            status = psa_generate_key( &skE_attributes, &skE_handle );

            if( status != PSA_SUCCESS )
            {
                return( EXIT_FAILURE );
            }

            ret = mbedtls_hpke_encrypt( opt.hpke_mode,                 // HPKE mode
                                        opt.hpke_suite,                // ciphersuite
                                        opt.pskid, psklen, psk,        // PSK
                                        pkR_len, pkR,                  // pkR
                                        0,                             // skI
                                        plaintext_len, plaintext,      // input plaintext
                                        aadlen, aad,                   // Additional data
                                        infolen, info,                 // Info
                                        skE_handle,                    // skE handle
                                        NULL, NULL,                    // pkE
                                        &ciphertext_len, ciphertext ); // ciphertext
        } else
        {
            ret = mbedtls_hpke_encrypt( opt.hpke_mode,                 // HPKE mode
                                        opt.hpke_suite,                // ciphersuite
                                        opt.pskid, psklen, psk,        // PSK
                                        pkR_len, pkR,                  // pkR
                                        0,                             // skI
                                        plaintext_len, plaintext,      // input plaintext
                                        aadlen, aad,                   // Additional data
                                        infolen, info,                 // Info
                                        0,                             // skE handle
                                        &pkE_len, pkE,                 // pkE
                                        &ciphertext_len, ciphertext ); // ciphertext
        }
        if( ret != 0 )
        {
            mbedtls_printf( "error encrypting (%d)\n", ret );
            goto exit;
        }

        // Write ciphertext
        ret = write_to_file( opt.output_filename, ciphertext_len, ciphertext );

        if( ret != 0 )
        {
            mbedtls_printf( "Error writing pkE to %s\n", opt.output_filename );
            goto exit;
        }

        if( opt.use_pkE_handle != 0 )
        {
            // Export pkE
            status = psa_export_public_key( skE_handle,
                                            pkE,
                                            pkE_len,
                                            &pkE_len
                                          );

            if( status != PSA_SUCCESS )
            {
                return( EXIT_FAILURE );
            }


        }
        // Write ephemeral public key (pkE)
        ret = write_to_file( opt.pkE_filename, pkE_len, pkE );

        if( ret != 0 )
        {
            mbedtls_printf( "Error writing pkE to %s\n", opt.pkE_filename );
            goto exit;
        }

    }
    // Decryption
    else
    {
        uint8_t *pkE = NULL;
        size_t pkE_len = 0;

        // Read skR
        if( opt.skR_filename == NULL )
        {
            goto usage;
        }
        else
        {
             ret = read_from_file( opt.skR_filename, &skR_len, &skR );

            if( ret != 0 )
            {
                mbedtls_printf( "bad skR_filename: %s\n", opt.skR_filename );
                goto usage;
            }

        }

        // Read ciphertext
        if( opt.input_filename == NULL )
        {
            mbedtls_printf( "No ciphertext file (input_filename) provided\n" );
            goto usage;
        }
        else
        {
            ret = read_from_file( opt.input_filename, &ciphertext_len, &ciphertext );

            if( ret != 0 )
            {
                mbedtls_printf( "bad input_filename value: %s\n", opt.input_filename );
                goto usage;
            }
        }

        // Read ephemeral public key (pkE)
        if( opt.pkE_filename == NULL )
        {
            mbedtls_printf( "No ephemeral public key file (pkE_filename) provided\n" );
            goto usage;
        }
        else
        {
            ret = read_from_file( opt.pkE_filename, &pkE_len, &pkE );

            if( ret != 0 )
            {
                mbedtls_printf( "bad pkE_filename value: %s\n", opt.pkE_filename );
                goto usage;
            }
        }

        // Import private key
        switch( opt.hpke_suite.kem_id )
        {
            case HPKE_KEM_ID_P256:
            case HPKE_KEM_ID_P384:
            case HPKE_KEM_ID_P521:
                type = PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 );
                break;
            case HPKE_KEM_ID_25519: // not implemented yet
            case HPKE_KEM_ID_448: // not implemented yet
            default:
                mbedtls_printf( "Unsupported KEM (%d) - exiting\n", opt.hpke_suite.kem_id );
                goto usage;
        }

        // Import private key
        psa_set_key_usage_flags( &attr_private_key, PSA_KEY_USAGE_DERIVE );
        psa_set_key_algorithm( &attr_private_key, PSA_ALG_ECDH );
        psa_set_key_type( &attr_private_key, type );

        status = psa_import_key( &attr_private_key,
                                 skR, skR_len,
                                 &skR_handle );

        if( status != PSA_SUCCESS )
        {
            mbedtls_printf( "Error importing private key (%d) - exiting\n", status );
            ret = (int) status;
            goto exit;
        }

        // Allocate memory for plaintext
        plaintext_len = ciphertext_len;
        plaintext = mbedtls_calloc( 1, plaintext_len );

        if( plaintext == NULL )
        {
            goto exit;
        }

        ret = mbedtls_hpke_decrypt( opt.hpke_mode,               // HPKE mode
                                    opt.hpke_suite,              // ciphersuite
                                    opt.pskid, psklen, psk,      // PSK for authentication
                                    publen, pub,                 // pkS
                                    skR_handle,                  // skR handle
                                    pkE_len,                     // pkE_len
                                    pkE,                         // pkE
                                    ciphertext_len,              // Ciphertext length
                                    ciphertext,                  // Ciphertext
                                    aadlen, aad,                 // Additional data
                                    infolen, info,               // Info
                                    &plaintext_len, plaintext ); // Plaintext

        psa_destroy_key( skR_handle );

        if( ret != 0 )
        {
            mbedtls_printf( "Error decrypting (%d) - exiting\n", ret );
            goto exit;
        }
        
        // Write plaintext
        ret = write_to_file( opt.output_filename, plaintext_len, plaintext );
        
        if( ret != 0 )
        {
            mbedtls_printf( "Error writing %lu bytes of output to %s\n",
                        (unsigned long) plaintext_len, opt.output_filename );
            goto exit;
        }
        
        mbedtls_printf( "Recovered plaintext is %lu octets.\n", (unsigned long) plaintext_len );

        if( pkE != NULL ) mbedtls_free( pkE );
    }

exit:
    if( ciphertext != NULL ) mbedtls_free( ciphertext );
    if( info != NULL ) mbedtls_free( info );
    if( aad != NULL ) mbedtls_free( aad );
    if( psk ) mbedtls_free( psk );
    if( plaintext != NULL ) mbedtls_free( plaintext );
    if( pkR != NULL ) mbedtls_free( pkR );
    if( skR != NULL ) mbedtls_free( skR );

    return( ret );
}

