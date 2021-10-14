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

#if defined(_WIN32) || defined(_WIN64)
#include "windows_getopt.h"
#else
#include <getopt.h>
#endif

#include <ctype.h>
#include "mbedtls/pk.h"
#include "mbedtls/hpke.h"

/* biggest/default buffer we use */
#define HPKE_MAXSIZE (2*1024)

static int verbose=0; ///< global var for verbosity

static void usage( char *prog, const char *errmsg )
{
    if( errmsg )
    {
        fprintf(stderr,"\nError! %s\n\n",errmsg);
    }
    fprintf(stderr,"HPKE (draft-irtf-cfrg-hpke) tester, options are:\n");
    fprintf(stderr,"Encryption:\n");
    fprintf(stderr,"\tUsage: %s -e -P public [-p private] [-a aad] [-I info] -k pkE \n",prog);
    fprintf(stderr,"\t\t\t-i input -o output\n");
    fprintf(stderr,"\t\t\t[-m mode] [-c suite] [-s psk] [-n pskid]\n");
    fprintf(stderr,"Decryption:\n");
    fprintf(stderr,"\tUsage: %s -d -p private -k pkE [-P public] [-a aad] [-I info]\n",prog);
    fprintf(stderr,"\t\t\t-i input -o output\n");
    fprintf(stderr,"\t\t\t[-m mode] [-c suite] [-s psk] [-n pskid]\n");
    fprintf(stderr,"Options:\n");
    fprintf(stderr,"\t-a additional authenticated data file name or actual value\n");
    fprintf(stderr,"\t-c specify ciphersuite\n");
    fprintf(stderr,"\t-d decrypt\n");
    fprintf(stderr,"\t-e encrypt\n");
    fprintf(stderr,"\t-k ephemeral public key (pkE)\n");
    fprintf(stderr,"\t-h help\n");
    fprintf(stderr,"\t-I additional info to bind to key - file name or actual value\n");
    fprintf(stderr,"\t-i input file name or actual value (stdin if not specified)\n");
    fprintf(stderr,"\t-P public key file name or base64 or ascii-hex encoded value\n");
    fprintf(stderr,"\t-p private key file name or base64 or ascii-hex encoded value\n");
    fprintf(stderr,"\t-m mode (a number or one of: %s,%s,%s or %s)\n",
            HPKE_MODESTR_BASE,HPKE_MODESTR_PSK,HPKE_MODESTR_AUTH,HPKE_MODESTR_PSKAUTH);
    fprintf(stderr,"\t-n PSK id string\n");
    fprintf(stderr,"\t-o output file name (output to stdout if not specified) \n");
    fprintf(stderr,"\t-s psk file name or base64 or ascii-hex encoded value\n");
    fprintf(stderr,"\t-v verbose output\n");
    fprintf(stderr,"\n");
    fprintf(stderr,"Notes:\n");
    fprintf(stderr,"- Sometimes base64 or ascii-hex decoding might work when you\n");
    fprintf(stderr,"  don't want it to (sorry about that;-)\n");
    fprintf(stderr,"- If a PSK mode is used, both pskid \"-n\" and psk \"-s\" MUST\n");
    fprintf(stderr,"  be supplied\n");
    fprintf(stderr,"- For %s or %s modes, provide both public and private keys\n",
            HPKE_MODESTR_AUTH,HPKE_MODESTR_PSKAUTH);
    fprintf(stderr,"- Ciphersuites are specified using a comma-separated list of numbers\n");
    fprintf(stderr,"  e.g. \"-c 0x20,1,3\" or a comma-separated list of strings from:\n");
    fprintf(stderr,"      KEMs: %s, %s, %s, %s or %s\n",
            HPKE_KEMSTR_P256, HPKE_KEMSTR_P384, HPKE_KEMSTR_P521, HPKE_KEMSTR_X25519, HPKE_KEMSTR_X448);
    fprintf(stderr,"      KDFs: %s, %s or %s\n",
            HPKE_KDFSTR_256, HPKE_KDFSTR_384, HPKE_KDFSTR_512);
    fprintf(stderr,"      AEADs: %s, %s or %s\n",
            HPKE_AEADSTR_AES128GCM, HPKE_AEADSTR_AES256GCM, HPKE_AEADSTR_CP);
    fprintf(stderr,"  For example \"-c %s,%s,%s\" (the default)\n",
            HPKE_KEMSTR_X25519, HPKE_KDFSTR_256, HPKE_AEADSTR_AES128GCM);
    if (errmsg==NULL) {
        exit(0);
    } else {
        exit(1);
    }
}

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
        fprintf(stderr, "Can't open (%s) - exiting\n", outp);
        return(EXIT_FAILURE);
    }
#else
    fp = fopen( outp, "wb" );

    if (!fp)
    {
        fprintf(stderr, "Can't open (%s) - exiting\n", outp);
        return(EXIT_FAILURE);
    }
#endif

    frv = fwrite( outbuf, 1, outlen, fp );
    
    if( verbose )
    {
        fprintf(stderr,"wrote %lu bytes to file %s\n",(unsigned long) frv, outp);
    }
    
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
        fprintf(stderr, "Can't open (%s) - exiting\n", inp);
        return(EXIT_FAILURE);
    }
#else
    fp = fopen( inp, "rb" );

    if( !fp )
    {
        fprintf(stderr, "Can't open (%s) - exiting\n", inp);
        return( EXIT_FAILURE );
    }
#endif /* _MSC_VER */

    toutlen = fread( tbuf, 1, HPKE_MAXSIZE, fp );
    
    if( verbose )
    {
        fprintf( stderr, "got %lu bytes from file %s\n", (unsigned long) toutlen, inp );
    }

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
        if (verbose) fprintf(stderr,"got %lu bytes from stdin\n",(unsigned long)toutlen);
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
            if (verbose) fprintf(stderr,"got %lu bytes from file %s\n",(unsigned long)toutlen,inp);
            if (ferror(fp)) { fclose(fp); return(__LINE__); }
            fclose(fp);
        } else {
            if (verbose) fprintf(stderr,"got %lu bytes direct from command line %s\n",
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
                if (verbose) fprintf(stderr,"ah_decode worked for %s - going with that\n",tbuf);
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
                if (verbose) 
                    fprintf(stderr,"base64 decode ok for %s - using the %lu bytes that provided\n",
                                tbuf,(unsigned long)*outlen);
                return(1);
            } else {
                /* base64 decode failed so maybe the content was good as-is */
                mbedtls_free(*outbuf);
                *outbuf=NULL;
            }
        }
        if (verbose) fprintf(stderr,"decodes failed for %s - going with original\n",tbuf);
    } else {
        if (verbose>1) fprintf(stderr,"going with original: %s\n",tbuf);
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

/*!
 * \brief Example application demonstrating the use of HPKE encryption and decryption.
 * 
 * To encrypt and decrypt messages using this HPKE application the following steps are necessary. 
 * 
 * (A) Encryption
 * 
 * A.1. Create a private key
 * A.2. Convert the key into a format understood by the HPKE example application
 *      (which uses the PSA Crypto API)
 * A.3. Invoke the HPKE example application
 * 
 * 
 * A.1. Create a private key
 * 
 * It is necessary to create a public/private key pair for use by the recipient 
 * (called pkR and skR in the HPKE spec). The command to generate a private key using the 
 * OpenSSL tools with ECC with the NIST P256r1. Then, put the private key in the skR.pem file
 * (in a PEM encoding).
 * 
 * > openssl ecparam -name prime256v1 -genkey -noout -out skR.pem
 * 
 * A.2. Convert key
 * 
 * We need to convert the key from the PEM format into the raw key format required by the 
 * example program. We use the key_writer utility to create two files, one for the public 
 * key and another one for the private key. The public key will be used for encryption by 
 * the sender and the private key by the recipient (obviously) for decryption. 
 * The key_writer program is a separate utility, which can be found here: 
 * https://github.com/hannestschofenig/key_writer
 * 
 * Once compiled, create pkR and skR using the following commands:
 * 
 * > key_writer mode=private filename=skR.pem output_mode=public output_file=pkR.bin output_format=bin
 * > key_writer mode=private filename=skR.pem output_mode=private output_file=skR.bin output_format=bin
 *
 * A.3. Encrypt plaintext
 * 
 * Finally, we invoke the HPKE example application to encrypt data. The sender uses several command 
 * line arguments to pass the following information in, namely:
 *
 *  - Public key of the recipient (pkR)
 *  - Plaintext
 *  - Ciphersuite information
 *  - Authentication mode
 * 
 * As a result, the following output is produced:
 * 
 *  - Ciphertext
 *  - Ephemeral public key (pkE)
 * 
 * > echo "Hello World!" > hello.txt
 * > hpke_example -e -P pkR.bin -i hello.txt -k pkE.bin -o ciphertext -v -m base -c 0x10,1,1
 * 
 * Note: The parameter -c 0x10,1,1 refers to the following ciphersuite combination:
 *
 *  - KEM: P256
 *  - KDF: HKDF-SHA256
 *  - AEADs: AES-128-GCM
 * 
 * Normally, the sender would then transmit the ciphertext, and the pkE to the recipient.
 * We assume that the authentication mode and the ciphersuite are known to both parties a
 * priori or negotiated.
 * 
 * (B) Decryption
 * 
 * Now, we invoke the HPKE example application to decrypt the ciphertext.
 * The recipient takes the input together with its private key (skR) and re-creates the 
 * plaintext as follows: 
 * 
 * > hpke_example -d -p skR.bin -v -m base -c 0x10,1,1 -k pkE.bin -i ciphertext -o plaintext
 * 
 * If everything was configured correctly, then the recipient obtains the plaintext. 
 *
 */
int main(int argc, char **argv)
{
    // PSA-based Variable
    psa_status_t status;
    int ret;

    int doing_enc = -1;
    char *pkE_filename=NULL;
    char *pkR_filename=NULL;
    char *skR_filename=NULL;
    char *aad_in=NULL;
    char *info_in=NULL;
    char *input_filename=NULL;
    char *output_filename=NULL;
    char *modestr=NULL;
    char *pskid=NULL;
    char *psk_in=NULL;
    char *suitestr=NULL;

    /* Buffers */
    uint8_t *pkR = NULL;
    size_t pkR_len;

    uint8_t *plaintext = NULL;
    size_t plaintext_len;

    uint8_t *ciphertext = NULL;
    size_t ciphertext_len;

    // Variables for use with private key import
    psa_key_handle_t skR_handle = 0;
    psa_key_type_t type;
    psa_key_attributes_t attr_private_key = PSA_KEY_ATTRIBUTES_INIT;

    size_t publen=0; unsigned char *pub=NULL;
    size_t skR_len=0; unsigned char *skR=NULL;
    size_t aadlen=0; unsigned char *aad=NULL;
    size_t infolen=0; unsigned char *info=NULL;
    size_t psklen=0; unsigned char *psk=NULL;

    int hpke_mode=HPKE_MODE_BASE;
    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;
    int opt;
    
    while((opt = getopt(argc, argv, "?c:ghedvP:p:a:I:i:m:n:k:o:s:")) != -1) 
    {
        switch(opt) {
            case '?': usage(argv[0], ("Unexpected option") ); break;
            case 'a': aad_in=optarg; break;
            case 'c': suitestr=optarg; break;
            case 'd': doing_enc=0; break;
            case 'e': doing_enc=1; break;
            case 'h': usage(argv[0],NULL); break;
            case 'I': info_in=optarg; break;
            case 'i': input_filename=optarg; break;
            case 'm': modestr=optarg; break;
            case 'n': pskid=optarg; break;
            case 'o': output_filename=optarg; break;
            case 'P': pkR_filename=optarg; break;
            case 'k': pkE_filename=optarg; break;
            case 'p': skR_filename=optarg; break;
            case 's': psk_in=optarg; break;
            case 'v': verbose++; break;
            default:
                usage(argv[0],"unknown arg");
        }
    }

    // check command line args
    if (modestr!=NULL) {
        if (strlen(modestr)==strlen(HPKE_MODESTR_BASE) && 
                !strncmp(modestr,HPKE_MODESTR_BASE,strlen(HPKE_MODESTR_BASE))) {
            hpke_mode=HPKE_MODE_BASE;
        } else if (strlen(modestr)==strlen(HPKE_MODESTR_PSK) && 
                !strncmp(modestr,HPKE_MODESTR_PSK,strlen(HPKE_MODESTR_PSK))) {
            hpke_mode=HPKE_MODE_PSK;
        } else if (strlen(modestr)==strlen(HPKE_MODESTR_AUTH) && 
                !strncmp(modestr,HPKE_MODESTR_AUTH,strlen(HPKE_MODESTR_AUTH))) {
            hpke_mode=HPKE_MODE_AUTH;
        } else if (strlen(modestr)==strlen(HPKE_MODESTR_PSKAUTH) && 
                !strncmp(modestr,HPKE_MODESTR_PSKAUTH,strlen(HPKE_MODESTR_PSKAUTH))) {
            hpke_mode=HPKE_MODE_PSKAUTH;
        } else if (strlen(modestr)==1) {
            switch(modestr[0]) {
                case '0': hpke_mode=HPKE_MODE_BASE; break;
                case '1': hpke_mode=HPKE_MODE_PSK; break;
                case '2': hpke_mode=HPKE_MODE_AUTH; break;
                case '3': hpke_mode=HPKE_MODE_PSKAUTH; break;
                default: usage(argv[0],"unnkown mode");
            }
        } else {
            usage(argv[0],"unkown mode");
        }
    }

    // Check encryption/decryption
    if( doing_enc == -1)
    {
        usage(argv[0],"missing -d or -e configuration setting");
    }
    // Check ciphersuit
    if( suitestr )
    {
        if( verbose )
        {
            fprintf( stderr, "Using ciphersuite %s\n", suitestr );
        }

        if (hpke_str2suite(suitestr,&hpke_suite)!=1)
        {
            usage(argv[0],"Bad ciphersuite string");
        }
    }

    if( aad_in && map_input( aad_in, &aadlen, &aad, 1 ) !=1 ) usage( argv[0], "bad -a value" );
    if( info_in && map_input( info_in, &infolen, &info, 1 ) !=1 ) usage( argv[0], "bad -I value" );

    // Initialize the PSA
    status = psa_crypto_init( );

    if ( status != PSA_SUCCESS )
    {
        fprintf( stderr, "Unable to initialize crypto (%d) - exiting\n", status );
        return( EXIT_FAILURE );
    }

    /* Encryption */
    if( doing_enc == 1 )
    {
        size_t pkE_len = PSA_EXPORT_PUBLIC_KEY_MAX_SIZE;
        uint8_t pkE[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = {0};

        if( psk_in && map_input( psk_in, &psklen, &psk, 1 ) !=1 ) usage( argv[0], "bad -s value" );

        // Load pkR
        if( doing_enc && !pkR_filename ) usage( argv[0], "No recipient public key (\"-P\") provided" );

        if( pkR_filename != NULL )
        {
            ret = read_from_file( pkR_filename, &pkR_len, &pkR );

            if( ret != 0 )
            {
                if( verbose ) fprintf( stderr, "bad -P value: %s\n", pkR_filename );
                return( EXIT_FAILURE );
            }
        }

        // Load plaintext
        if( doing_enc && !input_filename ) usage( argv[0], "No plaintext file (\"-i\") provided" );

        if( input_filename != NULL )
        {
            ret = read_from_file( input_filename, &plaintext_len, &plaintext );

            if( ret != 0 )
            {
                if( verbose ) fprintf( stderr, "bad -i value: %s\n", input_filename );
                return( EXIT_FAILURE );
            }
        }

        // Allocate memory for ciphertext
        ciphertext_len = PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE( plaintext_len );
        ciphertext = mbedtls_calloc( 1, ciphertext_len );

        if( ciphertext == NULL )
        {
            return( EXIT_FAILURE );
        }

        ret = mbedtls_hpke_encrypt( hpke_mode,                     // HPKE mode
                                    hpke_suite,                    // ciphersuite
                                    pskid, psklen, psk,            // PSK
                                    pkR_len, pkR,                  // pkR
                                    0,                             // skI
                                    plaintext_len, plaintext,      // input plaintext
                                    aadlen, aad,                   // Additional data
                                    infolen, info,                 // Info
                                    NULL,                          // skE
                                    &pkE_len, pkE,                 // pkE
                                    &ciphertext_len, ciphertext ); // ciphertext

        if( ret != 0 )
        {
            fprintf( stderr, "Error encrypting (%d) - exiting\n", ret );
            exit( ret );
        }

        // Write ciphertext
        ret = write_to_file( output_filename, ciphertext_len, ciphertext );

        if( ret != 0 )
        {
            if( verbose ) fprintf( stderr, "Error writing pkE to %s\n", output_filename );
            return( EXIT_FAILURE );
        }

        // Write ephemeral public key (pkE)
        ret = write_to_file( pkE_filename, pkE_len, pkE );

        if( ret != 0 )
        {
            if( verbose ) fprintf( stderr, "Error writing pkE to %s\n", pkE_filename );
            return( EXIT_FAILURE );
        }

        if( plaintext != NULL) mbedtls_free( plaintext );
        if( pkR != NULL) mbedtls_free( pkR );
        if( ciphertext != NULL) mbedtls_free( ciphertext );
    }
    /* Decryption */
    else
    {
        uint8_t *pkE = NULL;
        size_t pkE_len;

        // Read skR
        if( skR_filename == NULL )
        {
            usage( argv[0], "No private key (\"-p\") provided" );
        }
        else
        {
             ret = read_from_file( skR_filename, &skR_len, &skR );

            if( ret != 0 )
            {
                if( verbose ) fprintf( stderr, "bad -p value: %s\n", skR_filename );
                return( EXIT_FAILURE );
            }

        }

        // Read ciphertext
        if( input_filename == NULL )
        {
            usage( argv[0], "No ciphertext file (\"-i\") provided" );
        }
        else
        {
            ret = read_from_file( input_filename, &ciphertext_len, &ciphertext );

            if( ret != 0 )
            {
                if( verbose ) fprintf( stderr, "bad -i value: %s\n", input_filename );
                return( EXIT_FAILURE );
            }
        }

        // Read ephemeral public key (pkE)
        if( pkE_filename == NULL )
        {
            usage( argv[0], "No ephemeral public key file (\"-k\") provided" );
        }
        else
        {
            ret = read_from_file( pkE_filename, &pkE_len, &pkE );

            if( ret != 0 )
            {
                if( verbose ) fprintf( stderr, "bad -i value: %s\n", pkE_filename );
                return( EXIT_FAILURE );
            }
        }

        /* Import private key */
        switch( hpke_suite.kem_id )
        {
            case HPKE_KEM_ID_P256:
            case HPKE_KEM_ID_P384:
            case HPKE_KEM_ID_P521:
                type = PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 );
                break;
            case HPKE_KEM_ID_25519: // not implemented yet
            case HPKE_KEM_ID_448: // not implemented yet
            default:
                fprintf( stderr, "Unsupported KEM (%d) - exiting\n", hpke_suite.kem_id );
                return( EXIT_FAILURE );
        }

        /* Import private key */
        psa_set_key_usage_flags( &attr_private_key, PSA_KEY_USAGE_DERIVE );
        psa_set_key_algorithm( &attr_private_key, PSA_ALG_ECDH );
        psa_set_key_type( &attr_private_key, type );

        status = psa_import_key( &attr_private_key,
                                 skR, skR_len,
                                 &skR_handle );

        if( status != PSA_SUCCESS )
        {
            fprintf( stderr, "Error importing private key (%d) - exiting\n", status );
            return( status );
        }


        // Allocate memory for plaintext
        plaintext_len = ciphertext_len;
        plaintext = mbedtls_calloc( 1, plaintext_len );

        if( plaintext == NULL )
        {
            return( EXIT_FAILURE );
        }

        ret = mbedtls_hpke_decrypt( hpke_mode,                   // HPKE mode
                                    hpke_suite,                  // ciphersuite
                                    pskid, psklen, psk,          // PSK for authentication
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
            fprintf( stderr, "Error decrypting (%d) - exiting\n", ret );
            exit( ret );
        }
        
        // Write plaintext
        ret = write_to_file( output_filename, plaintext_len, plaintext );
        
        if( ret != 0 )
        {
            fprintf( stderr, "Error writing %lu bytes of output to %s\n",
                        (unsigned long) plaintext_len, output_filename );
            exit( ret );
        }
        
        fprintf( stdout, "All worked: Recovered plain is %lu octets.\n", (unsigned long) plaintext_len );

        if( skR != NULL ) mbedtls_free( skR );
        if( ciphertext != NULL ) mbedtls_free( ciphertext );
        if( pkE != NULL ) mbedtls_free( pkE );
        if( plaintext != NULL ) mbedtls_free ( plaintext );
    }
    
    if( info != NULL ) mbedtls_free( info );
    if( aad != NULL ) mbedtls_free( aad );
    if( psk ) mbedtls_free( psk );

    return( 0 );
}

