/*
 *  Diffie-Hellman-Merkle key exchange (client side)
 *
 *  Copyright (C) 2006-2010, Paul Bakker <polarssl_maintainer at polarssl.org>
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>

#include "polarssl/net.h"
#include "polarssl/aes.h"
#include "polarssl/dhm.h"
#include "polarssl/rsa.h"
#include "polarssl/sha1.h"
#include "polarssl/havege.h"

#define SERVER_NAME "localhost"
#define SERVER_PORT 11999

int main( void )
{
    FILE *f;

    int ret, n, buflen;
    int server_fd = -1;

    unsigned char *p, *end;
    unsigned char buf[1024];
    unsigned char hash[20];

    havege_state hs;
    rsa_context rsa;
    dhm_context dhm;
    aes_context aes;

    memset( &rsa, 0, sizeof( rsa ) );
    memset( &dhm, 0, sizeof( dhm ) );

    /*
     * 1. Setup the RNG
     */
    printf( "\n  . Seeding the random number generator" );
    fflush( stdout );

    havege_init( &hs );

    /*
     * 2. Read the server's public RSA key
     */
    printf( "\n  . Reading public key from rsa_pub.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_pub.txt", "rb" ) ) == NULL )
    {
        ret = 1;
        printf( " failed\n  ! Could not open rsa_pub.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    rsa_init( &rsa, RSA_PKCS_V15, 0, NULL, NULL );

    if( ( ret = mpi_read_file( &rsa.N, 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.E, 16, f ) ) != 0 )
    {
        printf( " failed\n  ! mpi_read_file returned %d\n\n", ret );
        goto exit;
    }

    rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;

    fclose( f );

    /*
     * 3. Initiate the connection
     */
    printf( "\n  . Connecting to tcp/%s/%d", SERVER_NAME,
                                             SERVER_PORT );
    fflush( stdout );

    if( ( ret = net_connect( &server_fd, SERVER_NAME,
                                         SERVER_PORT ) ) != 0 )
    {
        printf( " failed\n  ! net_connect returned %d\n\n", ret );
        goto exit;
    }

    /*
     * 4a. First get the buffer length
     */
    printf( "\n  . Receiving the server's DH parameters" );
    fflush( stdout );

    memset( buf, 0, sizeof( buf ) );

    if( ( ret = net_recv( &server_fd, buf, 2 ) ) != 2 )
    {
        printf( " failed\n  ! net_recv returned %d\n\n", ret );
        goto exit;
    }

    n = buflen = ( buf[0] << 8 ) | buf[1];
    if( buflen < 1 || buflen > (int) sizeof( buf ) )
    {
        printf( " failed\n  ! Got an invalid buffer length\n\n" );
        goto exit;
    }

    /*
     * 4b. Get the DHM parameters: P, G and Ys = G^Xs mod P
     */
    memset( buf, 0, sizeof( buf ) );

    if( ( ret = net_recv( &server_fd, buf, n ) ) != n )
    {
        printf( " failed\n  ! net_recv returned %d\n\n", ret );
        goto exit;
    }

    p = buf, end = buf + buflen;

    if( ( ret = dhm_read_params( &dhm, &p, end ) ) != 0 )
    {
        printf( " failed\n  ! dhm_read_params returned %d\n\n", ret );
        goto exit;
    }

    if( dhm.len < 64 || dhm.len > 256 )
    {
        ret = 1;
        printf( " failed\n  ! Invalid DHM modulus size\n\n" );
        goto exit;
    }

    /*
     * 5. Check that the server's RSA signature matches
     *    the SHA-1 hash of (P,G,Ys)
     */
    printf( "\n  . Verifying the server's RSA signature" );
    fflush( stdout );

    if( ( n = (int)( end - p ) ) != rsa.len )
    {
        ret = 1;
        printf( " failed\n  ! Invalid RSA signature size\n\n" );
        goto exit;
    }

    sha1( buf, (int)( p - 2 - buf ), hash );

    if( ( ret = rsa_pkcs1_verify( &rsa, RSA_PUBLIC, SIG_RSA_SHA1,
                                  0, hash, p ) ) != 0 )
    {
        printf( " failed\n  ! rsa_pkcs1_verify returned %d\n\n", ret );
        goto exit;
    }

    /*
     * 6. Send our public value: Yc = G ^ Xc mod P
     */
    printf( "\n  . Sending own public value to server" );
    fflush( stdout );

    n = dhm.len;
    if( ( ret = dhm_make_public( &dhm, 256, buf, n,
                                 havege_rand, &hs ) ) != 0 )
    {
        printf( " failed\n  ! dhm_make_public returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = net_send( &server_fd, buf, n ) ) != n )
    {
        printf( " failed\n  ! net_send returned %d\n\n", ret );
        goto exit;
    }

    /*
     * 7. Derive the shared secret: K = Ys ^ Xc mod P
     */
    printf( "\n  . Shared secret: " );
    fflush( stdout );

    n = dhm.len;
    if( ( ret = dhm_calc_secret( &dhm, buf, &n ) ) != 0 )
    {
        printf( " failed\n  ! dhm_calc_secret returned %d\n\n", ret );
        goto exit;
    }

    for( n = 0; n < 16; n++ )
        printf( "%02x", buf[n] );

    /*
     * 8. Setup the AES-256 decryption key
     *
     * This is an overly simplified example; best practice is
     * to hash the shared secret with a random value to derive
     * the keying material for the encryption/decryption keys,
     * IVs and MACs.
     */
    printf( "...\n  . Receiving and decrypting the ciphertext" );
    fflush( stdout );

    aes_setkey_dec( &aes, buf, 256 );

    memset( buf, 0, sizeof( buf ) );

    if( ( ret = net_recv( &server_fd, buf, 16 ) ) != 16 )
    {
        printf( " failed\n  ! net_recv returned %d\n\n", ret );
        goto exit;
    }

    aes_crypt_ecb( &aes, AES_DECRYPT, buf, buf );
    buf[16] = '\0';
    printf( "\n  . Plaintext is \"%s\"\n\n", (char *) buf );

exit:

    net_close( server_fd );
    rsa_free( &rsa );
    dhm_free( &dhm );

#ifdef WIN32
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
