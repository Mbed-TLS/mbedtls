#include <polarssl/config.h> 
#include "polarssl/platform.h"

#include "polarssl/ecies.h"
#include "polarssl/ecies_envelope.h"

#include "polarssl/pk.h"
#include "polarssl/cipher.h"
#include "polarssl/ecdh.h"
#include "polarssl/md.h"
#include "polarssl/kdf.h"

#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}


/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;


/**
 * This function just returns data from rand().
 * Although predictable and often similar on multiple
 * runs, this does not result in identical random on
 * each run. So do not use this if the results of a
 * test depend on the random data that is generated.
 *
 * rng_state shall be NULL.
 */
static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}


/**
 * This function returns random based on a pseudo random function.
 * This means the results should be identical on all systems.
 * Pseudo random is based on the XTEA encryption algorithm to
 * generate pseudorandom.
 *
 * rng_state shall be a pointer to a rnd_pseudo_info structure.
 */
static int rnd_pseudo_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_pseudo_info *info = (rnd_pseudo_info *) rng_state;
    uint32_t i, *k, sum, delta=0x9E3779B9;
    unsigned char result[4], *out = output;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    k = info->key;

    while( len > 0 )
    {
        size_t use_len = ( len > 4 ) ? 4 : len;
        sum = 0;

        for( i = 0; i < 32; i++ )
        {
            info->v0 += ( ( ( info->v1 << 4 ) ^ ( info->v1 >> 5 ) )
                            + info->v1 ) ^ ( sum + k[sum & 3] );
            sum += delta;
            info->v1 += ( ( ( info->v0 << 4 ) ^ ( info->v0 >> 5 ) )
                            + info->v0 ) ^ ( sum + k[( sum>>11 ) & 3] );
        }

        PUT_UINT32_BE( info->v0, result, 0 );
        memcpy( out, result, use_len );
        len -= use_len;
        out += 4;
    }

    return( 0 );
}

static int unhexify( unsigned char *obuf, const char *ibuf )
{
    unsigned char c, c2;
    int len = strlen( ibuf ) / 2;
    //    assert( strlen( ibuf ) % 2 == 0 ); // must be even number of bytes

    while( *ibuf != 0 )
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
	  printf("Oh no!");
	  //assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
	  //assert( 0 );
	  printf("Oh no!");

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

static void hexify( unsigned char *obuf, const unsigned char *ibuf, int len )
{
    unsigned char l, h;

    while( len != 0 )
    {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}


int main() {
  
  /***************************************************************************************************/
  /* Read public key, message, and private key from file ( Although for now we'll just hard code it) */
  /***************************************************************************************************/

  int id; // Elliptic Curve id for NIST-P256
  ecp_keypair keypair;
  size_t pt_len;

  // Unused public key string: 04c5f875c70b5202f41d76d681e7f112fc81194e9894080825e0ac265d8a9f12f46b273f302117f01122f30cfe34390f62f9e8d2f7b78f0970dda8c11f566b71b9
  char *hex_pubkey_x_string = "c5f875c70b5202f41d76d681e7f112fc81194e9894080825e0ac265d8a9f12f4";
  char *hex_pubkey_y_string = "6b273f302117f01122f30cfe34390f62f9e8d2f7b78f0970dda8c11f566b71b9";
  char *hex_privkey_string = "0656b51aa5546f37e1cac90a073be28ae49c20c005f4eb8b7de95584653c2936";
  char *hex_src_string = "7bd3ea956f4b938ebe83ef9a75ddbda16717e924dd4e45202560bf5f0cffbffcdd23be3ae08ff30503d698ed08568ff6b3f6b9fdc9ea79c8e53a838cc8566a8b52ce7c21b2b067e778925a066c970a6c37b8a6cfc53145f24bf698c352078a7f0409b53196e00c619237454c190b970842bb6629c0def7f166d19565127cbce0"; // the message
  int src_str_len = strlen(hex_src_string)/2;
  unsigned char src_str[src_str_len];
  int encrypted_out_length = 241 + 115;
  unsigned char crypt_output[encrypted_out_length];
  unsigned char encrypted_string[encrypted_out_length*2];

  unsigned char decrypt_output[encrypted_out_length];
  size_t encrypted_olen; // decrypted message length. Should be plaintext length + macsize.

  size_t decrypted_olen; // Decrypted output should be the same as src_string.

  unsigned char decrypted_string[src_str_len];
  rnd_pseudo_info rnd_info_en;
  rnd_pseudo_info rnd_info_de;

  int enc_success, dec_success;

  printf("The input string is:\n");
  printf("%s\n\n", hex_src_string);
  
  id = POLARSSL_ECP_DP_SECP256R1;

  memset(src_str, 0x00, 32);
  pt_len = unhexify( src_str, hex_src_string );  
  memset( &rnd_info_en, 0x00, sizeof( rnd_pseudo_info ) );
  memset( &rnd_info_de, 0x00, sizeof( rnd_pseudo_info ) );
  // Initialize the keypair

  ecp_keypair_init(&keypair);
  ecp_use_known_dp(&keypair.grp, id);
  ecp_point_read_string(&keypair.Q, 16, hex_pubkey_x_string, hex_pubkey_y_string);
  mpi_read_string(&keypair.d, 16, hex_privkey_string);

  /***********************************************************/
  /* Use ECIES to encrypt the message		 	    */
  /***********************************************************/
  // Use null random number generator for now



  enc_success = ecies_encrypt(&keypair, src_str, src_str_len,  crypt_output, &encrypted_olen, sizeof(crypt_output), &rnd_pseudo_rand,  &rnd_info_en);
  hexify(encrypted_string, crypt_output, pt_len);

  printf("Encryption sucess?\n");
  printf("%d\n\n", enc_success);
  
  printf("The encrypted string is: \n");
  printf("%s\n\n", encrypted_string);
  

  /************************************/
  /* Use ECIES to decrypt the message */
  /************************************/

  dec_success = ecies_decrypt(&keypair, crypt_output, sizeof(crypt_output), decrypt_output, &decrypted_olen, sizeof(decrypt_output),&rnd_pseudo_rand, &rnd_info_de);
  /***************************************************************/
  /* Compare the decrypted message to the message read from file */
  /***************************************************************/
  printf("Decryption sucess?\n");
  printf("%d\n\n", dec_success);
  printf("The decrypted string is: \n");
  hexify(decrypted_string, decrypt_output, pt_len);
  printf("%s\n\n", decrypted_string);

  printf("Here is the output: \n");
  printf("%d\n", strcmp((char *) decrypted_string , hex_src_string));
  
}

