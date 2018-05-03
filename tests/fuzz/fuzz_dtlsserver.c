#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "mbedtls/ssl.h"
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/timing.h"
#include "mbedtls/ssl_cookie.h"


const char *pers = "fuzz_dtlsserver";
const unsigned char client_ip[4] = {0x7F, 0, 0, 1};
static bool initialized = 0;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
static mbedtls_x509_crt srvcert;
static mbedtls_pk_context pkey;
#endif

typedef struct fuzzBufferOffset
{
    const uint8_t *Data;
    size_t Size;
    size_t Offset;
} fuzzBufferOffset_t;


static int dummy_send( void *ctx, const unsigned char *buf, size_t len )
{
    //silence warning about unused parameter
    (void) ctx;
    (void) buf;

    //pretends we wrote everything ok
    return( len );
}

static int fuzz_recv( void *ctx, unsigned char *buf, size_t len )
{
    //reads from the buffer from fuzzer
    fuzzBufferOffset_t * biomemfuzz = (fuzzBufferOffset_t *) ctx;

    if (biomemfuzz->Offset == biomemfuzz->Size) {
        //EOF
        return (0);
    }
    if (len + biomemfuzz->Offset > biomemfuzz->Size) {
        //do not overflow
        len = biomemfuzz->Size - biomemfuzz->Offset;
    }
    memcpy(buf, biomemfuzz->Data + biomemfuzz->Offset, len);
    biomemfuzz->Offset += len;
    return( len );
}

static int fuzz_recv_timeout( void *ctx, unsigned char *buf, size_t len,
                      uint32_t timeout )
{
    (void) timeout;

    return fuzz_recv(ctx, buf, len);
}

static int dummy_random( void *p_rng, unsigned char *output, size_t output_len )
{
    int ret;
    size_t i;

    //use mbedtls_ctr_drbg_random to find bugs in it
    ret = mbedtls_ctr_drbg_random(p_rng, output, output_len);
    for (i=0; i<output_len; i++) {
        //replace result with pseudo random
        output[i] = (unsigned char) random();
    }
    return( ret );
}

static int dummy_entropy( void *data, unsigned char *output, size_t len )
{
    int ret;
    size_t i;

    //use mbedtls_entropy_func to find bugs in it
    ret = mbedtls_entropy_func(data, output, len);
    for (i=0; i<len; i++) {
        //replace result with pseudo random
        output[i] = (unsigned char) random();
    }
    return( ret );
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    int ret;
    size_t len;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_timing_delay_context timer;
    mbedtls_ssl_cookie_ctx cookie_ctx;
    unsigned char buf[4096];
    fuzzBufferOffset_t biomemfuzz;

    if (initialized == 0) {
#if defined(MBEDTLS_X509_CRT_PARSE_C)
        mbedtls_x509_crt_init( &srvcert );
        mbedtls_pk_init( &pkey );
        if (mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                                   mbedtls_test_srv_crt_len ) != 0)
            return 1;
        if (mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                                   mbedtls_test_cas_pem_len ) != 0)
            return 1;
        if (mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key,
                                 mbedtls_test_srv_key_len, NULL, 0 ) != 0)
            return 1;
#endif
        initialized = 1;
    }
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_ssl_cookie_init( &cookie_ctx );

    if( mbedtls_ctr_drbg_seed( &ctr_drbg, dummy_entropy, &entropy,
                              (const unsigned char *) pers, strlen( pers ) ) != 0 )
        goto exit;


    if( mbedtls_ssl_config_defaults( &conf,
                                    MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT ) != 0 )
        goto exit;


    srandom(1);
    mbedtls_ssl_conf_rng( &conf, dummy_random, &ctr_drbg );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
    if( mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) != 0 )
        goto exit;
#endif

    if( mbedtls_ssl_cookie_setup( &cookie_ctx, dummy_random, &ctr_drbg ) != 0 )
        goto exit;

    mbedtls_ssl_conf_dtls_cookies( &conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &cookie_ctx );

    if( mbedtls_ssl_setup( &ssl, &conf ) != 0 )
        goto exit;

    mbedtls_ssl_set_timer_cb( &ssl, &timer, mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay );

    biomemfuzz.Data = Data;
    biomemfuzz.Size = Size;
    biomemfuzz.Offset = 0;
    mbedtls_ssl_set_bio( &ssl, &biomemfuzz, dummy_send, fuzz_recv, fuzz_recv_timeout );
    if( mbedtls_ssl_set_client_transport_id( &ssl, client_ip, sizeof(client_ip) ) != 0 )
        goto exit;

    ret = mbedtls_ssl_handshake( &ssl );

    if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
        biomemfuzz.Offset = ssl.next_record_offset;
        mbedtls_ssl_session_reset( &ssl );
        mbedtls_ssl_set_bio( &ssl, &biomemfuzz, dummy_send, fuzz_recv, fuzz_recv_timeout );
        if( mbedtls_ssl_set_client_transport_id( &ssl, client_ip, sizeof(client_ip) ) != 0 )
            goto exit;

        ret = mbedtls_ssl_handshake( &ssl );

        if( ret == 0 )
        {
            //keep reading data from server until the end
            do
            {
                len = sizeof( buf ) - 1;
                ret = mbedtls_ssl_read( &ssl, buf, len );
                if( ret == MBEDTLS_ERR_SSL_WANT_READ )
                    continue;
                else if( ret <= 0 )
                    //EOF or error
                    break;
            }
            while( 1 );
        }
    }

exit:
    mbedtls_ssl_cookie_free( &cookie_ctx );
    mbedtls_entropy_free( &entropy );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ssl_free( &ssl );

#else
    (void) Data;
    (void) Size;
#endif
    return 0;
}
