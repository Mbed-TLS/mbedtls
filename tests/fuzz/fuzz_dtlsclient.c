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


static bool initialized = 0;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
static mbedtls_x509_crt cacert;
#endif


const char *pers = "fuzz_dtlsclient";


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
    unsigned char buf[4096];
    fuzzBufferOffset_t biomemfuzz;

    if (initialized == 0) {
#if defined(MBEDTLS_X509_CRT_PARSE_C)
        mbedtls_x509_crt_init( &cacert );
        if (mbedtls_x509_crt_parse( &cacert, (const unsigned char *) mbedtls_test_cas_pem,
                                   mbedtls_test_cas_pem_len ) != 0)
            return 1;
#endif
        initialized = 1;
    }

    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    srandom(1);
    if( mbedtls_ctr_drbg_seed( &ctr_drbg, dummy_entropy, &entropy,
                              (const unsigned char *) pers, strlen( pers ) ) != 0 )
        goto exit;

    if( mbedtls_ssl_config_defaults( &conf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT ) != 0 )
        goto exit;

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
#endif
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_NONE );
    mbedtls_ssl_conf_rng( &conf, dummy_random, &ctr_drbg );

    if( mbedtls_ssl_setup( &ssl, &conf ) != 0 )
        goto exit;

    mbedtls_ssl_set_timer_cb( &ssl, &timer, mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( mbedtls_ssl_set_hostname( &ssl, "localhost" ) != 0 )
        goto exit;
#endif

    biomemfuzz.Data = Data;
    biomemfuzz.Size = Size;
    biomemfuzz.Offset = 0;
    mbedtls_ssl_set_bio( &ssl, &biomemfuzz, dummy_send, fuzz_recv, fuzz_recv_timeout );

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

exit:
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
