#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "fuzz_common.h"
#include "mbedtls/ssl.h"
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#include "mbedtls/timing.h"
#include "test/certs.h"

#if defined(MBEDTLS_SSL_CLI_C) && \
    defined(MBEDTLS_TIMING_C)
static int initialized = 0;
#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
static mbedtls_x509_crt cacert;
#endif

const char *pers = "fuzz_dtlsclient";
#endif
#endif // MBEDTLS_SSL_PROTO_DTLS



int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    srand(1);
    fuzz_watchdog_arm();
#if defined(MBEDTLS_SSL_PROTO_DTLS) && \
    defined(MBEDTLS_SSL_CLI_C) && \
    defined(MBEDTLS_TIMING_C)
    int ret;
    size_t len;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_timing_delay_context timer;
    unsigned char buf[4096];
    fuzzBufferOffset_t biomemfuzz;
    uint8_t options;

    //we take 1 byte as options input
    if (Size < 1) {
        return 0;
    }
    options = Data[Size - 1];

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (initialized == 0) {
#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
        mbedtls_x509_crt_init(&cacert);
        if (mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_test_cas_pem,
                                   mbedtls_test_cas_pem_len) != 0) {
            goto exit;
        }
#endif
        dummy_init();

        initialized = 1;
    }

    if (mbedtls_ssl_config_defaults(&conf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        goto exit;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
#endif
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

    if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
        goto exit;
    }

    mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
    if (mbedtls_ssl_set_hostname(&ssl, "localhost") != 0) {
        goto exit;
    }
#endif

    /* The MTU is the one connection parameter an application is free to choose
     * that the record layer then has to satisfy. mbedtls_ssl_set_mtu()
     * documents an error for values below the record expansion, so every value
     * here is one the library states it handles. 0 means "no limit". */
    mbedtls_ssl_set_mtu(&ssl, options);

    biomemfuzz.Data = Data;
    biomemfuzz.Size = Size-1;
    biomemfuzz.Offset = 0;
    mbedtls_ssl_set_bio(&ssl, &biomemfuzz, dummy_send, fuzz_recv, fuzz_recv_timeout);
    fuzz_watch_input(&ssl);

    ret = mbedtls_ssl_handshake(&ssl);
    if (ret == 0) {
        mbedtls_ssl_session session;
        mbedtls_ssl_session_init(&session);
        if (mbedtls_ssl_get_session(&ssl, &session) == 0) {
            size_t olen1 = 0, olen2 = 0;
            unsigned char *b1, *b2;
            mbedtls_ssl_session_save(&session, NULL, 0, &olen1);
            b1 = malloc(olen1 != 0 ? olen1 : 1);
            b2 = malloc(olen1 != 0 ? olen1 : 1);
            if (b1 != NULL && b2 != NULL &&
                mbedtls_ssl_session_save(&session, b1, olen1, &olen1) == 0) {
                mbedtls_ssl_session session2;
                mbedtls_ssl_session_init(&session2);
                if (mbedtls_ssl_session_load(&session2, b1, olen1) == 0 &&
                    mbedtls_ssl_session_save(&session2, b2, olen1, &olen2) == 0) {
                    if (olen1 != olen2 || memcmp(b1, b2, olen1) != 0) {
                        abort();
                    }
                }
                mbedtls_ssl_session_free(&session2);
            }
            free(b1);
            free(b2);
        }
        mbedtls_ssl_session_free(&session);

        //keep reading data from server until the end
        do {
            len = sizeof(buf) - 1;
            ret = mbedtls_ssl_read(&ssl, buf, len);

            if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                continue;
            } else if (ret <= 0) {
                //EOF or error
                break;
            }
        } while (1);
    }

exit:
    fuzz_watchdog_disarm();
    fuzz_release_input();
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_free(&ssl);
    mbedtls_psa_crypto_free();

#else
    (void) Data;
    (void) Size;
#endif
    return 0;
}
