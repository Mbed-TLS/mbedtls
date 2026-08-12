#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls/ssl_cache.h"
#include "test/certs.h"
#include "fuzz_common.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


#if defined(MBEDTLS_SSL_SRV_C)
const char *pers = "fuzz_server";
static int initialized = 0;
#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
static mbedtls_x509_crt srvcert;
static mbedtls_pk_context pkey;
#endif
const char *alpn_list[3];

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
const unsigned char psk[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
const char psk_id[] = "Client_identity";
#endif
#endif // MBEDTLS_SSL_SRV_C


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    srand(1);
#if defined(MBEDTLS_SSL_SRV_C)
    int ret;
    size_t len;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_TICKET_C)
    mbedtls_ssl_ticket_context ticket_ctx;
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
    /* Per iteration, not static: a cache shared across persistent-mode
     * iterations would make coverage depend on execution order and cost
     * stability. */
    mbedtls_ssl_cache_context cache_ctx;
#endif
    unsigned char buf[4096];
    fuzzBufferOffset_t biomemfuzz;
    uint8_t options;

    //we take 1 byte as options input
    if (Size < 1) {
        return 0;
    }
    options = Data[Size - 1];

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
#endif
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_TICKET_C)
    mbedtls_ssl_ticket_init(&ticket_ctx);
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&cache_ctx);
#endif
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (initialized == 0) {
        alpn_list[0] = "HTTP";
        alpn_list[1] = "fuzzalpn";
        alpn_list[2] = NULL;

        dummy_init();

        initialized = 1;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
    if (mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                               mbedtls_test_srv_crt_len) != 0) {
        goto exit;
    }
    if (mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                               mbedtls_test_cas_pem_len) != 0) {
        goto exit;
    }
    if (mbedtls_pk_parse_key(&pkey, (const unsigned char *) mbedtls_test_srv_key,
                             mbedtls_test_srv_key_len, NULL, 0) != 0) {
        goto exit;
    }
#endif

    if (mbedtls_ssl_config_defaults(&conf,
                                    MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        goto exit;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    if (mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey) != 0) {
        goto exit;
    }
#endif

    mbedtls_ssl_conf_cert_req_ca_list(&conf,
                                      (options &
                                       0x1) ? MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED : MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED);
#if defined(MBEDTLS_SSL_ALPN)
    if (options & 0x2) {
        mbedtls_ssl_conf_alpn_protocols(&conf, alpn_list);
    }
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_TICKET_C)
    if (options & 0x4) {
        if (mbedtls_ssl_ticket_setup(&ticket_ctx, //context
                                     PSA_ALG_GCM, //alg
                                     PSA_KEY_TYPE_AES, //key_type
                                     256, //key_bits
                                     86400) != 0) { //lifetime
            goto exit;
        }

        mbedtls_ssl_conf_session_tickets_cb(&conf,
                                            mbedtls_ssl_ticket_write,
                                            mbedtls_ssl_ticket_parse,
                                            &ticket_ctx);
    }
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
    /* Enabled unconditionally: all 8 bits of the options byte are taken, and
     * widening it would shift every existing corpus entry's payload and flags.
     * Without this, ssl_cache.c is never entered at all. Note that a fresh cache
     * per iteration can only ever miss, so this reaches the lookup and store
     * paths, not a resumption; a real cache hit needs an input carrying two
     * handshakes. */
    mbedtls_ssl_cache_set_max_entries(&cache_ctx, 4);
    mbedtls_ssl_cache_set_timeout(&cache_ctx, 86400);
    mbedtls_ssl_conf_session_cache(&conf, &cache_ctx,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);
#endif
#if defined(MBEDTLS_SSL_EARLY_DATA)
    if (options & 0x8) {
        mbedtls_ssl_conf_early_data(&conf, MBEDTLS_SSL_EARLY_DATA_ENABLED);
    }
#endif
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    mbedtls_ssl_conf_extended_master_secret(&conf,
                                            (options &
                                             0x10) ? MBEDTLS_SSL_EXTENDED_MS_DISABLED : MBEDTLS_SSL_EXTENDED_MS_ENABLED);
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    mbedtls_ssl_conf_encrypt_then_mac(&conf,
                                      (options &
                                       0x20) ? MBEDTLS_SSL_ETM_ENABLED : MBEDTLS_SSL_ETM_DISABLED);
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if (options & 0x40) {
        mbedtls_ssl_conf_psk(&conf, psk, sizeof(psk),
                             (const unsigned char *) psk_id, sizeof(psk_id) - 1);
    }
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation(&conf,
                                   (options &
                                    0x80) ? MBEDTLS_SSL_RENEGOTIATION_ENABLED : MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif

    if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
        goto exit;
    }

    biomemfuzz.Data = Data;
    biomemfuzz.Size = Size-1;
    biomemfuzz.Offset = 0;
    mbedtls_ssl_set_bio(&ssl, &biomemfuzz, dummy_send, fuzz_recv, NULL);

    mbedtls_ssl_session_reset(&ssl);
    ret = mbedtls_ssl_handshake(&ssl);
#if defined(MBEDTLS_SSL_EARLY_DATA)
    while (ret == MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA) {
        mbedtls_ssl_read_early_data(&ssl, buf, sizeof(buf) - 1);
        ret = mbedtls_ssl_handshake(&ssl);
    }
#endif
    if (ret == 0) {
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
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_TICKET_C)
    mbedtls_ssl_ticket_free(&ticket_ctx);
#endif /* MBEDTLS_SSL_SESSION_TICKETS && MBEDTLS_SSL_TICKET_C */
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&cache_ctx);
#endif
    mbedtls_ssl_config_free(&conf);
#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
#endif /* MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_PEM_PARSE_C */
    mbedtls_ssl_free(&ssl);
    mbedtls_psa_crypto_free();
#else /* MBEDTLS_SSL_SRV_C */
    (void) Data;
    (void) Size;
#endif /* MBEDTLS_SSL_SRV_C */

    return 0;
}
