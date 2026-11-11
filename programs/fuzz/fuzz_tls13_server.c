#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "psa/crypto.h"
#include "test/certs.h"
#include "common.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_CTR_DRBG_C)
static int initialized = 0;
#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
static mbedtls_x509_crt srvcert;
static mbedtls_x509_crt cacert;
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

const char *pers = "fuzz_tls13_server";

static unsigned char fuzz_nv_seed[MBEDTLS_ENTROPY_BLOCK_SIZE];

static int fuzz_nv_seed_read(unsigned char *buf, size_t buf_len)
{
    if (buf_len > sizeof(fuzz_nv_seed)) {
        return -1;
    }
    memcpy(buf, fuzz_nv_seed, buf_len);
    return 0;
}

static int fuzz_nv_seed_write(unsigned char *buf, size_t buf_len)
{
    if (buf_len > sizeof(fuzz_nv_seed)) {
        return -1;
    }
    memcpy(fuzz_nv_seed, buf, buf_len);
    return 0;
}

static void fuzz_psa_init(void)
{
#if defined(MBEDTLS_ENTROPY_NV_SEED) && defined(MBEDTLS_PLATFORM_NV_SEED_ALT)
    mbedtls_platform_set_nv_seed(fuzz_nv_seed_read, fuzz_nv_seed_write);
#endif
    {
        psa_status_t st = psa_crypto_init();
        (void) st;
    }
}
#endif /* SRV && ENTROPY && CTR_DRBG */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_CTR_DRBG_C)
    int ret;
    size_t len;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ssl_ticket_context ticket_ctx;
    unsigned char buf[4096];
    fuzzBufferOffset_t biomemfuzz;
    uint8_t options;
#if defined(MBEDTLS_ECP_C)
    /* must outlive the ssl_config: mbedtls_ssl_conf_groups stores the pointer */
    uint16_t p256_only_groups[2];
#endif

    if (initialized == 0) {
#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
        mbedtls_x509_crt_init(&srvcert);
        mbedtls_x509_crt_init(&cacert);
        mbedtls_pk_init(&pkey);
        if (mbedtls_x509_crt_parse(&srvcert,
                                   (const unsigned char *) mbedtls_test_srv_crt,
                                   mbedtls_test_srv_crt_len) != 0) {
            return 1;
        }
        if (mbedtls_x509_crt_parse(&cacert,
                                   (const unsigned char *) mbedtls_test_cas_pem,
                                   mbedtls_test_cas_pem_len) != 0) {
            return 1;
        }
        if (mbedtls_pk_parse_key(&pkey,
                                 (const unsigned char *) mbedtls_test_srv_key,
                                 mbedtls_test_srv_key_len, NULL, 0,
                                 dummy_random, NULL) != 0) {
            return 1;
        }
#endif

        alpn_list[0] = "HTTP";
        alpn_list[1] = "fuzzalpn13";
        alpn_list[2] = NULL;

        dummy_init();

        initialized = 1;
    }

    if (Size < 2) {
        return 0;
    }
    options = Data[Size - 1];

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ssl_ticket_init(&ticket_ctx);

#if defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_SSL_PROTO_TLS1_3)
    fuzz_psa_init();
#endif

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, dummy_entropy, &entropy,
                              (const unsigned char *) pers,
                              strlen(pers)) != 0) {
        goto exit;
    }

    if (mbedtls_ssl_config_defaults(&conf,
                                    MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        goto exit;
    }

    srand(1);
    mbedtls_ssl_conf_rng(&conf, dummy_random, &ctr_drbg);

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (options & 0x20) {
        mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    } else {
        mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);
    }
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    if (mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey) != 0) {
        goto exit;
    }
#endif

#if defined(MBEDTLS_SSL_ALPN)
    if (options & 0x04) {
        mbedtls_ssl_conf_alpn_protocols(&conf, alpn_list);
    }
#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_TICKET_C)
    if (options & 0x02) {
        if (mbedtls_ssl_ticket_setup(&ticket_ctx,
                                     dummy_random, &ctr_drbg,
                                     MBEDTLS_CIPHER_AES_256_GCM,
                                     86400) != 0) {
            goto exit;
        }
        mbedtls_ssl_conf_session_tickets_cb(&conf,
                                            mbedtls_ssl_ticket_write,
                                            mbedtls_ssl_ticket_parse,
                                            &ticket_ctx);
    }
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if (options & 0x01) {
        mbedtls_ssl_conf_psk(&conf, psk, sizeof(psk),
                             (const unsigned char *) psk_id,
                             sizeof(psk_id) - 1);
    }
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_conf_authmode(&conf,
                              (options & 0x10) ? MBEDTLS_SSL_VERIFY_REQUIRED
                                               : MBEDTLS_SSL_VERIFY_NONE);
#endif

#if defined(MBEDTLS_ECP_C)
    if (options & 0x08) {
        /* P-256-only: forces HelloRetryRequest against x25519 key shares */
        p256_only_groups[0] = 23; /* secp256r1 IANA id */
        p256_only_groups[1] = 0;  /* terminator */
        mbedtls_ssl_conf_groups(&conf, p256_only_groups);
    }
#endif

    if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
        goto exit;
    }

    biomemfuzz.Data = Data;
    biomemfuzz.Size = Size - 1;
    biomemfuzz.Offset = 0;
    mbedtls_ssl_set_bio(&ssl, &biomemfuzz, dummy_send, fuzz_recv, NULL);

    mbedtls_ssl_session_reset(&ssl);
    ret = mbedtls_ssl_handshake(&ssl);
    if (ret == 0) {
        do {
            len = sizeof(buf) - 1;
            ret = mbedtls_ssl_read(&ssl, buf, len);

            if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                continue;
            } else if (ret <= 0) {
                break;
            }
        } while (1);
    }

exit:
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_TICKET_C)
    mbedtls_ssl_ticket_free(&ticket_ctx);
#endif
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_free(&ssl);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_psa_crypto_free();
#endif
#else
    (void) Data;
    (void) Size;
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */

    return 0;
}
