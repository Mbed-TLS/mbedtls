#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/ssl.h"
#include "fuzz_common.h"

#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) && \
    defined(MBEDTLS_SSL_PROTO_DTLS) && \
    defined(MBEDTLS_SSL_CLI_C)

#if defined(MBEDTLS_SSL_ALPN)
/* A configured ALPN list is a precondition for the alpn_chosen restore loop in
 * ssl_context_load(): with conf->alpn_list NULL the loop is skipped entirely.
 * The names differ in length so a blob's alpn_len can match one and not another. */
static const char *ctx_alpn_list[3];
#endif

/* Serialize `ssl`, sizing the buffer from the library. Returns the blob, or
 * NULL if the context cannot be serialized. On success the context is reset,
 * which is what mbedtls_ssl_context_save() does to it. */
static unsigned char *context_save_alloc(mbedtls_ssl_context *ssl, size_t *olen)
{
    unsigned char *buf;
    size_t needed = 0;
    int ret;

    ret = mbedtls_ssl_context_save(ssl, NULL, 0, &needed);
    if (ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA) {
        /* The load side accepted a context the save side refuses to emit. The
         * two are documented as inverses, so the accepted value could never
         * have come from a genuine save. */
        abort();
    }
    if (ret != MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL || needed == 0) {
        return NULL;
    }
    buf = malloc(needed);
    if (buf == NULL) {
        return NULL;
    }
    if (mbedtls_ssl_context_save(ssl, buf, needed, olen) != 0) {
        free(buf);
        return NULL;
    }
    return buf;
}

/* Configure and set up an already-initialised pair. */
static int context_setup(mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf)
{
    if (mbedtls_ssl_config_defaults(conf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        return -1;
    }
#if defined(MBEDTLS_SSL_ALPN)
    if (mbedtls_ssl_conf_alpn_protocols(conf, ctx_alpn_list) != 0) {
        return -1;
    }
#endif
    return mbedtls_ssl_setup(ssl, conf);
}
#endif /* MBEDTLS_SSL_CONTEXT_SERIALIZATION && ... */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    srand(1);
    fuzz_watchdog_arm();
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) && \
    defined(MBEDTLS_SSL_PROTO_DTLS) && \
    defined(MBEDTLS_SSL_CLI_C)
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    unsigned char *b1 = NULL, *b2 = NULL;
    size_t olen1 = 0, olen2 = 0;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    if (psa_crypto_init() != PSA_SUCCESS) {
        goto exit;
    }
    dummy_init();

#if defined(MBEDTLS_SSL_ALPN)
    ctx_alpn_list[0] = "HTTP";
    ctx_alpn_list[1] = "fuzzalpn";
    ctx_alpn_list[2] = NULL;
#endif

    if (context_setup(&ssl, &conf) != 0) {
        goto exit;
    }

    if (mbedtls_ssl_context_load(&ssl, Data, Size) != 0) {
        /* A failed load leaves the context partly built; re-init rather than
         * free, so teardown cannot touch half-owned pointers. */
        mbedtls_ssl_init(&ssl);
        goto exit;
    }

    b1 = context_save_alloc(&ssl, &olen1);
    if (b1 == NULL) {
        goto exit;
    }

    /* Re-serializing what we just serialized must reproduce it byte for byte.
     * A field that survives load but comes back out as a different value fails
     * here even when both blobs are individually well formed. */
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    if (context_setup(&ssl, &conf) != 0) {
        goto exit;
    }
    if (mbedtls_ssl_context_load(&ssl, b1, olen1) != 0) {
        /* Our own save output must load back. */
        abort();
    }
    b2 = context_save_alloc(&ssl, &olen2);
    if (b2 == NULL) {
        abort();
    }
    if (olen1 != olen2 || memcmp(b1, b2, olen1) != 0) {
        abort();
    }

exit:
    free(b1);
    free(b2);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_psa_crypto_free();
#else
    (void) Data;
    (void) Size;
#endif
    fuzz_watchdog_disarm();
    return 0;
}
