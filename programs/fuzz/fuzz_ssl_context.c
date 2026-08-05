#include <stdint.h>
#include "mbedtls/ssl.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) && \
    defined(MBEDTLS_SSL_PROTO_DTLS) && \
    defined(MBEDTLS_SSL_CLI_C)
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    if (psa_crypto_init() != PSA_SUCCESS) {
        return 0;
    }

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    if (mbedtls_ssl_config_defaults(&conf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) == 0 &&
        mbedtls_ssl_setup(&ssl, &conf) == 0) {
        if (mbedtls_ssl_context_load(&ssl, Data, Size) != 0) {
            mbedtls_ssl_init(&ssl);
        }
    }

    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_psa_crypto_free();
#else
    (void) Data;
    (void) Size;
#endif

    return 0;
}
