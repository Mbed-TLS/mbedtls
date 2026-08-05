#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/ssl.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#if defined(MBEDTLS_SSL_TLS_C)
    mbedtls_ssl_session session;

    if (psa_crypto_init() != PSA_SUCCESS) {
        return 0;
    }

    mbedtls_ssl_session_init(&session);

    if (mbedtls_ssl_session_load(&session, Data, Size) == 0) {
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
    mbedtls_psa_crypto_free();
#else
    (void) Data;
    (void) Size;
#endif

    return 0;
}
