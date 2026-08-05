#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/ssl.h"
#include "fuzz_common.h"

#if defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_SSL_SRV_C) && \
    defined(MBEDTLS_SSL_TLS_C)
#include "ssl_misc.h"
#include "test/ssl_helpers_internal.h"

struct fuzz_cipher_cfg {
    int cipher_type;
    int hash_id;
    int etm;
};

static const struct fuzz_cipher_cfg fuzz_ciphers[] = {
    { MBEDTLS_CIPHER_AES_128_GCM, MBEDTLS_MD_NONE, 0 },
    { MBEDTLS_CIPHER_AES_256_GCM, MBEDTLS_MD_NONE, 0 },
    { MBEDTLS_CIPHER_AES_128_CCM, MBEDTLS_MD_NONE, 0 },
    { MBEDTLS_CIPHER_CHACHA20_POLY1305, MBEDTLS_MD_NONE, 0 },
    { MBEDTLS_CIPHER_AES_128_CBC, MBEDTLS_MD_SHA256, 1 },
    { MBEDTLS_CIPHER_AES_128_CBC, MBEDTLS_MD_SHA256, 0 },
    { MBEDTLS_CIPHER_AES_128_CBC, MBEDTLS_MD_SHA1, 0 },
};
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#if defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_SSL_SRV_C) && \
    defined(MBEDTLS_SSL_TLS_C)
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ssl_transform transform_in;
    mbedtls_ssl_transform transform_out;
    int have_transform;
    const struct fuzz_cipher_cfg *cfg;
    size_t reclen;

    if (Size < 14) {
        return 0;
    }
    if (psa_crypto_init() != PSA_SUCCESS) {
        return 0;
    }

    cfg = &fuzz_ciphers[Data[Size - 1] % (sizeof(fuzz_ciphers) / sizeof(fuzz_ciphers[0]))];
    reclen = Size - 1;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_transform_init(&transform_in);
    mbedtls_ssl_transform_init(&transform_out);

    have_transform = (mbedtls_test_ssl_build_transforms(&transform_in, &transform_out,
                                                        cfg->cipher_type, cfg->hash_id,
                                                        cfg->etm, 0,
                                                        MBEDTLS_SSL_VERSION_TLS1_2,
                                                        0, 0) == 0);

    if (mbedtls_ssl_config_defaults(&conf,
                                    MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) == 0 &&
        mbedtls_ssl_setup(&ssl, &conf) == 0) {
        if (have_transform) {
            mbedtls_ssl_set_inbound_transform(&ssl, &transform_in);
        }
        unsigned char *rec = malloc(reclen);
        if (rec != NULL) {
            memcpy(rec, Data, reclen);
            rec[1] = 0xfe;
            rec[2] = 0xfd;
            rec[3] = 0;
            rec[4] = 0;
            rec[11] = (unsigned char) ((reclen - 13) >> 8);
            rec[12] = (unsigned char) ((reclen - 13) & 0xff);
            mbedtls_ssl_check_record(&ssl, rec, reclen);
        }
        free(rec);
    }

    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_transform_free(&transform_in);
    mbedtls_ssl_transform_free(&transform_out);
    mbedtls_psa_crypto_free();
#else
    (void) Data;
    (void) Size;
#endif

    return 0;
}
