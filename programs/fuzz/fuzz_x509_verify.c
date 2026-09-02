#include <stdint.h>
#include <stdlib.h>
#include "mbedtls/x509_crt.h"
#include "mbedtls/platform_time.h"
#include "fuzz_common.h"

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PLATFORM_TIME_ALT)
/* Keep in step with dummy_constant_time() in fuzz_common.c: a clock inside the
 * test certificates' validity window, so verification can actually succeed. */
static mbedtls_time_t fuzz_constant_time(mbedtls_time_t *t)
{
    (void) t;
    return 0x6968d6c0;
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt chain;
    mbedtls_x509_crt trust_ca;
    size_t split, len1;
    uint32_t flags = 0;
    int ret;

    if (Size < 2) {
        return 0;
    }

    if (psa_crypto_init() != PSA_SUCCESS) {
        return 0;
    }
#if defined(MBEDTLS_PLATFORM_TIME_ALT)
    mbedtls_platform_set_time(fuzz_constant_time);
#endif

    mbedtls_x509_crt_init(&chain);
    mbedtls_x509_crt_init(&trust_ca);

    split = ((size_t) Data[0] << 8) | (size_t) Data[1];
    Data += 2;
    Size -= 2;
    len1 = split <= Size ? split : Size;

    mbedtls_x509_crt_parse(&chain, Data, len1);
    mbedtls_x509_crt_parse(&trust_ca, Data + len1, Size - len1);

    if (chain.raw.p != NULL) {
        ret = mbedtls_x509_crt_verify(&chain, &trust_ca, NULL, "localhost",
                                      &flags, NULL, NULL);
        if ((ret == 0 && flags != 0) ||
            (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED && flags == 0)) {
            abort();
        }

        /* Repeat against an IP literal so the iPAddress-SAN matching path is
         * exercised too; a DNS name never reaches it. The split field's high
         * byte picks the family, keeping the corpus layout unchanged. */
        flags = 0;
        ret = mbedtls_x509_crt_verify(&chain, &trust_ca, NULL,
                                      (split & 0x100) ? "2001:db8::dead:beef"
                                                      : "192.0.2.77",
                                      &flags, NULL, NULL);
        if ((ret == 0 && flags != 0) ||
            (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED && flags == 0)) {
            abort();
        }
    }

    mbedtls_x509_crt_free(&trust_ca);
    mbedtls_x509_crt_free(&chain);
    mbedtls_psa_crypto_free();
#else
    (void) Data;
    (void) Size;
#endif

    return 0;
}
