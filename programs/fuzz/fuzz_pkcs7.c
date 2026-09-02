#include <stdint.h>
#include "mbedtls/pkcs7.h"
#include "mbedtls/x509_crt.h"
#include "test/certs.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#ifdef MBEDTLS_PKCS7_C
    mbedtls_pkcs7 pkcs7;

    mbedtls_pkcs7_init(&pkcs7);

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (mbedtls_pkcs7_parse_der(&pkcs7, Data, Size) == MBEDTLS_PKCS7_SIGNED_DATA) {
#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
        mbedtls_x509_crt cert;
        unsigned char hash[32] = { 0 };

        mbedtls_x509_crt_init(&cert);
        if (mbedtls_x509_crt_parse(&cert, (const unsigned char *) mbedtls_test_cas_pem,
                                   mbedtls_test_cas_pem_len) == 0) {
            mbedtls_pkcs7_signed_data_verify(&pkcs7, &cert, Data, Size);
            mbedtls_pkcs7_signed_hash_verify(&pkcs7, &cert, hash, sizeof(hash));
        }
        mbedtls_x509_crt_free(&cert);
#endif /* MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_PEM_PARSE_C */
    }

exit:
    mbedtls_psa_crypto_free();
    mbedtls_pkcs7_free(&pkcs7);
#else
    (void) Data;
    (void) Size;
#endif

    return 0;
}
