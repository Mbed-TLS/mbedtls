#include <stdint.h>
#include <stdlib.h>
#include "mbedtls/x509_csr.h"
#include "fuzz_common.h"

#ifdef MBEDTLS_X509_CSR_PARSE_C
static int buf_within(const mbedtls_x509_buf *raw, const mbedtls_x509_buf *f)
{
    uintptr_t base, fp, offset;
    if (f->len == 0 || f->p == NULL) {
        return 1;
    }
    base = (uintptr_t) raw->p;
    fp = (uintptr_t) f->p;
    if (fp < base) {
        return 0;
    }
    offset = fp - base;
    return offset <= raw->len && f->len <= raw->len - offset;
}
#endif /* MBEDTLS_X509_CSR_PARSE_C */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#ifdef MBEDTLS_X509_CSR_PARSE_C
    int ret;
    mbedtls_x509_csr csr;
    unsigned char buf[4096];

    mbedtls_x509_csr_init(&csr);
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        goto exit;
    }
    ret = mbedtls_x509_csr_parse(&csr, Data, Size);
    if (ret == 0) {
        if (!buf_within(&csr.raw, &csr.cri) ||
            !buf_within(&csr.raw, &csr.subject_raw) ||
            !buf_within(&csr.raw, &csr.sig_oid)) {
            abort();
        }
    }
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    if (ret == 0) {
        ret = mbedtls_x509_csr_info((char *) buf, sizeof(buf) - 1, " ", &csr);
    }
#else /* !MBEDTLS_X509_REMOVE_INFO */
    ((void) ret);
    ((void) buf);
#endif /* !MBEDTLS_X509_REMOVE_INFO */

exit:
    mbedtls_psa_crypto_free();
    mbedtls_x509_csr_free(&csr);
#else /* MBEDTLS_X509_CSR_PARSE_C */
    (void) Data;
    (void) Size;
#endif /* MBEDTLS_X509_CSR_PARSE_C */

    return 0;
}
