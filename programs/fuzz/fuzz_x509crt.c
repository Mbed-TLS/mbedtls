#include <stdint.h>
#include <stdlib.h>
#include "mbedtls/x509_crt.h"
#include "fuzz_common.h"

#ifdef MBEDTLS_X509_CRT_PARSE_C
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
#endif /* MBEDTLS_X509_CRT_PARSE_C */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#ifdef MBEDTLS_X509_CRT_PARSE_C
    int ret;
    mbedtls_x509_crt crt;
    unsigned char buf[4096];

    mbedtls_x509_crt_init(&crt);
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        goto exit;
    }
    ret = mbedtls_x509_crt_parse(&crt, Data, Size);
    if (ret == 0) {
        for (const mbedtls_x509_crt *c = &crt; c != NULL; c = c->next) {
            if (!buf_within(&c->raw, &c->tbs) ||
                !buf_within(&c->raw, &c->serial) ||
                !buf_within(&c->raw, &c->sig_oid) ||
                !buf_within(&c->raw, &c->issuer_raw) ||
                !buf_within(&c->raw, &c->subject_raw) ||
                !buf_within(&c->raw, &c->pk_raw) ||
                !buf_within(&c->raw, &c->v3_ext)) {
                abort();
            }
        }
    }
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    if (ret == 0) {
        ret = mbedtls_x509_crt_info((char *) buf, sizeof(buf) - 1, " ", &crt);
    }
#else
    ((void) ret);
    ((void) buf);
#endif /* !MBEDTLS_X509_REMOVE_INFO */

exit:
    mbedtls_psa_crypto_free();
    mbedtls_x509_crt_free(&crt);
#else /* MBEDTLS_X509_CRT_PARSE_C */
    (void) Data;
    (void) Size;
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    return 0;
}
