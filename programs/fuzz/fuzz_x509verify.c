#include <stdint.h>
#include <string.h>

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/ecp.h"
#include "common.h"

static size_t get_len16(const uint8_t *d, size_t n, size_t pos, size_t cap,
                        size_t *out_pos)
{
    size_t len;

    if (pos + 2 > n) {
        *out_pos = n;
        return 0;
    }
    len = (size_t) d[pos] | ((size_t) d[pos + 1] << 8);
    pos += 2;
    if (len > cap) {
        len = cap;
    }
    if (len > n - pos) {
        len = n - pos;
    }
    *out_pos = pos;
    return len;
}

static const mbedtls_x509_crt_profile *profile_from_byte(uint8_t b)
{
    switch (b % 4) {
        case 0: return &mbedtls_x509_crt_profile_default;
        case 1: return &mbedtls_x509_crt_profile_next;
        case 2: return &mbedtls_x509_crt_profile_suiteb;
        default: return &mbedtls_x509_crt_profile_none;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    int ret;
    mbedtls_x509_crt leaf, ca;
    mbedtls_x509_crl crl;
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_x509_crt_restart_ctx rs;
#endif
    uint32_t flags = 0;
    size_t pos = 0, leaf_len, ca_len, crl_len;
    uint8_t opts;

    mbedtls_x509_crt_init(&leaf);
    mbedtls_x509_crt_init(&ca);
    mbedtls_x509_crl_init(&crl);
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_x509_crt_restart_init(&rs);
#endif

    if (Size < 5) {
        goto exit;
    }
    opts = Data[pos++];

    leaf_len = get_len16(Data, Size, pos, 8192, &pos);
    if (leaf_len == 0 || leaf_len > Size - pos) {
        goto exit;
    }
    ret = mbedtls_x509_crt_parse(&leaf, Data + pos, leaf_len);
    pos += leaf_len;
    if (ret != 0) {
        goto exit;
    }

    ca_len = get_len16(Data, Size, pos, 8192, &pos);
    if (ca_len > 0) {
        if (ca_len > Size - pos) {
            goto exit;
        }
        /* parse failures on the CA are fine: verify against an empty chain */
        (void) mbedtls_x509_crt_parse(&ca, Data + pos, ca_len);
        pos += ca_len;
    }

    crl_len = get_len16(Data, Size, pos, 8192, &pos);
    if (crl_len > 0 && crl_len <= Size - pos) {
        (void) mbedtls_x509_crl_parse(&crl, Data + pos, crl_len);
    }

    {
        const mbedtls_x509_crt_profile *profile = profile_from_byte(opts);

        /* seed some expected-failure bits (verify treats flags as out-param,
         * but exercising the bit values keeps the flag surface alive) */
        if (opts & 0x01) {
            flags |= MBEDTLS_X509_BADCERT_EXPIRED;
        }
        if (opts & 0x02) {
            flags |= MBEDTLS_X509_BADCERT_FUTURE;
        }
        if (opts & 0x04) {
            flags |= MBEDTLS_X509_BADCERT_KEY_USAGE;
        }
        if (opts & 0x08) {
            flags |= MBEDTLS_X509_BADCERT_NS_CERT_TYPE;
        }

        if (opts & 0x10) {
            /* verify with a CRL and per-CA storage */
            (void) mbedtls_x509_crt_verify_with_profile(
                &leaf, &ca, &crl, profile, NULL, &flags, NULL, NULL);
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
        } else if (opts & 0x20) {
            /* restartable: a small ECP max_ops budget makes
             * MBEDTLS_ERR_ECP_IN_PROGRESS actually reachable (the default
             * budget of 0 disables slicing and the loop would always exit
             * after the first call).  Bit 6 selects between two modes:
             * clear keeps a bounded slice count, so every such input ends
             * at the abort/restart-free path; set runs the verification to
             * completion with a larger per-call budget (up to a generous
             * call cap), so the resume path -- the restart context carrying
             * state through the chain and returning 0 with the final flags
             * -- is fuzzed as well.  The budget is global, so restore the
             * default after the loop to keep it from leaking into later
             * inputs. */
            int slices = (opts & 0x40) ? 1000 : 2 + (opts >> 6);
            unsigned max_ops = (opts & 0x40) ? 500u + 32u * (opts & 0x1f)
                                             : 42u + (opts & 0x1f);
            int i;

            mbedtls_ecp_set_max_ops(max_ops);
            for (i = 0; i < slices; i++) {
                ret = mbedtls_x509_crt_verify_restartable(
                    &leaf, &ca, NULL, profile, NULL,
                    &flags, NULL, NULL, &rs);
                if (ret == 0) {
                    break;
                }
                if (ret != MBEDTLS_ERR_ECP_IN_PROGRESS) {
                    break;
                }
            }
            mbedtls_ecp_set_max_ops(0);
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
        } else {
            (void) mbedtls_x509_crt_verify_with_profile(
                &leaf, &ca, NULL, profile, NULL, &flags, NULL, NULL);
        }

        /* also run the info/description side for the parsed leaf */
        if (leaf.raw.len > 0) {
            char info[1024];
            (void) mbedtls_x509_crt_info(info, sizeof(info), "", &leaf);
        }
        (void) flags;
    }

exit:
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_x509_crt_restart_free(&rs);
#endif
    mbedtls_x509_crl_free(&crl);
    mbedtls_x509_crt_free(&ca);
    mbedtls_x509_crt_free(&leaf);
    return 0;
}
