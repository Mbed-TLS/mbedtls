/* Two in-process DTLS endpoints handshaking with each other.
 *
 * Every other SSL harness replays recorded or mutated traffic at one endpoint,
 * so it cannot complete a handshake: the Finished MAC covers both peers'
 * randoms. Everything behind a completed handshake is therefore unreachable -
 * the keying-material exporter, session-cache and ticket writes, renegotiation,
 * post-handshake reads. Here the fuzzer steers the configuration of both ends
 * and the library produces the traffic, so the handshake really completes and
 * that surface opens up.
 *
 *   byte 0    transport and cookie selectors
 *   byte 1    ciphersuite pin index
 *   byte 2    MTU selector
 *   byte 3    post-handshake action selectors
 *   rest      exporter label and context bytes
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/timing.h"
#include "test/certs.h"
#include "fuzz_common.h"

#define FUZZ_LOOP_HDR 4

#if defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_SSL_CLI_C) && \
    defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_TIMING_C) && \
    defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
#define FUZZ_LOOPBACK_ENABLED

/* One direction of the wire. Datagram boundaries are preserved, because DTLS
 * record handling depends on them. A datagram must hold a whole flight - the
 * server's certificate flight alone is over 3 KB - or the send callback fails
 * the handshake and the harness silently tests nothing. */
#define PIPE_MSGS 16
#define PIPE_MSG_LEN (MBEDTLS_SSL_OUT_CONTENT_LEN + 2048)

typedef struct {
    unsigned char buf[PIPE_MSGS][PIPE_MSG_LEN];
    size_t len[PIPE_MSGS];
    unsigned head, tail;
} pipe_t;

static pipe_t to_srv, to_cli;

/* One endpoint's view of the wire: it writes into tx and reads from rx. */
typedef struct {
    pipe_t *tx;
    pipe_t *rx;
} wire_t;

static void pipe_reset(pipe_t *p)
{
    p->head = 0;
    p->tail = 0;
}

static int pipe_send(void *ctx, const unsigned char *buf, size_t len)
{
    pipe_t *p = ((wire_t *) ctx)->tx;

    if (len > PIPE_MSG_LEN) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (p->tail - p->head >= PIPE_MSGS) {
        /* Full: report it as sent. A peer that stops draining is a transport
         * condition, not a library defect. */
        return (int) len;
    }
    memcpy(p->buf[p->tail % PIPE_MSGS], buf, len);
    p->len[p->tail % PIPE_MSGS] = len;
    p->tail++;
    return (int) len;
}

static int pipe_recv(void *ctx, unsigned char *buf, size_t len)
{
    pipe_t *p = ((wire_t *) ctx)->rx;
    size_t n;

    if (p->head == p->tail) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    n = p->len[p->head % PIPE_MSGS];
    if (n > len) {
        n = len;
    }
    memcpy(buf, p->buf[p->head % PIPE_MSGS], n);
    p->head++;
    return (int) n;
}

static int pipe_recv_timeout(void *ctx, unsigned char *buf, size_t len,
                             uint32_t timeout)
{
    (void) timeout;
    return pipe_recv(ctx, buf, len);
}

/* A timer that never expires: retransmission is not what this harness is for,
 * and a firing timer makes the handshake loop unbounded. */
static void timer_set(void *ctx, uint32_t int_ms, uint32_t fin_ms)
{
    (void) ctx; (void) int_ms; (void) fin_ms;
}

static int timer_get(void *ctx)
{
    (void) ctx;
    return 0;
}
#endif /* FUZZ_LOOPBACK_ENABLED */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    srand(1);
    fuzz_watchdog_arm();
#if defined(FUZZ_LOOPBACK_ENABLED)
    mbedtls_ssl_context cli, srv;
    mbedtls_ssl_config cli_conf, srv_conf;
    mbedtls_ssl_cookie_ctx cookie_ctx;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
    wire_t cli_wire, srv_wire;
    unsigned char out[64];
    const uint8_t *tail;
    size_t tail_len, label_len;
    int i, rc, rs;

    if (Size < FUZZ_LOOP_HDR) {
        goto exit;
    }

    mbedtls_ssl_init(&cli);
    mbedtls_ssl_init(&srv);
    mbedtls_ssl_config_init(&cli_conf);
    mbedtls_ssl_config_init(&srv_conf);
    mbedtls_ssl_cookie_init(&cookie_ctx);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    pipe_reset(&to_srv);
    pipe_reset(&to_cli);

    if (psa_crypto_init() != PSA_SUCCESS) {
        goto exit;
    }
    dummy_init();

    if (mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                               mbedtls_test_srv_crt_len) != 0 ||
        mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                               mbedtls_test_cas_pem_len) != 0 ||
        mbedtls_pk_parse_key(&pkey, (const unsigned char *) mbedtls_test_srv_key,
                             mbedtls_test_srv_key_len, NULL, 0) != 0) {
        goto exit;
    }

    if (mbedtls_ssl_config_defaults(&cli_conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0 ||
        mbedtls_ssl_config_defaults(&srv_conf, MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        goto exit;
    }
    mbedtls_ssl_conf_authmode(&cli_conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_ca_chain(&cli_conf, srvcert.next, NULL);
    if (mbedtls_ssl_conf_own_cert(&srv_conf, &srvcert, &pkey) != 0) {
        goto exit;
    }

    /* HelloVerifyRequest is what makes the server retain its last flight, which
     * is the state the documented exporter contract does not account for. Both
     * settings are reachable configurations, so both are worth driving. */
    if (Data[0] & 1) {
        if (mbedtls_ssl_cookie_setup(&cookie_ctx) != 0) {
            goto exit;
        }
        mbedtls_ssl_conf_dtls_cookies(&srv_conf, mbedtls_ssl_cookie_write,
                                      mbedtls_ssl_cookie_check, &cookie_ctx);
    } else {
        mbedtls_ssl_conf_dtls_cookies(&srv_conf, NULL, NULL, NULL);
    }
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    /* Serialization and the TLS 1.2 exporter are 1.2-only; pin the version so
     * the loopback lands there rather than negotiating 1.3. */
    if ((Data[0] & 2) == 0) {
        mbedtls_ssl_conf_max_tls_version(&cli_conf, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&srv_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    }
#endif

    if (mbedtls_ssl_setup(&cli, &cli_conf) != 0 ||
        mbedtls_ssl_setup(&srv, &srv_conf) != 0) {
        goto exit;
    }
    if (mbedtls_ssl_set_client_transport_id(&srv, (const unsigned char *) "\x7f\0\0\1",
                                            4) != 0) {
        goto exit;
    }
    if (Data[2] != 0) {
        mbedtls_ssl_set_mtu(&cli, 512u + Data[2]);
        mbedtls_ssl_set_mtu(&srv, 512u + Data[2]);
    }

    cli_wire.tx = &to_srv; cli_wire.rx = &to_cli;
    srv_wire.tx = &to_cli; srv_wire.rx = &to_srv;
    mbedtls_ssl_set_bio(&cli, &cli_wire, pipe_send, pipe_recv, pipe_recv_timeout);
    mbedtls_ssl_set_bio(&srv, &srv_wire, pipe_send, pipe_recv, pipe_recv_timeout);
    mbedtls_ssl_set_timer_cb(&cli, NULL, timer_set, timer_get);
    mbedtls_ssl_set_timer_cb(&srv, NULL, timer_set, timer_get);

    /* Step both ends until both report the handshake over. A step returning 0
     * means that one step succeeded, not that the handshake finished, so the
     * loop is driven by is_handshake_over(). If neither side advanced in a full
     * round the exchange is stuck and there is nothing more to drive. */
    for (i = 0; i < 512; i++) {
        int moved = 0;

        if (!mbedtls_ssl_is_handshake_over(&cli)) {
            rc = mbedtls_ssl_handshake_step(&cli);
            if (rc == 0) {
                moved = 1;
            } else if (rc != MBEDTLS_ERR_SSL_WANT_READ &&
                       rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
                goto exit;
            }
        }
        if (!mbedtls_ssl_is_handshake_over(&srv)) {
            rs = mbedtls_ssl_handshake_step(&srv);
            if (rs == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
                mbedtls_ssl_session_reset(&srv);
                if (mbedtls_ssl_set_client_transport_id(
                        &srv, (const unsigned char *) "\x7f\0\0\1", 4) != 0) {
                    goto exit;
                }
                moved = 1;
            } else if (rs == 0) {
                moved = 1;
            } else if (rs != MBEDTLS_ERR_SSL_WANT_READ &&
                       rs != MBEDTLS_ERR_SSL_WANT_WRITE) {
                goto exit;
            }
        }
        if (mbedtls_ssl_is_handshake_over(&cli) &&
            mbedtls_ssl_is_handshake_over(&srv)) {
            break;
        }
        if (!moved) {
            goto exit;
        }
    }
    if (!mbedtls_ssl_is_handshake_over(&cli) ||
        !mbedtls_ssl_is_handshake_over(&srv)) {
        goto exit;
    }

#if defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
    /* The documented precondition is that the handshake is over, which both
     * endpoints now report. Which side sends the last flight decides which one
     * still has its flight retained, so both are asked. */
    tail = Data + FUZZ_LOOP_HDR;
    tail_len = Size - FUZZ_LOOP_HDR;
    label_len = tail_len / 2;
    if (Data[3] & 1) {
        (void) mbedtls_ssl_export_keying_material(
            &srv, out, 1 + (tail_len % sizeof(out)),
            "EXPORTER-fuzz", 13, tail, tail_len - label_len, (int) (Data[3] & 2));
    }
    if (Data[3] & 4) {
        (void) mbedtls_ssl_export_keying_material(
            &cli, out, 1 + (tail_len % sizeof(out)),
            "EXPORTER-fuzz", 13, tail, tail_len - label_len, (int) (Data[3] & 8));
    }
#else
    (void) tail; (void) tail_len; (void) label_len; (void) out;
#endif

exit:
    mbedtls_ssl_free(&cli);
    mbedtls_ssl_free(&srv);
    mbedtls_ssl_config_free(&cli_conf);
    mbedtls_ssl_config_free(&srv_conf);
    mbedtls_ssl_cookie_free(&cookie_ctx);
    mbedtls_pk_free(&pkey);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_psa_crypto_free();
#else
    (void) Data;
    (void) Size;
#endif /* FUZZ_LOOPBACK_ENABLED */
    fuzz_watchdog_disarm();
    return 0;
}
