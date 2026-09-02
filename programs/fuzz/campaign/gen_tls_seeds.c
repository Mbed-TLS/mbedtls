/*
 * Seed generator for the fuzz_client / fuzz_dtlsclient harnesses.
 *
 * Those harnesses feed the fuzz input to the client as the *server's* side of a
 * handshake (dummy_send throws the client's output away, fuzz_recv serves the
 * input). A useful seed is therefore a recorded server->client record stream,
 * with the harness's trailing options bytes appended.
 *
 * Why this needs a deterministic RNG
 * ---------------------------------
 * TLS 1.3 makes the server echo the client's 32-byte legacy_session_id, and the
 * client derives its handshake keys from an ephemeral key it generated itself.
 * Both come from the PSA RNG. If the RNG draws real entropy the client picks new
 * values on every execution, so no recorded server flight can ever match and the
 * client cannot get past ServerHello. The harnesses get their determinism from
 * MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG, which crypto_config.h turns on whenever
 * FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION is defined; dummy_init() then points
 * it at the test external RNG, which is libc rand(). This generator must be
 * built the same way (build_tls_seeds.sh does).
 *
 * That RNG has one global stream for the whole process, so it has to be rewound
 * to its process-start state (srand(1)) before each seed - otherwise only the
 * first seed emitted would replay in a freshly started harness.
 *
 * The client here is configured exactly as fuzz_client configures it for the
 * options value being emitted, so it produces the same ClientHello - and the
 * same ephemeral key - that the harness will produce when replaying the seed.
 * The server is only a means of producing a well-formed flight; nothing about it
 * has to be reproducible.
 *
 * After the handshake the server also sends application data (and, when the
 * client offered tickets, a NewSessionTicket), so a seed exercises the
 * post-handshake and application-data paths rather than stopping at Finished.
 */

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "test/certs.h"
#include "fuzz_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STREAM (256 * 1024)

/* One direction of the in-memory transport. */
typedef struct {
    unsigned char buf[MAX_STREAM];
    size_t len;                 /* bytes written   */
    size_t off;                 /* bytes consumed  */
} channel_t;

static channel_t c2s;           /* client -> server */
static channel_t s2c;           /* server -> client, this is what we record */

static int chan_send(channel_t *ch, const unsigned char *buf, size_t len)
{
    if (ch->len + len > sizeof(ch->buf)) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    memcpy(ch->buf + ch->len, buf, len);
    ch->len += len;
    return (int) len;
}

static int chan_recv(channel_t *ch, unsigned char *buf, size_t len)
{
    size_t avail = ch->len - ch->off;
    if (avail == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    if (len > avail) {
        len = avail;
    }
    memcpy(buf, ch->buf + ch->off, len);
    ch->off += len;
    return (int) len;
}

static int cli_send(void *ctx, const unsigned char *b, size_t l)
{
    (void) ctx; return chan_send(&c2s, b, l);
}
static int cli_recv(void *ctx, unsigned char *b, size_t l)
{
    (void) ctx; return chan_recv(&s2c, b, l);
}
static int srv_send(void *ctx, const unsigned char *b, size_t l)
{
    (void) ctx; return chan_send(&s2c, b, l);
}
static int srv_recv(void *ctx, unsigned char *b, size_t l)
{
    (void) ctx; return chan_recv(&c2s, b, l);
}

/* Shared across handshakes, mirroring the harness's `initialized` block which
 * parses the CA bundle once and keeps it for every later iteration. */
static mbedtls_x509_crt cacert;
static const char *alpn_list[3];

/*
 * Configure the client exactly as fuzz_client.c does for `options`. Any
 * divergence changes the ClientHello and the seed stops replaying, so this
 * mirrors the harness statement for statement.
 */
static int setup_client(mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf,
                        uint16_t options)
{
    if (mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        return -1;
    }

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    static const unsigned char psk[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const char psk_id[] = "Client_identity";
    if (options & 2) {
        mbedtls_ssl_conf_psk(conf, psk, sizeof(psk),
                             (const unsigned char *) psk_id, sizeof(psk_id) - 1);
    }
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
    if (options & 4) {
        mbedtls_ssl_conf_ca_chain(conf, &cacert, NULL);
        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    } else
#endif
    {
        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
    }
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    mbedtls_ssl_conf_extended_master_secret(conf,
                                            (options & 0x10) ?
                                            MBEDTLS_SSL_EXTENDED_MS_DISABLED :
                                            MBEDTLS_SSL_EXTENDED_MS_ENABLED);
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    mbedtls_ssl_conf_encrypt_then_mac(conf,
                                      (options & 0x20) ?
                                      MBEDTLS_SSL_ETM_DISABLED :
                                      MBEDTLS_SSL_ETM_ENABLED);
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation(conf,
                                   (options & 0x80) ?
                                   MBEDTLS_SSL_RENEGOTIATION_ENABLED :
                                   MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_conf_session_tickets(conf,
                                     (options & 0x100) ?
                                     MBEDTLS_SSL_SESSION_TICKETS_DISABLED :
                                     MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
#endif
#if defined(MBEDTLS_SSL_ALPN)
    if (options & 0x200) {
        mbedtls_ssl_conf_alpn_protocols(conf, alpn_list);
    }
#endif

    if (mbedtls_ssl_setup(ssl, conf) != 0) {
        return -1;
    }
#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
    if ((options & 1) == 0) {
        if (mbedtls_ssl_set_hostname(ssl, "localhost") != 0) {
            return -1;
        }
    }
#endif
    mbedtls_ssl_set_bio(ssl, NULL, cli_send, cli_recv, NULL);
    return 0;
}

/*
 * Emit one seed: run a handshake for `options` at `ver`, record the server's
 * output, append the options bytes the harness reads off the tail.
 */
static int emit_seed(const char *dir, const char *name, uint16_t options,
                     mbedtls_ssl_protocol_version ver)
{
    mbedtls_ssl_context cli, srv;
    mbedtls_ssl_config cli_conf, srv_conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_TICKET_C)
    mbedtls_ssl_ticket_context ticket_ctx;
#endif
    int ret = -1, cli_ret, srv_ret;
    char path[512];
    FILE *f;

    memset(&c2s, 0, sizeof(c2s));
    memset(&s2c, 0, sizeof(s2c));

    mbedtls_ssl_init(&cli);
    mbedtls_ssl_init(&srv);
    mbedtls_ssl_config_init(&cli_conf);
    mbedtls_ssl_config_init(&srv_conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_TICKET_C)
    mbedtls_ssl_ticket_init(&ticket_ctx);
#endif

    if (setup_client(&cli, &cli_conf, options) != 0) {
        fprintf(stderr, "  %s: client setup failed\n", name);
        goto exit;
    }

    /*
     * Produce the ClientHello *before* touching the server. Client and server
     * share one process-wide PSA DRBG, and the server's setup consumes from it
     * (mbedtls_ssl_ticket_setup alone generates a 256-bit AES key). Setting the
     * server up first would shift the client's draws away from what the harness
     * does, so its 32-byte legacy_session_id would not match the one recorded in
     * the ServerHello and the replay would die in
     * ssl_tls13_check_server_hello_session_id_echo(). This first step writes the
     * ClientHello and returns WANT_READ, by which point every draw a TLS 1.3
     * client makes (random, session id, key share) has happened.
     */
    cli_ret = mbedtls_ssl_handshake(&cli);
    if (cli_ret != MBEDTLS_ERR_SSL_WANT_READ && cli_ret != 0) {
        fprintf(stderr, "  %s: ClientHello failed (-0x%04x)\n",
                name, (unsigned) -cli_ret);
        goto exit;
    }

    if (mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                               mbedtls_test_srv_crt_len) != 0 ||
        mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                               mbedtls_test_cas_pem_len) != 0 ||
        mbedtls_pk_parse_key(&pkey, (const unsigned char *) mbedtls_test_srv_key,
                             mbedtls_test_srv_key_len, NULL, 0) != 0) {
        fprintf(stderr, "  %s: server credentials failed\n", name);
        goto exit;
    }
    if (mbedtls_ssl_config_defaults(&srv_conf, MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        goto exit;
    }
    mbedtls_ssl_conf_ca_chain(&srv_conf, srvcert.next, NULL);
    if (mbedtls_ssl_conf_own_cert(&srv_conf, &srvcert, &pkey) != 0) {
        goto exit;
    }
    /* Pin the server to one version so the recorded flight is unambiguous. */
    mbedtls_ssl_conf_min_tls_version(&srv_conf, ver);
    mbedtls_ssl_conf_max_tls_version(&srv_conf, ver);
#if defined(MBEDTLS_SSL_ALPN)
    if (options & 0x200) {
        mbedtls_ssl_conf_alpn_protocols(&srv_conf, alpn_list);
    }
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_TICKET_C)
    /* Lets the server emit NewSessionTicket, so the seed reaches the client's
     * ticket-parsing path instead of stopping after Finished. */
    if (mbedtls_ssl_ticket_setup(&ticket_ctx, PSA_ALG_GCM, PSA_KEY_TYPE_AES,
                                 256, 86400) == 0) {
        mbedtls_ssl_conf_session_tickets_cb(&srv_conf, mbedtls_ssl_ticket_write,
                                            mbedtls_ssl_ticket_parse, &ticket_ctx);
    }
#endif
    if (mbedtls_ssl_setup(&srv, &srv_conf) != 0) {
        goto exit;
    }
    mbedtls_ssl_set_bio(&srv, NULL, srv_send, srv_recv, NULL);

    /* Drive both ends until neither can make progress. cli_ret already holds
     * the result of the ClientHello step above. */
    srv_ret = MBEDTLS_ERR_SSL_WANT_READ;
    for (int i = 0; i < 64; i++) {
        size_t before = c2s.len + s2c.len;

        if (cli_ret == MBEDTLS_ERR_SSL_WANT_READ ||
            cli_ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            cli_ret = mbedtls_ssl_handshake(&cli);
        }
        if (srv_ret == MBEDTLS_ERR_SSL_WANT_READ ||
            srv_ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            srv_ret = mbedtls_ssl_handshake(&srv);
        }
        if (cli_ret == 0 && srv_ret == 0) {
            break;
        }
        if ((cli_ret != 0 && cli_ret != MBEDTLS_ERR_SSL_WANT_READ &&
             cli_ret != MBEDTLS_ERR_SSL_WANT_WRITE) ||
            (srv_ret != 0 && srv_ret != MBEDTLS_ERR_SSL_WANT_READ &&
             srv_ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
            break;
        }
        if (c2s.len + s2c.len == before) {
            break;                      /* stalled */
        }
    }

    if (cli_ret != 0 || srv_ret != 0) {
        fprintf(stderr, "  %s: handshake failed (cli -0x%04x srv -0x%04x)\n",
                name, (unsigned) -cli_ret, (unsigned) -srv_ret);
        goto exit;
    }

    /* Application data, plus whatever post-handshake messages the server wants
     * to send (TLS 1.3 NewSessionTicket is flushed on the first write). */
    {
        const unsigned char payload[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello world\n";
        mbedtls_ssl_write(&srv, payload, sizeof(payload) - 1);
        mbedtls_ssl_write(&srv, payload, sizeof(payload) - 1);
        /* Let the client consume it so the server can flush anything queued. */
        unsigned char sink[512];
        for (int i = 0; i < 4; i++) {
            if (mbedtls_ssl_read(&cli, sink, sizeof(sink)) <= 0) {
                break;
            }
        }
        mbedtls_ssl_close_notify(&srv);
    }

    if (s2c.len == 0) {
        fprintf(stderr, "  %s: nothing recorded\n", name);
        goto exit;
    }

    snprintf(path, sizeof(path), "%s/%s", dir, name);
    if ((f = fopen(path, "wb")) == NULL) {
        fprintf(stderr, "  %s: cannot write\n", name);
        goto exit;
    }
    fwrite(s2c.buf, 1, s2c.len, f);
    fputc((options >> 8) & 0xff, f);     /* harness reads options from the */
    fputc(options & 0xff, f);            /* last two bytes                 */
    fclose(f);
    printf("  %-34s %6zu bytes  options=0x%04x\n", name, s2c.len + 2, options);
    ret = 0;

exit:
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_TICKET_C)
    mbedtls_ssl_ticket_free(&ticket_ctx);
#endif
    mbedtls_pk_free(&pkey);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_ssl_free(&srv);
    mbedtls_ssl_free(&cli);
    mbedtls_ssl_config_free(&srv_conf);
    mbedtls_ssl_config_free(&cli_conf);
    return ret;
}

struct seed_spec {
    const char *name;
    uint16_t options;
    mbedtls_ssl_protocol_version ver;
};

int main(int argc, char **argv)
{
    const char *dir = (argc > 1) ? argv[1] : ".";
    int ok = 0, total = 0;

    dummy_init();

    const struct seed_spec specs[] = {
        /* TLS 1.3: the paths that no mutated input can reach, because the
         * ServerHello has to echo a session id the fuzzer cannot guess. */
        { "tls13_verify_none",      0x0000, MBEDTLS_SSL_VERSION_TLS1_3 },
        { "tls13_verify_ca",        0x0004, MBEDTLS_SSL_VERSION_TLS1_3 },
        /* options bit 0 (no hostname) is only usable with VERIFY_NONE: with
         * VERIFY_REQUIRED and no hostname the handshake stops early with
         * MBEDTLS_ERR_SSL_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME. */
        { "tls13_no_hostname",      0x0001, MBEDTLS_SSL_VERSION_TLS1_3 },
        { "tls13_alpn",             0x0204, MBEDTLS_SSL_VERSION_TLS1_3 },
        { "tls13_no_tickets",       0x0104, MBEDTLS_SSL_VERSION_TLS1_3 },
        { "tls13_psk",              0x0006, MBEDTLS_SSL_VERSION_TLS1_3 },
        { "tls13_reneg_flag",       0x0084, MBEDTLS_SSL_VERSION_TLS1_3 },
        { "tls13_no_ems",           0x0014, MBEDTLS_SSL_VERSION_TLS1_3 },
        /* TLS 1.2 for the same reason: the client's ECDHE key and the Finished
         * verify_data cannot be produced by mutation either. */
        { "tls12_verify_none",      0x0000, MBEDTLS_SSL_VERSION_TLS1_2 },
        { "tls12_verify_ca",        0x0004, MBEDTLS_SSL_VERSION_TLS1_2 },
        { "tls12_alpn",             0x0204, MBEDTLS_SSL_VERSION_TLS1_2 },
        { "tls12_no_tickets",       0x0104, MBEDTLS_SSL_VERSION_TLS1_2 },
        { "tls12_etm_off",          0x0024, MBEDTLS_SSL_VERSION_TLS1_2 },
    };

    for (size_t i = 0; i < sizeof(specs) / sizeof(specs[0]); i++) {
        /* Rewind the external RNG to the state a freshly started harness sees,
         * and give each seed a fresh PSA context, matching the harness's
         * per-iteration init/free cycle. */
        srand(1);
        if (psa_crypto_init() != PSA_SUCCESS) {
            fprintf(stderr, "psa_crypto_init failed\n");
            return 1;
        }
        mbedtls_x509_crt_init(&cacert);
        if (mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_test_cas_pem,
                                   mbedtls_test_cas_pem_len) != 0) {
            fprintf(stderr, "CA parse failed\n");
            return 1;
        }
        alpn_list[0] = "HTTP";
        alpn_list[1] = "fuzzalpn";
        alpn_list[2] = NULL;

        total++;
        if (emit_seed(dir, specs[i].name, specs[i].options, specs[i].ver) == 0) {
            ok++;
        }

        mbedtls_x509_crt_free(&cacert);
        mbedtls_psa_crypto_free();
    }

    printf("[+] %d/%d seeds written to %s\n", ok, total, dir);
    return ok == 0 ? 1 : 0;
}
