/*
 *  KTLS key export demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * Usage:
 *   ktls_app ip=127.0.0.1 port=4433 crt_filename=/path_to_crt_dir/server.crt
 *            key_filename=/path_to_key_dir/server.key [key_pwd=secret] debug_level=level
 *
 * Notes:
 *   - `ip`          : Server IP address (default: 127.0.0.1)
 *   - `port`        : TCP port to bind (default: 4433)
 *   - `crt_filename`: Path to server certificate
 *   - `key_filename`: Path to server private key
 *   - `key_pwd`     : Optional password for private key (omit or if unencrypted)
 *   - `debug_level` : 0 = disabled, 1-4 = increasing verbosity (default: 0)
 */

/*
 * NOTE:
 * This example is **not a production web server**. Its purpose is purely
 * educational: it demonstrates how to use Mbed TLS to derive and export
 * TLS traffic keys and initialization vectors (IVs) for use with the
 * Linux Kernel TLS (KTLS) interface, enabling zero-copy encryption/
 * decryption at the kernel level.
 *
 * The **core of this demonstration** is the `app_export_keys_cb` callback
 * and the `enable_ktls` function. Everything else serves merely as
 * supporting scaffolding—helpers to set up the socket, manage contexts,
 * or handle errors. Focus on these two components for understanding
 * the KTLS integration.
 *
 * Users should ensure their kernel supports KTLS before attempting to
 * use this functionality. Basic KTLS (TLS 1.2 TX) is available from
 * Linux 4.13+.
 *
 * To utilize full TLS 1.3 offload (both RX and TX), the system must
 * run at least Linux kernel 5.20.
 *
 * You can verify support with:
 *
 *     $ zgrep KTLS /proc/config.gz
 *
 * Or check if the TLS module is loaded:
 *
 *     $ lsmod | grep tls
 *
 * If missing, load it with:
 *
 *     # modprobe tls
 *
 * To load it automatically on boot, create a file inside
 * /etc/modules-load.d/ with the content:
 *
 *     tls
 *
 * This example is intentionally minimal and synchronous: it accepts
 * connections, reads the request header, and sends a static response.
 * Its goal is to illustrate **how to hand off encryption keys to KTLS**,
 * not to serve arbitrary web traffic securely or efficiently.
 */

#define DFL_IP "127.0.0.1"
#define DFL_CRT_FILENAME "./tls/server.crt"
#define DFL_KEY_FILENAME "./tls/server.key"
#define DFL_KEY_PWD NULL
#define DFL_PORT 4433
#define DFL_DEBUG_LEVEL 0

#define BUFFER_SIZE (1024 * 1)

#define GET_REQUEST "GET / HTTP/1.1\r\n\r\n"

#define GET_RESPONSE                                                                                                   \
    "HTTP/1.1 200 OK\r\n"                                                                                              \
    "Content-Type: text/plain\r\n"                                                                                     \
    "Content-Length: 21\r\n"                                                                                           \
    "\r\n"                                                                                                             \
    "Welcome to Mbed TLS!\n"

#ifndef __linux__
#error "this example is for Linux only."
#endif

#include "mbedtls/build_info.h"
#include "mbedtls/platform.h"

#ifndef _WIN32
#include <netinet/tcp.h> // TCP_NODELAY TCP_ULP SOL_TLS
#endif

#if !defined(__linux__) || !defined(TCP_ULP) || !defined(SOL_TLS)
int main(void) {
    mbedtls_printf("KTLS program designed to run on Linux with KTLS.\n");
    mbedtls_exit(0);
}
#elif !defined(MBEDTLS_X509_CRT_PARSE_C) || (!defined(MBEDTLS_SSL_PROTO_TLS1_2) && !defined(MBEDTLS_SSL_PROTO_TLS1_3))
int main(void) {
    mbedtls_printf("MBEDTLS_X509_CRT_PARSE_C and/or MBEDTLS_SSL_PROTO_TLS1_2 and/or MBEDTLS_SSL_PROTO_TLS1_3 "
                   "not defined.\n");
    mbedtls_exit(0);
}
#else /*__linux__*/

#include "mbedtls/ssl.h"

#if defined(MBEDTLS_DEBUG_C)
#include "mbedtls/debug.h"
#endif

#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>   // inet_ntop inet_pton
#include <unistd.h>      // close syscall
#include <signal.h>      // SIGPIPE
#include <sys/syscall.h> // SYS_futex
#include <string.h>      // strlen
#include <linux/tls.h>   // TLS_TX TLS_RX
#include <linux/futex.h> // FUTEX_WAIT FUTEX_WAKE

#define USAGE                                                                                                          \
    "\n usage: ktls param=<>...\n"                                                                                 \
    "\n acceptable parameters:\n"                                                                                      \
    "    ip=%%s               default: 127.0.0.1\n"                                                                    \
    "    port=%%d             default: 4433\n"                                                                         \
    "    crt_filename=%%s     Server certificate filename\n"                                                           \
    "                         default: ./tls/server.crt\n"                                                             \
    "    key_filename=%%s     Server private key filename\n"                                                           \
    "                         default: ./tls/server.key\n"                                                             \
    "    key_pwd=%%s          Password for key specified by key_file argument\n"                                       \
    "                         default: none\n"                                                                         \
    "    debug_level=%%d      default: 0 (disabled)\n"                                                                 \
    "\n"

/*
 * global options
 */
struct options {
    const char *ip;           /* IP address to bind the server to      (default: "127.0.0.1")  */
    const char *crt_filename; /* Server certificate filename           (default: "server.crt") */
    const char *key_filename; /* Server private key filename           (default: "server.key") */
    const char *key_pwd;      /* Password for key specified by key_file argument if encrypted  */
    int         debug_level;  /* Level of debugging                     (default: 0)           */
    uint16_t    port;         /* TCP port on which the server listens   (default: "4433")      */
} opt;

typedef int app_send_fn_t(void *ctx, const unsigned char *buf, size_t len);
typedef int app_receive_fn_t(void *ctx, unsigned char *buf, size_t len);

typedef struct {
    unsigned char                block[128];
    mbedtls_ssl_key_set          key_set;
    mbedtls_cipher_type_t        cipher_type;
    const mbedtls_ssl_context   *ssl;
    size_t                       secret_len;
    mbedtls_ssl_protocol_version protocol_version;
} exported_keys_t;

typedef struct {
    mbedtls_ssl_config      conf;
    mbedtls_x509_crt        crt;
    mbedtls_pk_context      key;
    struct sockaddr_storage addr;
    int                     fd;
} server_st_t;

typedef struct {
    mbedtls_ssl_config  conf;
    mbedtls_x509_crt    crt;
    mbedtls_pk_context  key;
    mbedtls_ssl_context ssl;

    app_send_fn_t    *send_fn;
    app_receive_fn_t *recv_fn;

    int      fd;
    unsigned id;
} client_st_t;

typedef struct {
    const mbedtls_ssl_config *conf;
    app_send_fn_t            *send_fn;
    app_receive_fn_t         *recv_fn;

    int      client_fd;
    unsigned client_id;
} request_args_t;

typedef struct {
    mbedtls_ssl_context *ssl;
    int                  fd;
} send_recv_ctx_t;

void app_export_keys_cb(void *keys_ctx, mbedtls_ssl_key_export_type type, const unsigned char *secret,
                        size_t secret_len, const unsigned char *client_random, const unsigned char *server_random,
                        mbedtls_tls_prf_types tls_prf_type) {
    exported_keys_t *e_keys = (exported_keys_t *)keys_ctx;

    switch (type) {
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        case MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET: {
            // TLS 1.2 master secret export:
            //   - Concatenate server_random || client_random in 'block'
            //   - The role (client/server) does not change this order
            memcpy(e_keys->block, server_random, 32);
            memcpy(e_keys->block + 32, client_random, 32);

            int ret = mbedtls_ssl_export_traffic_keys(e_keys->ssl, &e_keys->key_set, &e_keys->cipher_type, secret,
                                                      secret_len, e_keys->block, tls_prf_type);

            // Clear temporary memory to avoid leaking sensitive material
            mbedtls_platform_zeroize(e_keys->block, 64);

            e_keys->protocol_version = MBEDTLS_SSL_VERSION_TLS1_2;

            if (ret != 0) {
                e_keys->protocol_version = MBEDTLS_SSL_VERSION_UNKNOWN;
                printf(" failed\n  !  mbedtls_ssl_conf_own_cert returned %i.\n", ret);
                fflush(stdout);
            }

            break;
        }
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET: {
            // TLS 1.3 client application traffic secret:
            //   - Concatenate client_secret || server_secret in 'block'
            //   - Order is always client then server, independent of app role
            memcpy(e_keys->block, secret, secret_len);

            if (e_keys->secret_len == 0) {
                // First part of the secret received; store length
                e_keys->secret_len = secret_len;
            } else {
                // Second part received; combine and export traffic keys
                e_keys->secret_len += secret_len;
                int ret = mbedtls_ssl_export_traffic_keys(e_keys->ssl, &e_keys->key_set, &e_keys->cipher_type,
                                                          e_keys->block, e_keys->secret_len, NULL, tls_prf_type);

                // Clear temporary buffer
                mbedtls_platform_zeroize(e_keys->block, e_keys->secret_len);
                e_keys->protocol_version = MBEDTLS_SSL_VERSION_TLS1_3;

                if (ret != 0) {
                    e_keys->protocol_version = MBEDTLS_SSL_VERSION_UNKNOWN;
                    printf(" failed\n  !  mbedtls_ssl_export_traffic_keys returned %i.\n", ret);
                    fflush(stdout);
                }
            }

            break;
        }

        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET: {
            // TLS 1.3 server application traffic secret:
            //   - Append server_secret to 'block' (after client_secret)
            //   - Export keys once both client & server secrets are present
            memcpy(e_keys->block + secret_len, secret, secret_len);

            if (e_keys->secret_len != 0) {
                e_keys->secret_len += secret_len;
                int ret = mbedtls_ssl_export_traffic_keys(e_keys->ssl, &e_keys->key_set, &e_keys->cipher_type,
                                                          e_keys->block, e_keys->secret_len, NULL, tls_prf_type);

                // Clear temporary buffer
                mbedtls_platform_zeroize(e_keys->block, e_keys->secret_len);
                e_keys->protocol_version = MBEDTLS_SSL_VERSION_TLS1_3;

                if (ret != 0) {
                    e_keys->protocol_version = MBEDTLS_SSL_VERSION_UNKNOWN;
                    printf(" failed\n  !  mbedtls_ssl_export_traffic_keys returned %i.\n", ret);
                    fflush(stdout);
                }
            } else {
                // First part (server secret) received; store length for later combination
                e_keys->secret_len = secret_len;
            }

            break;
        }
#endif
        default: {
            // Other export types are ignored
        }
    }
}

int app_recv(void *ctx, unsigned char *buffer, size_t length) {
    send_recv_ctx_t *info = (send_recv_ctx_t *)ctx;
    int              fd   = info->fd;
    int              read = 0;

    while (1) {
        read = (int)recv(fd, buffer, length, MSG_NOSIGNAL);

        if ((read == -1) && (errno == EINTR)) {
            continue; // retry
        }

        break;
    }

    return read;
}

int app_send(void *ctx, const unsigned char *buffer, size_t length) {
    send_recv_ctx_t *info = (send_recv_ctx_t *)ctx;
    int              fd   = info->fd;
    int              sent = 0;

    while (1) {
        sent = (int)send(fd, buffer, length, MSG_NOSIGNAL);

        if ((sent == -1) && (errno == EINTR)) {
            continue; // retry
        }

        break;
    }

    return sent;
}

int app_tls_recv(void *ctx, unsigned char *buffer, size_t length) {
    send_recv_ctx_t *info = (send_recv_ctx_t *)ctx;
    return mbedtls_ssl_read(info->ssl, buffer, length);
}

int app_tls_send(void *ctx, const unsigned char *buffer, size_t length) {
    send_recv_ctx_t *info = (send_recv_ctx_t *)ctx;
    return mbedtls_ssl_write(info->ssl, buffer, length);
}

int app_tls_recv_cb(void *ctx, unsigned char *buffer, size_t length) {
    int fd   = *((int *)ctx);
    int read = 0;

    while (1) {
        read = (int)recv(fd, buffer, length, MSG_NOSIGNAL);

        if (read == -1) {
            if (errno == EINTR) {
                continue; // retry
            }

            printf("failed to read for fd %i. errno %i\n", fd, errno);
            fflush(stdout);
        }

        break;
    }

    return read;
}

int app_tls_send_cb(void *ctx, const unsigned char *buffer, size_t length) {
    int fd   = *((int *)ctx);
    int sent = 0;

    while (1) {
        sent = (int)send(fd, buffer, length, MSG_NOSIGNAL);

        if (sent == -1) {
            if (errno == EINTR) {
                continue; // retry
            }

            printf("failed to send for fd %i. errno %i\n", fd, errno);
            fflush(stdout);
        }

        break;
    }

    return sent;
}

/**
 * \brief Enable Kernel TLS (KTLS) on a given socket for an Mbed TLS session.
 *
 * This function configures both the transmit (TX) and receive (RX) channels
 * for Kernel TLS, using keys exported from an established Mbed TLS session.
 *
 * \param endpoint   Endpoint role — either MBEDTLS_SSL_IS_CLIENT or MBEDTLS_SSL_IS_SERVER.
 * \param e_keys     Pointer to an `exported_keys_t` structure containing:
 *                     - `key_set`: AEAD keys for TX/RX,
 *                     - `cipher_type`: cipher in use (AES-GCM, AES-CCM, etc.),
 *                     - `ssl`: pointer to the source Mbed TLS context,
 *                     - `secret_len`: length of exported secrets,
 *                     - `protocol_version`: TLS version in use.
 * \param fd         File descriptor of the active TCP socket.
 *
 * \note TLS 1.2 vs TLS 1.3 IV handling for KTLS:
 *       In TLS 1.2 AEAD modes (e.g., AES-GCM, CCM), each record carries
 *       an explicit (per-record) IV in the record header. The kernel
 *       automatically constructs the full nonce internally, combining
 *       its own per-record sequence number with the static salt.
 *       Therefore, the IV field is zeroed and its length set to zero.
 *
 *       In TLS 1.3, explicit IVs are removed. Each record IV is derived
 *       as:
 *           record_iv = static_iv XOR sequence_number
 *       Hence, the full static IV must be provided to the kernel during
 *       KTLS setup.
 *
 * \return
 *         - 1 if both TX and RX KTLS channels are successfully configured.
 *         - 0 if only TX channel is configured.
 *         - -1 on error (e.g., unsupported cipher, missing ULP support, etc.).
 */
int enable_ktls(int endpoint, exported_keys_t *e_keys, int fd) {
    if (e_keys->protocol_version == MBEDTLS_SSL_VERSION_UNKNOWN) {
        return -1;
    }

    void     *crypto_info_ptr;
    socklen_t crypto_info_size;

    // Endpoint-specific identifiers
    const char *name;

    unsigned char *tx_key;
    unsigned char *tx_iv;
    unsigned char *tx_salt;

    unsigned char *rx_key;
    unsigned char *rx_iv;
    unsigned char *rx_salt;

    unsigned char *info_iv;
    unsigned char *info_key;
    unsigned char *info_salt;
    unsigned char *info_rec_seq;

    // Lengths of IV, key, salt, and record sequence for the selected cipher
    size_t iv_len;
    size_t key_len;
    size_t salt_len;
    size_t seq_len;

    // Select role-specific key material for TX and RX
    if (endpoint == MBEDTLS_SSL_IS_SERVER) {
        name    = "server";
        tx_key  = e_keys->key_set.server_write_key;
        tx_iv   = e_keys->key_set.server_write_iv;
        tx_salt = e_keys->key_set.server_write_iv;
        rx_key  = e_keys->key_set.client_write_key;
        rx_iv   = e_keys->key_set.client_write_iv;
        rx_salt = e_keys->key_set.client_write_iv;
    } else {
        name    = "client";
        tx_key  = e_keys->key_set.client_write_key;
        tx_iv   = e_keys->key_set.client_write_iv;
        tx_salt = e_keys->key_set.client_write_iv;
        rx_key  = e_keys->key_set.server_write_key;
        rx_iv   = e_keys->key_set.server_write_iv;
        rx_salt = e_keys->key_set.server_write_iv;
    }

    // Attempt to enable KTLS user-level protocol (TCP_ULP)
    if (setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) == 0) {
        /* --- Cipher selection and crypto_info structure preparation --- */
        switch (e_keys->cipher_type) {
            case MBEDTLS_CIPHER_AES_128_GCM: {
                struct tls12_crypto_info_aes_gcm_128 crypto_info;
                crypto_info_ptr              = &crypto_info;
                crypto_info_size             = sizeof(crypto_info);
                crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

                // Set protocol version-specific fields
                if (e_keys->protocol_version == MBEDTLS_SSL_VERSION_TLS1_3) {
                    crypto_info.info.version = TLS_1_3_VERSION;
                    iv_len                   = TLS_CIPHER_AES_GCM_128_IV_SIZE;
                } else {
                    crypto_info.info.version = TLS_1_2_VERSION;
                    iv_len                   = 0;
                    memset(crypto_info.iv, 0, TLS_CIPHER_AES_GCM_128_IV_SIZE);
                }

                key_len  = TLS_CIPHER_AES_GCM_128_KEY_SIZE;
                salt_len = TLS_CIPHER_AES_GCM_128_SALT_SIZE;
                seq_len  = TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE;

                tx_iv += salt_len;
                rx_iv += salt_len;

                info_iv      = crypto_info.iv;
                info_key     = crypto_info.key;
                info_salt    = crypto_info.salt;
                info_rec_seq = crypto_info.rec_seq;

                break;
            }

            case MBEDTLS_CIPHER_AES_256_GCM: {
                struct tls12_crypto_info_aes_gcm_256 crypto_info;
                crypto_info_ptr              = &crypto_info;
                crypto_info_size             = sizeof(crypto_info);
                crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_256;

                // Set protocol version-specific fields
                if (e_keys->protocol_version == MBEDTLS_SSL_VERSION_TLS1_3) {
                    crypto_info.info.version = TLS_1_3_VERSION;
                    iv_len                   = TLS_CIPHER_AES_GCM_256_IV_SIZE;
                } else {
                    crypto_info.info.version = TLS_1_2_VERSION;
                    iv_len                   = 0;
                    memset(crypto_info.iv, 0, TLS_CIPHER_AES_GCM_256_IV_SIZE);
                }

                key_len  = TLS_CIPHER_AES_GCM_256_KEY_SIZE;
                salt_len = TLS_CIPHER_AES_GCM_256_SALT_SIZE;
                seq_len  = TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE;

                tx_iv += salt_len;
                rx_iv += salt_len;

                info_iv      = crypto_info.iv;
                info_key     = crypto_info.key;
                info_salt    = crypto_info.salt;
                info_rec_seq = crypto_info.rec_seq;

                break;
            }

            case MBEDTLS_CIPHER_CHACHA20_POLY1305: {
                struct tls12_crypto_info_chacha20_poly1305 crypto_info;
                crypto_info_ptr              = &crypto_info;
                crypto_info_size             = sizeof(crypto_info);
                crypto_info.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;

                crypto_info.info.version =
                    ((e_keys->protocol_version == MBEDTLS_SSL_VERSION_TLS1_3) ? TLS_1_3_VERSION : TLS_1_2_VERSION);

                iv_len   = TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE;
                key_len  = TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE;
                salt_len = TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE;
                seq_len  = TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE;

                info_iv      = crypto_info.iv;
                info_key     = crypto_info.key;
                info_salt    = crypto_info.salt;
                info_rec_seq = crypto_info.rec_seq;

                break;
            }

            // TLS 1.2 only
            case MBEDTLS_CIPHER_ARIA_128_GCM: {
                struct tls12_crypto_info_aria_gcm_128 crypto_info;
                crypto_info_ptr              = &crypto_info;
                crypto_info_size             = sizeof(crypto_info);
                crypto_info.info.cipher_type = TLS_CIPHER_ARIA_GCM_128;

                crypto_info.info.version = TLS_1_2_VERSION;

                iv_len = 0;
                memset(crypto_info.iv, 0, TLS_CIPHER_ARIA_GCM_128_IV_SIZE);

                key_len  = TLS_CIPHER_ARIA_GCM_128_KEY_SIZE;
                salt_len = TLS_CIPHER_ARIA_GCM_128_SALT_SIZE;
                seq_len  = TLS_CIPHER_ARIA_GCM_128_REC_SEQ_SIZE;

                info_iv      = crypto_info.iv;
                info_key     = crypto_info.key;
                info_salt    = crypto_info.salt;
                info_rec_seq = crypto_info.rec_seq;

                break;
            }

            case MBEDTLS_CIPHER_ARIA_256_GCM: {
                struct tls12_crypto_info_aria_gcm_256 crypto_info;
                crypto_info_ptr              = &crypto_info;
                crypto_info_size             = sizeof(crypto_info);
                crypto_info.info.cipher_type = TLS_CIPHER_ARIA_GCM_256;

                crypto_info.info.version = TLS_1_2_VERSION;

                iv_len = 0;
                memset(crypto_info.iv, 0, TLS_CIPHER_ARIA_GCM_256_IV_SIZE);

                key_len  = TLS_CIPHER_ARIA_GCM_256_KEY_SIZE;
                salt_len = TLS_CIPHER_ARIA_GCM_256_SALT_SIZE;
                seq_len  = TLS_CIPHER_ARIA_GCM_256_REC_SEQ_SIZE;

                info_iv      = crypto_info.iv;
                info_key     = crypto_info.key;
                info_salt    = crypto_info.salt;
                info_rec_seq = crypto_info.rec_seq;

                break;
            }

            case MBEDTLS_CIPHER_AES_128_CCM: {
                struct tls12_crypto_info_aes_ccm_128 crypto_info;
                crypto_info_ptr              = &crypto_info;
                crypto_info_size             = sizeof(crypto_info);
                crypto_info.info.cipher_type = TLS_CIPHER_AES_CCM_128;

                crypto_info.info.version = TLS_1_2_VERSION;

                iv_len = 0;
                memset(crypto_info.iv, 0, TLS_CIPHER_AES_CCM_128_IV_SIZE);

                key_len  = TLS_CIPHER_AES_CCM_128_KEY_SIZE;
                salt_len = TLS_CIPHER_AES_CCM_128_SALT_SIZE;
                seq_len  = TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE;

                info_iv      = crypto_info.iv;
                info_key     = crypto_info.key;
                info_salt    = crypto_info.salt;
                info_rec_seq = crypto_info.rec_seq;

                break;
            }

            default: {
                // Unsupported cipher type; no KTLS configuration
                printf("[%s] failed to configure KTLS for fd %d: cipher not supported.\n", name, fd);
                fflush(stdout);
                return -1;
            }
        }

        const unsigned char *in_seq;
        const unsigned char *out_seq;

        // Retrieve current TLS record sequence numbers.
        mbedtls_ssl_get_sequence_numbers(e_keys->ssl, &in_seq, &out_seq);

        // Configure transmit (TX) channel
        memcpy(info_iv, tx_iv, iv_len);
        memcpy(info_key, tx_key, key_len);
        memcpy(info_salt, tx_salt, salt_len);
        memcpy(info_rec_seq, out_seq, seq_len);

        int res = 0;

        if (setsockopt(fd, SOL_TLS, TLS_TX, crypto_info_ptr, crypto_info_size) == 0) {
            printf("[%s] KTLS transmit channel successfully configured for fd %i.\n", name, fd);

            // Configure receive (RX) channel
            memcpy(info_iv, rx_iv, iv_len);
            memcpy(info_key, rx_key, key_len);
            memcpy(info_salt, rx_salt, salt_len);
            memcpy(info_rec_seq, in_seq, seq_len);

            if (setsockopt(fd, SOL_TLS, TLS_RX, crypto_info_ptr, crypto_info_size) == 0) {
                printf("[%s] KTLS receive channel successfully configured for fd %i.\n", name, fd);
                ++res;
            } else {
                printf("[%s] Failed to configure KTLS receive channel for fd %i.\n", name, fd);
            }
        } else {
            printf("[%s] Failed to configure KTLS transmit channel for fd %i.\n", name, fd);
        }

        mbedtls_platform_zeroize(crypto_info_ptr, crypto_info_size);
        return res;
    }

    fprintf(stderr,
            "[error] Failed to enable Kernel TLS (TCP_ULP) on socket %d: %s (errno=%i). "
            "Ensure the 'tls' kernel module is loaded (try: sudo modprobe tls).\n",
            fd, strerror(errno), errno);

    fflush(stdout);
    return -1;
}

void *process_requests(void *arg) {
    unsigned char       buffer[BUFFER_SIZE];
    request_args_t     *request = (request_args_t *)arg;
    mbedtls_ssl_context client_ssl;
    exported_keys_t     e_keys;
    send_recv_ctx_t     send_recv_ctx;
    const size_t        response_len = strlen(GET_RESPONSE);

    mbedtls_ssl_init(&client_ssl);

    int ret = mbedtls_ssl_setup(&client_ssl, request->conf);

    if (ret == 0) {
        memset(&e_keys, 0, sizeof(exported_keys_t));
        e_keys.ssl = &client_ssl;

        mbedtls_ssl_set_bio(&client_ssl, &request->client_fd, app_tls_send_cb, app_tls_recv_cb, NULL);
        mbedtls_ssl_set_export_keys_cb(&client_ssl, app_export_keys_cb, &e_keys);

        ret = mbedtls_ssl_handshake(&client_ssl);

        if (ret == 0) {
            request->recv_fn  = app_tls_recv;
            request->send_fn  = app_tls_send;
            send_recv_ctx.ssl = &client_ssl;
            send_recv_ctx.fd  = request->client_fd;

            printf("[server] negotiated ciphersuite for client %u: %s.\n", request->client_id,
                   mbedtls_ssl_get_ciphersuite(&client_ssl));
            fflush(stdout);

            ret = enable_ktls(MBEDTLS_SSL_IS_SERVER, &e_keys, request->client_fd);
            mbedtls_platform_zeroize(&e_keys, sizeof(e_keys));

            if (ret >= 0) {
                request->send_fn = app_send;

                if (ret == 1) {
                    request->recv_fn = app_recv;
                }
            }

            unsigned requests = 0;

            do {
                int read          = 0;
                int valid_request = 0;

                do {
                    read = request->recv_fn(&send_recv_ctx, buffer, BUFFER_SIZE);

                    if (read > 0) {
                        ++requests;
                        printf("[server] read %i bytes from client %u (request: %u).\n", read, request->client_id,
                               requests);
                        fflush(stdout);
                    } else {
                        if (read == 0) {
                            printf("[server] client %u disconnected.\n", request->client_id);
                            fflush(stdout);
                        } else if (errno == EAGAIN) {
                            printf("[server] Client %u timed out due to inactivity.\n", request->client_id);
                            fflush(stdout);
                        } else {
                            printf("[server] failed to recv from client %u.\n", request->client_id);
                            fflush(stdout);
                        }

                        break;
                    }

                    int offset = 0;

                    while (offset < read) {
                        // Detect end-of-request markers: \n\n or \r\n\r\n
                        if (buffer[offset] == '\n' && (offset + 1 < read)) {
                            if (buffer[offset + 1] == '\r') {
                                if ((offset + 2 < read) && buffer[offset + 2] == '\n') {
                                    valid_request = 1;
                                    break;
                                }
                            } else if (buffer[offset + 1] == '\n') {
                                valid_request = 1;
                                break;
                            }
                        }
                        ++offset;
                    }
                } while (valid_request == 0);

                if (valid_request == 1) {
                    const int sent =
                        request->send_fn(&send_recv_ctx, (const unsigned char *)GET_RESPONSE, response_len);

                    if (sent > 0) {
                        printf("[server] sent %i bytes to client %u (response: %u).\n", sent, request->client_id,
                               requests);
                        fflush(stdout);
                    } else {
                        printf("[server] failed to send to client %u.\n", request->client_id);
                        fflush(stdout);
                    }

                    continue;
                }
                break;
            } while (1);
        } else {
            printf("server -> client %u handshake failed. error code: %i.\n", request->client_id, ret);
            fflush(stdout);
        }
    } else {
        printf(" failed\n  !  mbedtls_ssl_setup returned %i.\n", ret);
        fflush(stdout);
    }

    close(request->client_fd);
    mbedtls_ssl_free(&client_ssl);

    free(request);

    return NULL;
}

void cleanup_server_ssl(server_st_t *server_st) {
    mbedtls_ssl_config_free(&server_st->conf);
    mbedtls_x509_crt_free(&server_st->crt);
    mbedtls_pk_free(&server_st->key);
}

void cleanup_client_ssl(client_st_t *client_st) {
    mbedtls_ssl_config_free(&client_st->conf);
    mbedtls_ssl_free(&client_st->ssl);
}

void exit_server(server_st_t *server_st, int ret) {
    fflush(stdout);
    cleanup_server_ssl(server_st);
    mbedtls_psa_crypto_free();
    exit(ret);
}

void fatal_error(void *arg, const char *msg) {
    perror(msg);
    exit_server((server_st_t *)arg, EXIT_FAILURE);
}

pthread_t app_create_thread(void *(*fun)(void *), void *arg) {
    pthread_t      thread = 0;
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    const int ret = pthread_create(&thread, &attr, fun, arg);
    pthread_attr_destroy(&attr);

    if (ret != 0) {
        fatal_error(arg, "pthread_create");
    }

    return thread;
}

void *server_accept_task(void *arg) {
    struct timeval            timeout;
    struct sockaddr_storage   client_addr;
    struct sockaddr          *client_addr_ptr    = (struct sockaddr *)&client_addr;
    server_st_t              *server_st          = (server_st_t *)arg;
    const struct sockaddr_in *addr               = (struct sockaddr_in *)&server_st->addr;
    static socklen_t          client_addr_length = sizeof(struct sockaddr_storage);
    char                      ip[64];
    unsigned                  client_id = 0;

    timeout.tv_sec  = 5;
    timeout.tv_usec = 0;

    if (addr->sin_family == AF_INET) {
        inet_ntop(AF_INET, &addr->sin_addr, ip, 64);
        printf("Listening on %s:%i\n", ip, opt.port);
    } else {
        const struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&server_st->addr;
        inet_ntop(AF_INET6, &addr6->sin6_addr, ip, 64);
        printf("Listening on [%s]:%i\n", ip, opt.port);
    }

    fflush(stdout);

    do {
        const int client_fd = accept(server_st->fd, client_addr_ptr, &client_addr_length);

        if (client_fd != -1) {
            ++client_id;
            printf("[server] accepted connection (fd: %i, client:  %u).\n", client_fd, client_id);
            fflush(stdout);

            setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

            request_args_t *request = (request_args_t *)malloc(sizeof(request_args_t));
            request->conf           = &server_st->conf;
            request->client_fd      = client_fd;
            request->client_id      = client_id;

            pthread_t p_id = app_create_thread(process_requests, request);

            if (p_id != 0) {
                pthread_detach(p_id);
            } else {
                free(request);
            }
        } else {
            break;
        }
    } while (1);

    printf("server shutdown.\n");
    fflush(stdout);

    close(server_st->fd);
    cleanup_server_ssl(server_st);

    return NULL;
}

void init_server_ssl(server_st_t *server_st) {
    mbedtls_ssl_config_init(&server_st->conf);
    mbedtls_x509_crt_init(&server_st->crt);
    mbedtls_pk_init(&server_st->key);
}

void init_client_ssl(client_st_t *client_st) {
    mbedtls_ssl_config_init(&client_st->conf);
    mbedtls_ssl_init(&client_st->ssl);
}

void configure_server_cert(server_st_t *server_st) {
    /* Load certificate chain (PEM) */

    int ret = mbedtls_x509_crt_parse_file(&server_st->crt, opt.crt_filename);

    if (ret != 0) {
        printf(" failed\n  !  mbedtls_x509_crt_parse_file returned %i.\n", ret);
        exit_server(server_st, ret);
    }

    ret = mbedtls_pk_parse_keyfile(&server_st->key, opt.key_filename, opt.key_pwd);

    if (ret != 0) {
        printf(" failed\n  !  mbedtls_pk_parse_keyfile returned %i.\n", ret);
        exit_server(server_st, ret);
    }

    ret = mbedtls_ssl_conf_own_cert(&server_st->conf, &server_st->crt, &server_st->key);

    if (ret != 0) {
        printf(" failed\n  !  mbedtls_ssl_conf_own_cert returned %i.\n", ret);
        exit_server(server_st, ret);
    }
}

#if defined(MBEDTLS_DEBUG_C)
pthread_mutex_t debug_mutex;

void server_debug_cb(void *ctx, int level, const char *file, int line, const char *str) {
    ((void)level);
    long int thread_id = (long int)pthread_self();

    pthread_mutex_lock(&debug_mutex);

    ((void)level);
    mbedtls_fprintf((FILE *)ctx, "[server debug]: %s:%04d: [ #%ld ] %s", file, line, thread_id, str);
    fflush((FILE *)ctx);

    pthread_mutex_unlock(&debug_mutex);
}

void client_debug_cb(void *ctx, int level, const char *file, int line, const char *str) {
    ((void)level);
    long int thread_id = (long int)pthread_self();

    pthread_mutex_lock(&debug_mutex);

    ((void)level);
    mbedtls_fprintf((FILE *)ctx, "[client debug]: %s:%04d: [ #%ld ] %s", file, line, thread_id, str);
    fflush((FILE *)ctx);

    pthread_mutex_unlock(&debug_mutex);
}
#endif

void setup_server_ssl(server_st_t *server_st) {
    int ret;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg(&server_st->conf, server_debug_cb, stdout);
#endif

    ret = mbedtls_ssl_config_defaults(&server_st->conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);

    if (ret != 0) {
        printf(" failed\n  !  mbedtls_ssl_config_defaults returned %i.\n", ret);
        exit_server(server_st, ret);
    }

    mbedtls_ssl_conf_preference_order(&server_st->conf, MBEDTLS_SSL_SRV_CIPHERSUITE_ORDER_CLIENT);
    mbedtls_ssl_conf_renegotiation(&server_st->conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
    mbedtls_ssl_conf_session_tickets(&server_st->conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);

    configure_server_cert(server_st);
    mbedtls_ssl_conf_min_tls_version(&server_st->conf, MBEDTLS_SSL_VERSION_TLS1_2);
}

void setup_client_ssl(client_st_t *client_st) {
    int ret;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg(&client_st->conf, client_debug_cb, stdout);
#endif

    ret = mbedtls_ssl_config_defaults(&client_st->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);

    if (ret != 0) {
        printf(" failed\n  !  mbedtls_ssl_config_defaults for client returned %i.\n", ret);
        fflush(stdout);
        return;
    }

    mbedtls_ssl_conf_authmode(&client_st->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_renegotiation(&client_st->conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
    mbedtls_ssl_conf_session_tickets(&client_st->conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
}

pthread_t run_server(server_st_t *server_st, int *started) {
    const int enable = 1;
    int       ret;

    int         is_v6 = 0;
    const char *ip    = opt.ip;

    if (ip) {
        while (*ip) {
            if (*ip == ':') {
                is_v6 = 1;
                break;
            }
            ++ip;
        }
    }

    if (is_v6 == 1) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&server_st->addr;
        addr->sin6_family         = AF_INET6;

        addr->sin6_port = htons(opt.port);
        ret             = inet_pton(AF_INET6, opt.ip, &addr->sin6_addr);
    } else {
        struct sockaddr_in *addr = (struct sockaddr_in *)&server_st->addr;
        addr->sin_family         = AF_INET;

        addr->sin_port = htons(opt.port);
        ret            = inet_pton(AF_INET, opt.ip, &addr->sin_addr);
    }

    if (ret != 1) {
        fatal_error(server_st, " incorrect ip address used");
    }

    server_st->fd = socket(is_v6 == 1 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);

    if (server_st->fd == -1) {
        fatal_error(server_st, "run_server socket");
    }

    ret = setsockopt(server_st->fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    if (ret == -1) {
        close(server_st->fd);
        fatal_error(server_st, "setsockopt(SO_REUSEADDR)");
    }

    setsockopt(server_st->fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));

    ret = bind(server_st->fd, (struct sockaddr *)&server_st->addr, sizeof(server_st->addr));

    if (ret == -1) {
        close(server_st->fd);
        fatal_error(server_st, "bind");
    }

    ret = listen(server_st->fd, 8); // no need for bigger queue here

    if (ret == -1) {
        close(server_st->fd);
        fatal_error(server_st, "listen");
    }

    // Wake the waiting client thread once the server socket is listening
    __atomic_store_n(started, 1, __ATOMIC_RELEASE);
    long syscall_ret = syscall(SYS_futex, started, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);

    if (syscall_ret == -1) {
        close(server_st->fd);
        fatal_error(server_st, "SYS_futex");
    }

    return app_create_thread(server_accept_task, server_st);
}

void client_send_and_receive(client_st_t *client_st) {
    unsigned char   buffer[BUFFER_SIZE];
    exported_keys_t e_keys;
    send_recv_ctx_t send_recv_ctx;
    const size_t    response_len = strlen(GET_RESPONSE);
    const size_t    request_len  = strlen(GET_REQUEST);

    memset(&e_keys, 0, sizeof(exported_keys_t));
    e_keys.ssl = &client_st->ssl;

    mbedtls_ssl_set_bio(&client_st->ssl, &client_st->fd, app_tls_send_cb, app_tls_recv_cb, NULL);
    // Register key export callback to demonstrate KTLS key extraction
    mbedtls_ssl_set_export_keys_cb(&client_st->ssl, app_export_keys_cb, &e_keys);

    int ret = mbedtls_ssl_handshake(&client_st->ssl);

    if (ret == 0) {
        const unsigned max_requests_count = 5;
        unsigned       requests           = 0;

        client_st->recv_fn = app_tls_recv;
        client_st->send_fn = app_tls_send;
        send_recv_ctx.ssl  = &client_st->ssl;
        send_recv_ctx.fd   = client_st->fd;

        while (requests < max_requests_count) {
            int response_length = response_len;

            ++requests;

            const int sent = client_st->send_fn(&send_recv_ctx, (const unsigned char *)GET_REQUEST, request_len);

            if (sent > 0) {
                printf("[client %u] sent %i bytes (request: %u).\n", client_st->id, sent, requests);
                fflush(stdout);
            } else {
                printf("[client %u] failed to send.\n", client_st->id);
                fflush(stdout);
            }

            if (requests == 3) {
                /*
                 * Mid-session KTLS activation.
                 *
                 * This transition occurs after several encrypted
                 * application records have already been exchanged —
                 * sequence numbers are therefore non-zero. From this
                 * point onward, encryption and decryption are handled
                 * directly by the Linux Kernel TLS (KTLS).
                 *
                 * The active traffic keys and IVs are exported from
                 * Mbed TLS and installed into the socket via TLS_TX and
                 * TLS_RX. User-space record handling ceases entirely,
                 * yet the session state remains uninterrupted.
                 *
                 * In the event log, this is reflected by:
                 *   [client] KTLS transmit channel successfully configured...
                 *   [client] KTLS receive channel successfully configured...
                 * indicating that kernel-level crypto now manages the
                 * connection mid-flight.
                 */
                ret = enable_ktls(MBEDTLS_SSL_IS_CLIENT, &e_keys, client_st->fd);
                mbedtls_platform_zeroize(&e_keys, sizeof(e_keys));

                if (ret >= 0) {
                    client_st->send_fn = app_send;

                    if (ret == 1) {
                        client_st->recv_fn = app_recv;
                    }
                }
            }

            do {
                const int read = client_st->recv_fn(&send_recv_ctx, buffer, BUFFER_SIZE);

                if (read > 0) {
                    response_length -= read;
                    printf("[client %u] read %i bytes (response: %u).\n", client_st->id, read, requests);
                    fflush(stdout);

                    if (response_length == 0) {
                        break;
                    }

                    continue;
                }

                printf("[client %u] failed to recv.\n", client_st->id);
                fflush(stdout);
                requests = max_requests_count;
                break;
            } while (1);
        }
    } else {
        printf("client %u -> server handshake failed. error code: %i.\n", client_st->id, ret);
        fflush(stdout);
    }
}

void start_request(client_st_t *client_st, const struct sockaddr_storage *server_sockaddr, unsigned *client_id) {
    struct timeval timeout;
    timeout.tv_sec  = 5;
    timeout.tv_usec = 0;

    const int enable = 1;
    int       ret;

    client_st->fd = socket(AF_INET, SOCK_STREAM, 0);

    if (client_st->fd == -1) {
        perror("send_requests socket");
        mbedtls_ssl_session_reset(&client_st->ssl);
        return;
    }

    ret = connect(client_st->fd, (struct sockaddr *)server_sockaddr, sizeof(struct sockaddr_storage));

    if (ret == -1) {
        perror("connect");
        close(client_st->fd);
        mbedtls_ssl_session_reset(&client_st->ssl);
        return;
    }

    setsockopt(client_st->fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
    setsockopt(client_st->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client_st->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    ++(*client_id);
    client_st->id = *client_id;

    client_send_and_receive(client_st);
    close(client_st->fd);
    mbedtls_ssl_session_reset(&client_st->ssl);
}

void send_requests(const struct sockaddr_storage *server_sockaddr) {
    unsigned    client_id = 0;
    client_st_t client_st;
    int         ret;

    static int ciphers[3] = {0, 0, 0};

    memset(&client_st, 0, sizeof(client_st_t));

    init_client_ssl(&client_st);
    setup_client_ssl(&client_st);
    mbedtls_ssl_conf_ciphersuites(&client_st.conf, ciphers);

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    /* TLS 1.3 */
    mbedtls_ssl_conf_max_tls_version(&client_st.conf, MBEDTLS_SSL_VERSION_TLS1_3);

    /* TLS 1.3 CHACHA20_POLY1305 */
    ciphers[0] = MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256;
    ret        = mbedtls_ssl_setup(&client_st.ssl, &client_st.conf);

    if (ret != 0) {
        printf(" failed\n  !  mbedtls_ssl_setup  for client returned %i.\n", ret);
        fflush(stdout);
        return;
    }

    start_request(&client_st, server_sockaddr, &client_id);

    /* TLS 1.3 AES_256_GCM */
    ciphers[0] = MBEDTLS_TLS1_3_AES_256_GCM_SHA384;
    ret        = mbedtls_ssl_setup(&client_st.ssl, &client_st.conf);

    if (ret != 0) {
        printf(" failed\n  !  mbedtls_ssl_setup  for client returned %i.\n", ret);
        fflush(stdout);
        return;
    }

    start_request(&client_st, server_sockaddr, &client_id);

    /* TLS 1.3 AES_128_GCM */
    ciphers[0] = MBEDTLS_TLS1_3_AES_128_GCM_SHA256;

    ret = mbedtls_ssl_setup(&client_st.ssl, &client_st.conf);
    if (ret != 0) {
        printf(" failed\n  !  mbedtls_ssl_setup  for client returned %i.\n", ret);
        fflush(stdout);
        return;
    }

    start_request(&client_st, server_sockaddr, &client_id);
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    /* TLS 1.2 */

    mbedtls_ssl_conf_max_tls_version(&client_st.conf, MBEDTLS_SSL_VERSION_TLS1_2);

    // /* TLS 1.2 CHACHA20_POLY1305 */
    ciphers[0] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
    ciphers[1] = MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    ret        = mbedtls_ssl_setup(&client_st.ssl, &client_st.conf);

    if (ret != 0) {
        printf(" failed\n  !  mbedtls_ssl_setup  for client returned %i.\n", ret);
        fflush(stdout);
        return;
    }

    start_request(&client_st, server_sockaddr, &client_id);

    // /* TLS 1.2 AES_256_GCM */
    ciphers[0] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    ciphers[1] = MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
    ret        = mbedtls_ssl_setup(&client_st.ssl, &client_st.conf);

    if (ret != 0) {
        printf(" failed\n  !  mbedtls_ssl_setup  for client returned %i.\n", ret);
        fflush(stdout);
        return;
    }

    start_request(&client_st, server_sockaddr, &client_id);

    // /* TLS 1.2 AES_128_GCM */
    ciphers[0] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    ciphers[1] = MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    ret        = mbedtls_ssl_setup(&client_st.ssl, &client_st.conf);

    if (ret != 0) {
        printf(" failed\n  !  mbedtls_ssl_setup  for client returned %i.\n", ret);
        fflush(stdout);
        return;
    }

    start_request(&client_st, server_sockaddr, &client_id);

    /* TLS 1.2 AES_128_CCM */
    ciphers[0] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM;
    ciphers[1] = MBEDTLS_TLS_PSK_WITH_AES_128_CCM;
    ret        = mbedtls_ssl_setup(&client_st.ssl, &client_st.conf);

    if (ret != 0) {
        printf(" failed\n  !  mbedtls_ssl_setup  for client returned %i.\n", ret);
        fflush(stdout);
        return;
    }

    start_request(&client_st, server_sockaddr, &client_id);

    /* TLS 1.2 ARIA_128_GCM */
    ciphers[0] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256;
    ciphers[1] = MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256;
    ret        = mbedtls_ssl_setup(&client_st.ssl, &client_st.conf);

    if (ret != 0) {
        printf(" failed\n  !  mbedtls_ssl_setup  for client returned %i.\n", ret);
        fflush(stdout);
        return;
    }

    start_request(&client_st, server_sockaddr, &client_id);

    // /* TLS 1.2 ARIA_128_GCM */
    ciphers[0] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384;
    ciphers[1] = MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384;
    ret        = mbedtls_ssl_setup(&client_st.ssl, &client_st.conf);

    if (ret != 0) {
        printf(" failed\n  !  mbedtls_ssl_setup  for client returned %i.\n", ret);
        fflush(stdout);
        return;
    }

    start_request(&client_st, server_sockaddr, &client_id);
#endif

    cleanup_client_ssl(&client_st);
}

int main(int argc, char *argv[]) {
    // Initialize options with defaults
    opt.ip           = DFL_IP;
    opt.crt_filename = DFL_CRT_FILENAME;
    opt.key_filename = DFL_KEY_FILENAME;
    opt.key_pwd      = DFL_KEY_PWD;
    opt.port         = DFL_PORT;
    opt.debug_level  = DFL_DEBUG_LEVEL;

    // Help requested
    if (argc == 2 && (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        printf(USAGE);
        fflush(stdout);
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        char *param = argv[i];
        char *value = strchr(param, '=');

        if (value == NULL) {
            printf("Parameter requires a value: '%s'\n", param);
            printf(USAGE);
            return 1;
        }

        *value++ = '\0'; // Split into key=value

        if (strcmp(param, "ip") == 0) {
            opt.ip = value;
        } else if (strcmp(param, "crt_filename") == 0) {
            opt.crt_filename = value;
        } else if (strcmp(param, "key_filename") == 0) {
            opt.key_filename = value;
        } else if (strcmp(param, "key_pwd") == 0) {
            opt.key_pwd = value;
        } else if (strcmp(param, "port") == 0) {
            char         *endptr;
            unsigned long val = strtoul(value, &endptr, 10);
            if (*endptr != '\0' || val > 65535) {
                fprintf(stderr, "Invalid integer value for port: '%s'\n", value);
                return 1;
            }
            opt.port = (uint16_t)val;
        } else if (strcmp(param, "debug_level") == 0) {
            char         *endptr;
            unsigned long val = strtoul(value, &endptr, 10);
            if (*endptr != '\0' || val > 4) {
                fprintf(stderr, "Invalid integer value for debug_level: '%s'\n", value);
                return 1;
            }
            opt.debug_level = (int)val;
        } else {
            fprintf(stderr, "Unknown parameter: '%s'\n", param);
            printf(USAGE);
            fflush(stdout);
            return 1;
        }
    }

    server_st_t server_st;
    memset(&server_st, 0, sizeof(server_st_t));

    int server_started = 0;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(opt.debug_level);
#endif

    int ret = psa_crypto_init();

    if (ret != PSA_SUCCESS) {
        exit(MBEDTLS_ERR_SSL_HW_ACCEL_FAILED);
    }

    init_server_ssl(&server_st);
    setup_server_ssl(&server_st);
    signal(SIGPIPE, SIG_IGN); /* Ignore SIGPIPE */

    pthread_t server_thread = run_server(&server_st, &server_started);

    const int expected = 0;

    while (1) {
        const int current = __atomic_load_n(&server_started, __ATOMIC_ACQUIRE);

        if (current != expected) {
            break;
        }

        const long syscall_ret =
            syscall(SYS_futex, &server_started, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, expected, NULL, NULL, 0);

        if (syscall_ret == -1) {
            if ((errno == EINTR) || (errno == EAGAIN)) {
                continue; // retry
            }

            fatal_error(&server_st, "futex_wait");
        }

        break;
    }

    send_requests(&server_st.addr);

    if (server_thread != 0) {
        pthread_join(server_thread, NULL);
    }

    mbedtls_psa_crypto_free();

    return 0;
}

#endif
