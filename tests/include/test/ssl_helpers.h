/** \file ssl_helpers.h
 *
 * \brief This file contains helper functions to set up a TLS connection.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef SSL_HELPERS_H
#define SSL_HELPERS_H

#include <string.h>

#include <test/helpers.h>
#include <test/macros.h>
#include <test/random.h>
#include <test/psa_crypto_helpers.h>

#if defined(MBEDTLS_SSL_TLS_C)
#include <mbedtls/ssl_internal.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/certs.h>
#include <mbedtls/timing.h>
#include <mbedtls/debug.h>
#include <ssl_tls13_keys.h>

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED)
#define MBEDTLS_CAN_HANDLE_RSA_TEST_KEY
#endif

enum {
#define MBEDTLS_SSL_TLS1_3_LABEL(name, string)   \
    tls1_3_label_ ## name,
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
#undef MBEDTLS_SSL_TLS1_3_LABEL
};

typedef struct mbedtls_test_ssl_log_pattern {
    const char *pattern;
    size_t counter;
} mbedtls_test_ssl_log_pattern;

/* Invalid minor version used when not specifying a min/max version or expecting a test to fail */
#define TEST_SSL_MINOR_VERSION_NONE -1

typedef struct mbedtls_test_handshake_test_options {
    const char *cipher;
    int client_min_version;
    int client_max_version;
    int server_min_version;
    int server_max_version;
    int expected_negotiated_version;
    int pk_alg;
    data_t *psk_str;
    int dtls;
    int srv_auth_mode;
    int serialize;
    int mfl;
    int cli_msg_len;
    int srv_msg_len;
    int expected_cli_fragments;
    int expected_srv_fragments;
    int renegotiate;
    int legacy_renegotiation;
    void *srv_log_obj;
    void *cli_log_obj;
    void (*srv_log_fun)(void *, int, const char *, int, const char *);
    void (*cli_log_fun)(void *, int, const char *, int, const char *);
    int resize_buffers;
} mbedtls_test_handshake_test_options;

/*
 * Buffer structure for custom I/O callbacks.
 */
typedef struct mbedtls_test_ssl_buffer {
    size_t start;
    size_t content_length;
    size_t capacity;
    unsigned char *buffer;
} mbedtls_test_ssl_buffer;

/*
 * Context for a message metadata queue (fifo) that is on top of the ring buffer.
 */
typedef struct mbedtls_test_ssl_message_queue {
    size_t *messages;
    int pos;
    int num;
    int capacity;
} mbedtls_test_ssl_message_queue;

/*
 * Context for the I/O callbacks simulating network connection.
 */

#define MBEDTLS_MOCK_SOCKET_CONNECTED 1

typedef struct mbedtls_test_mock_socket {
    int status;
    mbedtls_test_ssl_buffer *input;
    mbedtls_test_ssl_buffer *output;
    struct mbedtls_test_mock_socket *peer;
} mbedtls_test_mock_socket;

/* Errors used in the message socket mocks */

#define MBEDTLS_TEST_ERROR_CONTEXT_ERROR -55
#define MBEDTLS_TEST_ERROR_SEND_FAILED -66
#define MBEDTLS_TEST_ERROR_RECV_FAILED -77

/*
 * Structure used as an addon, or a wrapper, around the mocked sockets.
 * Contains an input queue, to which the other socket pushes metadata,
 * and an output queue, to which this one pushes metadata. This context is
 * considered as an owner of the input queue only, which is initialized and
 * freed in the respective setup and free calls.
 */
typedef struct mbedtls_test_message_socket_context {
    mbedtls_test_ssl_message_queue *queue_input;
    mbedtls_test_ssl_message_queue *queue_output;
    mbedtls_test_mock_socket *socket;
} mbedtls_test_message_socket_context;

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && \
    defined(MBEDTLS_CERTS_C) && \
    defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_CTR_DRBG_C)

/*
 * Structure with endpoint's certificates for SSL communication tests.
 */
typedef struct mbedtls_test_ssl_endpoint_certificate {
    mbedtls_x509_crt *ca_cert;
    mbedtls_x509_crt *cert;
    mbedtls_pk_context *pkey;
} mbedtls_test_ssl_endpoint_certificate;

/*
 * Endpoint structure for SSL communication tests.
 */
typedef struct mbedtls_test_ssl_endpoint {
    const char *name;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_test_mock_socket socket;
    mbedtls_test_ssl_endpoint_certificate cert;
} mbedtls_test_ssl_endpoint;

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED && MBEDTLS_CERTS_C &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */

/*
 * This function can be passed to mbedtls to receive output logs from it. In
 * this case, it will count the instances of a mbedtls_test_ssl_log_pattern
 * in the received logged messages.
 */
void mbedtls_test_ssl_log_analyzer(void *ctx, int level,
                                   const char *file, int line,
                                   const char *str);

void mbedtls_test_init_handshake_options(
    mbedtls_test_handshake_test_options *opts);

/*
 * Initialises \p buf. After calling this function it is safe to call
 * `mbedtls_test_ssl_buffer_free()` on \p buf.
 */
void mbedtls_test_ssl_buffer_init(mbedtls_test_ssl_buffer *buf);

/*
 * Sets up \p buf. After calling this function it is safe to call
 * `mbedtls_test_ssl_buffer_put()` and `mbedtls_test_ssl_buffer_get()`
 * on \p buf.
 */
int mbedtls_test_ssl_buffer_setup(mbedtls_test_ssl_buffer *buf,
                                  size_t capacity);

void mbedtls_test_ssl_buffer_free(mbedtls_test_ssl_buffer *buf);

/*
 * Puts \p input_len bytes from the \p input buffer into the ring buffer \p buf.
 *
 * \p buf must have been initialized and set up by calling
 * `mbedtls_test_ssl_buffer_init()` and `mbedtls_test_ssl_buffer_setup()`.
 *
 * \retval  \p input_len, if the data fits.
 * \retval  0 <= value < \p input_len, if the data does not fit.
 * \retval  -1, if \p buf is NULL, it hasn't been set up or \p input_len is not
 *          zero and \p input is NULL.
 */
int mbedtls_test_ssl_buffer_put(mbedtls_test_ssl_buffer *buf,
                                const unsigned char *input, size_t input_len);

/*
 * Gets \p output_len bytes from the ring buffer \p buf into the
 * \p output buffer. The output buffer can be NULL, in this case a part of the
 * ring buffer will be dropped, if the requested length is available.
 *
 * \p buf must have been initialized and set up by calling
 * `mbedtls_test_ssl_buffer_init()` and `mbedtls_test_ssl_buffer_setup()`.
 *
 * \retval  \p output_len, if the data is available.
 * \retval  0 <= value < \p output_len, if the data is not available.
 * \retval  -1, if \buf is NULL or it hasn't been set up.
 */
int mbedtls_test_ssl_buffer_get(mbedtls_test_ssl_buffer *buf,
                                unsigned char *output, size_t output_len);

/*
 * Errors used in the message transport mock tests
 */
 #define MBEDTLS_TEST_ERROR_ARG_NULL -11
 #define MBEDTLS_TEST_ERROR_MESSAGE_TRUNCATED -44

/*
 * Setup and free functions for the message metadata queue.
 *
 * \p capacity describes the number of message metadata chunks that can be held
 *    within the queue.
 *
 * \retval  0, if a metadata queue of a given length can be allocated.
 * \retval  MBEDTLS_ERR_SSL_ALLOC_FAILED, if allocation failed.
 */
int mbedtls_test_ssl_message_queue_setup(
    mbedtls_test_ssl_message_queue *queue, size_t capacity);

void mbedtls_test_ssl_message_queue_free(
    mbedtls_test_ssl_message_queue *queue);

/*
 * Push message length information onto the message metadata queue.
 * This will become the last element to leave it (fifo).
 *
 * \retval  MBEDTLS_TEST_ERROR_ARG_NULL, if the queue is null.
 * \retval  MBEDTLS_ERR_SSL_WANT_WRITE, if the queue is full.
 * \retval  \p len, if the push was successful.
 */
int mbedtls_test_ssl_message_queue_push_info(
    mbedtls_test_ssl_message_queue *queue, size_t len);

/*
 * Pop information about the next message length from the queue. This will be
 * the oldest inserted message length(fifo). \p msg_len can be null, in which
 * case the data will be popped from the queue but not copied anywhere.
 *
 * \retval  MBEDTLS_TEST_ERROR_ARG_NULL, if the queue is null.
 * \retval  MBEDTLS_ERR_SSL_WANT_READ, if the queue is empty.
 * \retval  message length, if the pop was successful, up to the given
            \p buf_len.
 */
int mbedtls_test_ssl_message_queue_pop_info(
    mbedtls_test_ssl_message_queue *queue, size_t buf_len);

/*
 * Setup and teardown functions for mock sockets.
 */
void mbedtls_test_mock_socket_init(mbedtls_test_mock_socket *socket);

/*
 * Closes the socket \p socket.
 *
 * \p socket must have been previously initialized by calling
 * mbedtls_test_mock_socket_init().
 *
 * This function frees all allocated resources and both sockets are aware of the
 * new connection state.
 *
 * That is, this function does not simulate half-open TCP connections and the
 * phenomenon that when closing a UDP connection the peer is not aware of the
 * connection having been closed.
 */
void mbedtls_test_mock_socket_close(mbedtls_test_mock_socket *socket);

/*
 * Establishes a connection between \p peer1 and \p peer2.
 *
 * \p peer1 and \p peer2 must have been previously initialized by calling
 * mbedtls_test_mock_socket_init().
 *
 * The capacities of the internal buffers are set to \p bufsize. Setting this to
 * the correct value allows for simulation of MTU, sanity testing the mock
 * implementation and mocking TCP connections with lower memory cost.
 */
int mbedtls_test_mock_socket_connect(mbedtls_test_mock_socket *peer1,
                                     mbedtls_test_mock_socket *peer2,
                                     size_t bufsize);

/*
 * Callbacks for simulating blocking I/O over connection-oriented transport.
 */
int mbedtls_test_mock_tcp_send_b(void *ctx,
                                 const unsigned char *buf, size_t len);

int mbedtls_test_mock_tcp_recv_b(void *ctx, unsigned char *buf, size_t len);

/*
 * Callbacks for simulating non-blocking I/O over connection-oriented transport.
 */
int mbedtls_test_mock_tcp_send_nb(void *ctx,
                                  const unsigned char *buf, size_t len);

int mbedtls_test_mock_tcp_recv_nb(void *ctx, unsigned char *buf, size_t len);

void mbedtls_test_message_socket_init(
    mbedtls_test_message_socket_context *ctx);

/*
 * Setup a given message socket context including initialization of
 * input/output queues to a chosen capacity of messages. Also set the
 * corresponding mock socket.
 *
 * \retval  0, if everything succeeds.
 * \retval  MBEDTLS_ERR_SSL_ALLOC_FAILED, if allocation of a message
 *          queue failed.
 */
int mbedtls_test_message_socket_setup(
    mbedtls_test_ssl_message_queue *queue_input,
    mbedtls_test_ssl_message_queue *queue_output,
    size_t queue_capacity,
    mbedtls_test_mock_socket *socket,
    mbedtls_test_message_socket_context *ctx);

/*
 * Close a given message socket context, along with the socket itself. Free the
 * memory allocated by the input queue.
 */
void mbedtls_test_message_socket_close(
    mbedtls_test_message_socket_context *ctx);

/*
 * Send one message through a given message socket context.
 *
 * \retval  \p len, if everything succeeds.
 * \retval  MBEDTLS_TEST_ERROR_CONTEXT_ERROR, if any of the needed context
 *          elements or the context itself is null.
 * \retval  MBEDTLS_TEST_ERROR_SEND_FAILED if
 *          mbedtls_test_mock_tcp_send_b failed.
 * \retval  MBEDTLS_ERR_SSL_WANT_WRITE, if the output queue is full.
 *
 * This function will also return any error from
 * mbedtls_test_ssl_message_queue_push_info.
 */
int mbedtls_test_mock_tcp_send_msg(void *ctx,
                                   const unsigned char *buf, size_t len);

/*
 * Receive one message from a given message socket context and return message
 * length or an error.
 *
 * \retval  message length, if everything succeeds.
 * \retval  MBEDTLS_TEST_ERROR_CONTEXT_ERROR, if any of the needed context
 *          elements or the context itself is null.
 * \retval  MBEDTLS_TEST_ERROR_RECV_FAILED if
 *          mbedtls_test_mock_tcp_recv_b failed.
 *
 * This function will also return any error other than
 * MBEDTLS_TEST_ERROR_MESSAGE_TRUNCATED from test_ssl_message_queue_peek_info.
 */
int mbedtls_test_mock_tcp_recv_msg(void *ctx,
                                   unsigned char *buf, size_t buf_len);

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && \
    defined(MBEDTLS_CERTS_C) && \
    defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_CTR_DRBG_C)

/*
 * Initializes \p ep_cert structure and assigns it to endpoint
 * represented by \p ep.
 *
 * \retval  0 on success, otherwise error code.
 */
int mbedtls_test_ssl_endpoint_certificate_init(mbedtls_test_ssl_endpoint *ep,
                                               int pk_alg);

/*
 * Initializes \p ep structure. It is important to call
 * `mbedtls_test_ssl_endpoint_free()` after calling this function
 * even if it fails.
 *
 * \p endpoint_type must be set as MBEDTLS_SSL_IS_SERVER or
 * MBEDTLS_SSL_IS_CLIENT.
 * \p pk_alg the algorithm to use, currently only MBEDTLS_PK_RSA and
 * MBEDTLS_PK_ECDSA are supported.
 * \p dtls_context - in case of DTLS - this is the context handling metadata.
 * \p input_queue - used only in case of DTLS.
 * \p output_queue - used only in case of DTLS.
 *
 * \retval  0 on success, otherwise error code.
 */
int mbedtls_test_ssl_endpoint_init(
    mbedtls_test_ssl_endpoint *ep, int endpoint_type, int pk_alg,
    mbedtls_test_message_socket_context *dtls_context,
    mbedtls_test_ssl_message_queue *input_queue,
    mbedtls_test_ssl_message_queue *output_queue,
    const mbedtls_ecp_group_id *curves);

/*
 * Deinitializes endpoint represented by \p ep.
 */
void mbedtls_test_ssl_endpoint_free(
    mbedtls_test_ssl_endpoint *ep,
    mbedtls_test_message_socket_context *context);

/*
 * This function moves ssl handshake from \p ssl to prescribed \p state.
 * /p second_ssl is used as second endpoint and their sockets have to be
 * connected before calling this function.
 *
 * \retval  0 on success, otherwise error code.
 */
int mbedtls_test_move_handshake_to_state(mbedtls_ssl_context *ssl,
                                         mbedtls_ssl_context *second_ssl,
                                         int state);

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED && MBEDTLS_CERTS_C &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */

/*
 * Helper function setting up inverse record transformations
 * using given cipher, hash, EtM mode, authentication tag length,
 * and version.
 */

#define CHK(x)                                  \
    do                                          \
    {                                           \
        if (!(x))                               \
        {                                       \
            ret = -1;                           \
            goto cleanup;                       \
        }                                       \
    } while (0)

#if MBEDTLS_SSL_CID_OUT_LEN_MAX > MBEDTLS_SSL_CID_IN_LEN_MAX
#define SSL_CID_LEN_MIN MBEDTLS_SSL_CID_IN_LEN_MAX
#else
#define SSL_CID_LEN_MIN MBEDTLS_SSL_CID_OUT_LEN_MAX
#endif

int mbedtls_test_ssl_build_transforms(mbedtls_ssl_transform *t_in,
                                      mbedtls_ssl_transform *t_out,
                                      int cipher_type, int hash_id,
                                      int etm, int tag_mode, int ver,
                                      size_t cid0_len,
                                      size_t cid1_len);

#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
/**
 * \param[in,out] record        The record to prepare.
 *                              It must contain the data to MAC at offset
 *                              `record->data_offset`, of length
 *                              `record->data_length`.
 *                              On success, write the MAC immediately
 *                              after the data and increment
 *                              `record->data_length` accordingly.
 * \param[in,out] transform_out The out transform, typically prepared by
 *                              mbedtls_test_ssl_build_transforms().
 *                              Its HMAC context may be used. Other than that
 *                              it is treated as an input parameter.
 *
 * \return                      0 on success, an `MBEDTLS_ERR_xxx` error code
 *                              or -1 on error.
 */
int mbedtls_test_ssl_prepare_record_mac(mbedtls_record *record,
                                        mbedtls_ssl_transform *transform_out);
#endif /* MBEDTLS_SSL_SOME_MODES_USE_MAC */

/*
 * Populate a session structure for serialization tests.
 * Choose dummy values, mostly non-0 to distinguish from the init default.
 */
int mbedtls_test_ssl_populate_session(mbedtls_ssl_session *session,
                                      int ticket_len,
                                      const char *crt_file);

/*
 * Perform data exchanging between \p ssl_1 and \p ssl_2 and check if the
 * message was sent in the correct number of fragments.
 *
 * /p ssl_1 and /p ssl_2    Endpoints represented by mbedtls_ssl_context. Both
 *                          of them must be initialized and connected
 *                          beforehand.
 * /p msg_len_1 and /p msg_len_2 specify the size of the message to send.
 * /p expected_fragments_1 and /p expected_fragments_2 determine in how many
 *                          fragments the message should be sent.
 *      expected_fragments is 0: can be used for DTLS testing while the message
 *                          size is larger than MFL. In that case the message
 *                          cannot be fragmented and sent to the second
 *                          endpoint.
 *                          This value can be used for negative tests.
 *      expected_fragments is 1: can be used for TLS/DTLS testing while the
 *                          message size is below MFL
 *      expected_fragments > 1: can be used for TLS testing while the message
 *                          size is larger than MFL
 *
 * \retval  0 on success, otherwise error code.
 */
int mbedtls_test_ssl_exchange_data(
    mbedtls_ssl_context *ssl_1,
    int msg_len_1, const int expected_fragments_1,
    mbedtls_ssl_context *ssl_2,
    int msg_len_2, const int expected_fragments_2);

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && \
    defined(MBEDTLS_CERTS_C) && \
    defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_CTR_DRBG_C)
void mbedtls_test_ssl_perform_handshake(
    mbedtls_test_handshake_test_options *options);
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED && MBEDTLS_CERTS_C &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_SSL_TLS_C */

#endif /* SSL_HELPERS_H */
