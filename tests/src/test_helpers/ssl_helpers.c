/** \file ssl_helpers.c
 *
 * \brief Helper functions to set up a TLS connection.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <test/ssl_helpers.h>

#include <limits.h>

#if defined(MBEDTLS_SSL_TLS_C)

void mbedtls_test_ssl_log_analyzer(void *ctx, int level,
                                   const char *file, int line,
                                   const char *str)
{
    mbedtls_test_ssl_log_pattern *p = (mbedtls_test_ssl_log_pattern *) ctx;

    (void) level;
    (void) line;
    (void) file;

    if (NULL != p &&
        NULL != p->pattern &&
        NULL != strstr(str, p->pattern)) {
        p->counter++;
    }
}

void mbedtls_test_init_handshake_options(
    mbedtls_test_handshake_test_options *opts)
{
    opts->cipher = "";
    opts->client_min_version = TEST_SSL_MINOR_VERSION_NONE;
    opts->client_max_version = TEST_SSL_MINOR_VERSION_NONE;
    opts->server_min_version = TEST_SSL_MINOR_VERSION_NONE;
    opts->server_max_version = TEST_SSL_MINOR_VERSION_NONE;
    opts->expected_negotiated_version = MBEDTLS_SSL_MINOR_VERSION_3;
    opts->pk_alg = MBEDTLS_PK_RSA;
    opts->psk_str = NULL;
    opts->dtls = 0;
    opts->srv_auth_mode = MBEDTLS_SSL_VERIFY_NONE;
    opts->serialize = 0;
    opts->mfl = MBEDTLS_SSL_MAX_FRAG_LEN_NONE;
    opts->cli_msg_len = 100;
    opts->srv_msg_len = 100;
    opts->expected_cli_fragments = 1;
    opts->expected_srv_fragments = 1;
    opts->renegotiate = 0;
    opts->legacy_renegotiation = MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION;
    opts->srv_log_obj = NULL;
    opts->srv_log_obj = NULL;
    opts->srv_log_fun = NULL;
    opts->cli_log_fun = NULL;
    opts->resize_buffers = 1;
}

void mbedtls_test_ssl_buffer_init(mbedtls_test_ssl_buffer *buf)
{
    memset(buf, 0, sizeof(*buf));
}

int mbedtls_test_ssl_buffer_setup(mbedtls_test_ssl_buffer *buf,
                                  size_t capacity)
{
    buf->buffer = (unsigned char *) mbedtls_calloc(capacity,
                                                   sizeof(unsigned char));
    if (NULL == buf->buffer) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    buf->capacity = capacity;

    return 0;
}

void mbedtls_test_ssl_buffer_free(mbedtls_test_ssl_buffer *buf)
{
    if (buf->buffer != NULL) {
        mbedtls_free(buf->buffer);
    }

    memset(buf, 0, sizeof(*buf));
}

int mbedtls_test_ssl_buffer_put(mbedtls_test_ssl_buffer *buf,
                                const unsigned char *input, size_t input_len)
{
    size_t overflow = 0;

    if ((buf == NULL) || (buf->buffer == NULL)) {
        return -1;
    }

    /* Reduce input_len to a number that fits in the buffer. */
    if ((buf->content_length + input_len) > buf->capacity) {
        input_len = buf->capacity - buf->content_length;
    }

    if (input == NULL) {
        return (input_len == 0) ? 0 : -1;
    }

    /* Check if the buffer has not come full circle and free space is not in
     * the middle */
    if (buf->start + buf->content_length < buf->capacity) {

        /* Calculate the number of bytes that need to be placed at lower memory
         * address */
        if (buf->start + buf->content_length + input_len
            > buf->capacity) {
            overflow = (buf->start + buf->content_length + input_len)
                       % buf->capacity;
        }

        memcpy(buf->buffer + buf->start + buf->content_length, input,
               input_len - overflow);
        memcpy(buf->buffer, input + input_len - overflow, overflow);

    } else {
        /* The buffer has come full circle and free space is in the middle */
        memcpy(buf->buffer + buf->start + buf->content_length - buf->capacity,
               input, input_len);
    }

    buf->content_length += input_len;
    return (input_len > INT_MAX) ? INT_MAX : (int) input_len;
}

int mbedtls_test_ssl_buffer_get(mbedtls_test_ssl_buffer *buf,
                                unsigned char *output, size_t output_len)
{
    size_t overflow = 0;

    if ((buf == NULL) || (buf->buffer == NULL)) {
        return -1;
    }

    if (output == NULL && output_len == 0) {
        return 0;
    }

    if (buf->content_length < output_len) {
        output_len = buf->content_length;
    }

    /* Calculate the number of bytes that need to be drawn from lower memory
     * address */
    if (buf->start + output_len > buf->capacity) {
        overflow = (buf->start + output_len) % buf->capacity;
    }

    if (output != NULL) {
        memcpy(output, buf->buffer + buf->start, output_len - overflow);
        memcpy(output + output_len - overflow, buf->buffer, overflow);
    }

    buf->content_length -= output_len;
    buf->start = (buf->start + output_len) % buf->capacity;

    return (output_len > INT_MAX) ? INT_MAX : (int) output_len;
}

int mbedtls_test_ssl_message_queue_setup(
    mbedtls_test_ssl_message_queue *queue, size_t capacity)
{
    queue->messages = (size_t *) mbedtls_calloc(capacity, sizeof(size_t));
    if (NULL == queue->messages) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    queue->capacity = (capacity > INT_MAX) ? INT_MAX : (int) capacity;
    queue->pos = 0;
    queue->num = 0;

    return 0;
}

void mbedtls_test_ssl_message_queue_free(
    mbedtls_test_ssl_message_queue *queue)
{
    if (queue == NULL) {
        return;
    }

    if (queue->messages != NULL) {
        mbedtls_free(queue->messages);
    }

    memset(queue, 0, sizeof(*queue));
}

int mbedtls_test_ssl_message_queue_push_info(
    mbedtls_test_ssl_message_queue *queue, size_t len)
{
    int place;
    if (queue == NULL) {
        return MBEDTLS_TEST_ERROR_ARG_NULL;
    }

    if (queue->num >= queue->capacity) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    place = (queue->pos + queue->num) % queue->capacity;
    queue->messages[place] = len;
    queue->num++;
    return (len > INT_MAX) ? INT_MAX : (int) len;
}

int mbedtls_test_ssl_message_queue_pop_info(
    mbedtls_test_ssl_message_queue *queue, size_t buf_len)
{
    size_t message_length;
    if (queue == NULL) {
        return MBEDTLS_TEST_ERROR_ARG_NULL;
    }
    if (queue->num == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    message_length = queue->messages[queue->pos];
    queue->messages[queue->pos] = 0;
    queue->num--;
    queue->pos++;
    queue->pos %= queue->capacity;
    if (queue->pos < 0) {
        queue->pos += queue->capacity;
    }

    return (message_length > INT_MAX && buf_len > INT_MAX) ? INT_MAX :
           (message_length > buf_len) ? (int) buf_len : (int) message_length;
}

/*
 * Take a peek on the info about the next message length from the queue.
 * This will be the oldest inserted message length(fifo).
 *
 * \retval  MBEDTLS_TEST_ERROR_ARG_NULL, if the queue is null.
 * \retval  MBEDTLS_ERR_SSL_WANT_READ, if the queue is empty.
 * \retval  0, if the peek was successful.
 * \retval  MBEDTLS_TEST_ERROR_MESSAGE_TRUNCATED, if the given buffer length is
 *          too small to fit the message. In this case the \p msg_len will be
 *          set to the full message length so that the
 *          caller knows what portion of the message can be dropped.
 */
static int test_ssl_message_queue_peek_info(
    mbedtls_test_ssl_message_queue *queue,
    size_t buf_len, size_t *msg_len)
{
    if (queue == NULL || msg_len == NULL) {
        return MBEDTLS_TEST_ERROR_ARG_NULL;
    }
    if (queue->num == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    *msg_len = queue->messages[queue->pos];
    return (*msg_len > buf_len) ? MBEDTLS_TEST_ERROR_MESSAGE_TRUNCATED : 0;
}

void mbedtls_test_mock_socket_init(mbedtls_test_mock_socket *socket)
{
    memset(socket, 0, sizeof(*socket));
}

void mbedtls_test_mock_socket_close(mbedtls_test_mock_socket *socket)
{
    if (socket == NULL) {
        return;
    }

    if (socket->input != NULL) {
        mbedtls_test_ssl_buffer_free(socket->input);
        mbedtls_free(socket->input);
    }

    if (socket->output != NULL) {
        mbedtls_test_ssl_buffer_free(socket->output);
        mbedtls_free(socket->output);
    }

    if (socket->peer != NULL) {
        memset(socket->peer, 0, sizeof(*socket->peer));
    }

    memset(socket, 0, sizeof(*socket));
}

int mbedtls_test_mock_socket_connect(mbedtls_test_mock_socket *peer1,
                                     mbedtls_test_mock_socket *peer2,
                                     size_t bufsize)
{
    int ret = -1;

    peer1->output =
        (mbedtls_test_ssl_buffer *) mbedtls_calloc(
            1, sizeof(mbedtls_test_ssl_buffer));
    if (peer1->output == NULL) {
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto exit;
    }
    mbedtls_test_ssl_buffer_init(peer1->output);
    if (0 != (ret = mbedtls_test_ssl_buffer_setup(peer1->output, bufsize))) {
        goto exit;
    }

    peer2->output =
        (mbedtls_test_ssl_buffer *) mbedtls_calloc(
            1, sizeof(mbedtls_test_ssl_buffer));
    if (peer2->output == NULL) {
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto exit;
    }
    mbedtls_test_ssl_buffer_init(peer2->output);
    if (0 != (ret = mbedtls_test_ssl_buffer_setup(peer2->output, bufsize))) {
        goto exit;
    }

    peer1->peer = peer2;
    peer2->peer = peer1;
    peer1->input = peer2->output;
    peer2->input = peer1->output;

    peer1->status = peer2->status = MBEDTLS_MOCK_SOCKET_CONNECTED;
    ret = 0;

exit:

    if (ret != 0) {
        mbedtls_test_mock_socket_close(peer1);
        mbedtls_test_mock_socket_close(peer2);
    }

    return ret;
}

int mbedtls_test_mock_tcp_send_b(void *ctx,
                                 const unsigned char *buf, size_t len)
{
    mbedtls_test_mock_socket *socket = (mbedtls_test_mock_socket *) ctx;

    if (socket == NULL || socket->status != MBEDTLS_MOCK_SOCKET_CONNECTED) {
        return -1;
    }

    return mbedtls_test_ssl_buffer_put(socket->output, buf, len);
}

int mbedtls_test_mock_tcp_recv_b(void *ctx, unsigned char *buf, size_t len)
{
    mbedtls_test_mock_socket *socket = (mbedtls_test_mock_socket *) ctx;

    if (socket == NULL || socket->status != MBEDTLS_MOCK_SOCKET_CONNECTED) {
        return -1;
    }

    return mbedtls_test_ssl_buffer_get(socket->input, buf, len);
}

int mbedtls_test_mock_tcp_send_nb(void *ctx,
                                  const unsigned char *buf, size_t len)
{
    mbedtls_test_mock_socket *socket = (mbedtls_test_mock_socket *) ctx;

    if (socket == NULL || socket->status != MBEDTLS_MOCK_SOCKET_CONNECTED) {
        return -1;
    }

    if (socket->output->capacity == socket->output->content_length) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    return mbedtls_test_ssl_buffer_put(socket->output, buf, len);
}

int mbedtls_test_mock_tcp_recv_nb(void *ctx, unsigned char *buf, size_t len)
{
    mbedtls_test_mock_socket *socket = (mbedtls_test_mock_socket *) ctx;

    if (socket == NULL || socket->status != MBEDTLS_MOCK_SOCKET_CONNECTED) {
        return -1;
    }

    if (socket->input->content_length == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    return mbedtls_test_ssl_buffer_get(socket->input, buf, len);
}

void mbedtls_test_message_socket_init(
    mbedtls_test_message_socket_context *ctx)
{
    ctx->queue_input = NULL;
    ctx->queue_output = NULL;
    ctx->socket = NULL;
}

int mbedtls_test_message_socket_setup(
    mbedtls_test_ssl_message_queue *queue_input,
    mbedtls_test_ssl_message_queue *queue_output,
    size_t queue_capacity,
    mbedtls_test_mock_socket *socket,
    mbedtls_test_message_socket_context *ctx)
{
    int ret = mbedtls_test_ssl_message_queue_setup(queue_input, queue_capacity);
    if (ret != 0) {
        return ret;
    }
    ctx->queue_input = queue_input;
    ctx->queue_output = queue_output;
    ctx->socket = socket;
    mbedtls_test_mock_socket_init(socket);

    return 0;
}

void mbedtls_test_message_socket_close(
    mbedtls_test_message_socket_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_test_ssl_message_queue_free(ctx->queue_input);
    mbedtls_test_mock_socket_close(ctx->socket);
    memset(ctx, 0, sizeof(*ctx));
}

int mbedtls_test_mock_tcp_send_msg(void *ctx,
                                   const unsigned char *buf, size_t len)
{
    mbedtls_test_ssl_message_queue *queue;
    mbedtls_test_mock_socket *socket;
    mbedtls_test_message_socket_context *context =
        (mbedtls_test_message_socket_context *) ctx;

    if (context == NULL || context->socket == NULL
        || context->queue_output == NULL) {
        return MBEDTLS_TEST_ERROR_CONTEXT_ERROR;
    }

    queue = context->queue_output;
    socket = context->socket;

    if (queue->num >= queue->capacity) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    if (mbedtls_test_mock_tcp_send_b(socket, buf, len) != (int) len) {
        return MBEDTLS_TEST_ERROR_SEND_FAILED;
    }

    return mbedtls_test_ssl_message_queue_push_info(queue, len);
}

int mbedtls_test_mock_tcp_recv_msg(void *ctx,
                                   unsigned char *buf, size_t buf_len)
{
    mbedtls_test_ssl_message_queue *queue;
    mbedtls_test_mock_socket *socket;
    mbedtls_test_message_socket_context *context =
        (mbedtls_test_message_socket_context *) ctx;
    size_t drop_len = 0;
    size_t msg_len;
    int ret;

    if (context == NULL || context->socket == NULL
        || context->queue_input == NULL) {
        return MBEDTLS_TEST_ERROR_CONTEXT_ERROR;
    }

    queue = context->queue_input;
    socket = context->socket;

    /* Peek first, so that in case of a socket error the data remains in
     * the queue. */
    ret = test_ssl_message_queue_peek_info(queue, buf_len, &msg_len);
    if (ret == MBEDTLS_TEST_ERROR_MESSAGE_TRUNCATED) {
        /* Calculate how much to drop */
        drop_len = msg_len - buf_len;

        /* Set the requested message len to be buffer length */
        msg_len = buf_len;
    } else if (ret != 0) {
        return ret;
    }

    if (mbedtls_test_mock_tcp_recv_b(socket, buf, msg_len) != (int) msg_len) {
        return MBEDTLS_TEST_ERROR_RECV_FAILED;
    }

    if (ret == MBEDTLS_TEST_ERROR_MESSAGE_TRUNCATED) {
        /* Drop the remaining part of the message */
        if (mbedtls_test_mock_tcp_recv_b(socket, NULL, drop_len) !=
            (int) drop_len) {
            /* Inconsistent state - part of the message was read,
             * and a part couldn't. Not much we can do here, but it should not
             * happen in test environment, unless forced manually. */
        }
    }
    ret = mbedtls_test_ssl_message_queue_pop_info(queue, buf_len);
    if (ret < 0) {
        return ret;
    }

    return (msg_len > INT_MAX) ? INT_MAX : (int) msg_len;
}

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && \
    defined(MBEDTLS_CERTS_C) && \
    defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_CTR_DRBG_C)

/*
 * Deinitializes certificates from endpoint represented by \p ep.
 */
static void test_ssl_endpoint_certificate_free(mbedtls_test_ssl_endpoint *ep)
{
    mbedtls_test_ssl_endpoint_certificate *cert = &(ep->cert);
    if (cert != NULL) {
        if (cert->ca_cert != NULL) {
            mbedtls_x509_crt_free(cert->ca_cert);
            mbedtls_free(cert->ca_cert);
            cert->ca_cert = NULL;
        }
        if (cert->cert != NULL) {
            mbedtls_x509_crt_free(cert->cert);
            mbedtls_free(cert->cert);
            cert->cert = NULL;
        }
        if (cert->pkey != NULL) {
#if defined(MBEDTLS_USE_PSA_CRYPTO)
            if (mbedtls_pk_get_type(cert->pkey) == MBEDTLS_PK_OPAQUE) {
                mbedtls_svc_key_id_t *key_slot = cert->pkey->pk_ctx;
                psa_destroy_key(*key_slot);
            }
#endif
            mbedtls_pk_free(cert->pkey);
            mbedtls_free(cert->pkey);
            cert->pkey = NULL;
        }
    }
}

int mbedtls_test_ssl_endpoint_certificate_init(mbedtls_test_ssl_endpoint *ep,
                                               int pk_alg)
{
    int i = 0;
    int ret = -1;
    mbedtls_test_ssl_endpoint_certificate *cert = NULL;

    if (ep == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    cert = &(ep->cert);
    TEST_CALLOC(cert->ca_cert, 1);
    TEST_CALLOC(cert->cert, 1);
    TEST_CALLOC(cert->pkey, 1);

    mbedtls_x509_crt_init(cert->ca_cert);
    mbedtls_x509_crt_init(cert->cert);
    mbedtls_pk_init(cert->pkey);

    /* Load the trusted CA */

    for (i = 0; mbedtls_test_cas_der[i] != NULL; i++) {
        ret = mbedtls_x509_crt_parse_der(
            cert->ca_cert,
            (const unsigned char *) mbedtls_test_cas_der[i],
            mbedtls_test_cas_der_len[i]);
        TEST_ASSERT(ret == 0);
    }

    /* Load own certificate and private key */

    if (ep->conf.endpoint == MBEDTLS_SSL_IS_SERVER) {
        if (pk_alg == MBEDTLS_PK_RSA) {
            ret = mbedtls_x509_crt_parse(
                cert->cert,
                (const unsigned char *) mbedtls_test_srv_crt_rsa_sha256_der,
                mbedtls_test_srv_crt_rsa_sha256_der_len);
            TEST_ASSERT(ret == 0);

            ret = mbedtls_pk_parse_key(
                cert->pkey,
                (const unsigned char *) mbedtls_test_srv_key_rsa_der,
                mbedtls_test_srv_key_rsa_der_len, NULL, 0);
            TEST_ASSERT(ret == 0);
        } else {
            ret = mbedtls_x509_crt_parse(
                cert->cert,
                (const unsigned char *) mbedtls_test_srv_crt_ec_der,
                mbedtls_test_srv_crt_ec_der_len);
            TEST_ASSERT(ret == 0);

            ret = mbedtls_pk_parse_key(
                cert->pkey,
                (const unsigned char *) mbedtls_test_srv_key_ec_der,
                mbedtls_test_srv_key_ec_der_len, NULL, 0);
            TEST_ASSERT(ret == 0);
        }
    } else {
        if (pk_alg == MBEDTLS_PK_RSA) {
            ret = mbedtls_x509_crt_parse(
                cert->cert,
                (const unsigned char *) mbedtls_test_cli_crt_rsa_der,
                mbedtls_test_cli_crt_rsa_der_len);
            TEST_ASSERT(ret == 0);

            ret = mbedtls_pk_parse_key(
                cert->pkey,
                (const unsigned char *) mbedtls_test_cli_key_rsa_der,
                mbedtls_test_cli_key_rsa_der_len, NULL, 0);
            TEST_ASSERT(ret == 0);
        } else {
            ret = mbedtls_x509_crt_parse(
                cert->cert,
                (const unsigned char *) mbedtls_test_cli_crt_ec_der,
                mbedtls_test_cli_crt_ec_len);
            TEST_ASSERT(ret == 0);

            ret = mbedtls_pk_parse_key(
                cert->pkey,
                (const unsigned char *) mbedtls_test_cli_key_ec_der,
                mbedtls_test_cli_key_ec_der_len, NULL, 0);
            TEST_ASSERT(ret == 0);
        }
    }

    mbedtls_ssl_conf_ca_chain(&(ep->conf), cert->ca_cert, NULL);

    ret = mbedtls_ssl_conf_own_cert(&(ep->conf), cert->cert,
                                    cert->pkey);
    TEST_ASSERT(ret == 0);

exit:
    if (ret != 0) {
        test_ssl_endpoint_certificate_free(ep);
    }

    return ret;
}

int mbedtls_test_ssl_endpoint_init(
    mbedtls_test_ssl_endpoint *ep, int endpoint_type, int pk_alg,
    mbedtls_test_message_socket_context *dtls_context,
    mbedtls_test_ssl_message_queue *input_queue,
    mbedtls_test_ssl_message_queue *output_queue,
    const mbedtls_ecp_group_id *curves)
{
    int ret = -1;

    if (dtls_context != NULL &&
        (input_queue == NULL || output_queue == NULL)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (ep == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    memset(ep, 0, sizeof(*ep));

    ep->name = (endpoint_type == MBEDTLS_SSL_IS_SERVER) ? "Server" : "Client";

    mbedtls_ssl_init(&(ep->ssl));
    mbedtls_ssl_config_init(&(ep->conf));
    mbedtls_ctr_drbg_init(&(ep->ctr_drbg));
    mbedtls_ssl_conf_rng(&(ep->conf),
                         mbedtls_ctr_drbg_random,
                         &(ep->ctr_drbg));
    mbedtls_entropy_init(&(ep->entropy));
    if (dtls_context != NULL) {
        TEST_ASSERT(mbedtls_test_message_socket_setup(input_queue, output_queue,
                                                      100, &(ep->socket),
                                                      dtls_context) == 0);
    } else {
        mbedtls_test_mock_socket_init(&(ep->socket));
    }

    ret = mbedtls_ctr_drbg_seed(&(ep->ctr_drbg), mbedtls_entropy_func,
                                &(ep->entropy),
                                (const unsigned char *) (ep->name),
                                strlen(ep->name));
    TEST_ASSERT(ret == 0);

    /* Non-blocking callbacks without timeout */
    if (dtls_context != NULL) {
        mbedtls_ssl_set_bio(&(ep->ssl), dtls_context,
                            mbedtls_test_mock_tcp_send_msg,
                            mbedtls_test_mock_tcp_recv_msg,
                            NULL);
    } else {
        mbedtls_ssl_set_bio(&(ep->ssl), &(ep->socket),
                            mbedtls_test_mock_tcp_send_nb,
                            mbedtls_test_mock_tcp_recv_nb,
                            NULL);
    }

    ret = mbedtls_ssl_config_defaults(&(ep->conf), endpoint_type,
                                      (dtls_context != NULL) ?
                                      MBEDTLS_SSL_TRANSPORT_DATAGRAM :
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    TEST_ASSERT(ret == 0);

#if defined(MBEDTLS_ECP_C)
    if (curves != NULL) {
        mbedtls_ssl_conf_curves(&(ep->conf), curves);
    }
#else
    (void) curves;
#endif

    ret = mbedtls_ssl_setup(&(ep->ssl), &(ep->conf));
    TEST_ASSERT(ret == 0);

    if (MBEDTLS_SSL_IS_CLIENT == endpoint_type) {
        ret = mbedtls_ssl_set_hostname(&(ep->ssl), "localhost");
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_SSL_SRV_C)
    if (endpoint_type == MBEDTLS_SSL_IS_SERVER && dtls_context != NULL) {
        mbedtls_ssl_conf_dtls_cookies(&(ep->conf), NULL, NULL, NULL);
    }
#endif

    ret = mbedtls_test_ssl_endpoint_certificate_init(ep, pk_alg);
    TEST_ASSERT(ret == 0);

exit:
    return ret;
}

void mbedtls_test_ssl_endpoint_free(
    mbedtls_test_ssl_endpoint *ep,
    mbedtls_test_message_socket_context *context)
{
    test_ssl_endpoint_certificate_free(ep);

    mbedtls_ssl_free(&(ep->ssl));
    mbedtls_ssl_config_free(&(ep->conf));
    mbedtls_ctr_drbg_free(&(ep->ctr_drbg));
    mbedtls_entropy_free(&(ep->entropy));

    if (context != NULL) {
        mbedtls_test_message_socket_close(context);
    } else {
        mbedtls_test_mock_socket_close(&(ep->socket));
    }
}

int mbedtls_test_move_handshake_to_state(mbedtls_ssl_context *ssl,
                                         mbedtls_ssl_context *second_ssl,
                                         int state)
{
    enum { BUFFSIZE = 1024 };
    int max_steps = 1000;
    int ret = 0;

    if (ssl == NULL || second_ssl == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    /* Perform communication via connected sockets */
    while ((ssl->state != state) && (--max_steps >= 0)) {
        /* If /p second_ssl ends the handshake procedure before /p ssl then
         * there is no need to call the next step */
        if (second_ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER) {
            ret = mbedtls_ssl_handshake_step(second_ssl);
            if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                return ret;
            }
        }

        /* We only care about the \p ssl state and returns, so we call it last,
         * to leave the iteration as soon as the state is as expected. */
        ret = mbedtls_ssl_handshake_step(ssl);
        if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return ret;
        }
    }

    return (max_steps >= 0) ? ret : -1;
}

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED && MBEDTLS_CERTS_C &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */

/*
 * Write application data. Increase write counter if necessary.
 */
int mbedtls_ssl_write_fragment(mbedtls_ssl_context *ssl,
                               unsigned char *buf, int buf_len,
                               int *written,
                               const int expected_fragments)
{
    int ret;

    /* Verify that calling mbedtls_ssl_write with a NULL buffer and zero length is
     * a valid no-op for TLS connections. */
    if (ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        TEST_ASSERT(mbedtls_ssl_write(ssl, NULL, 0) == 0);
    }

    ret = mbedtls_ssl_write(ssl, buf + *written, buf_len - *written);
    if (ret > 0) {
        *written += ret;
    }

    if (expected_fragments == 0) {
        /* Used for DTLS and the message size larger than MFL. In that case
         * the message can not be fragmented and the library should return
         * MBEDTLS_ERR_SSL_BAD_INPUT_DATA error. This error must be returned
         * to prevent a dead loop inside mbedtls_test_ssl_exchange_data(). */
        return ret;
    } else if (expected_fragments == 1) {
        /* Used for TLS/DTLS and the message size lower than MFL */
        TEST_ASSERT(ret == buf_len ||
                    ret == MBEDTLS_ERR_SSL_WANT_READ ||
                    ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    } else {
        /* Used for TLS and the message size larger than MFL */
        TEST_ASSERT(expected_fragments > 1);
        TEST_ASSERT((ret >= 0 && ret <= buf_len) ||
                    ret == MBEDTLS_ERR_SSL_WANT_READ ||
                    ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    }

    return 0;

exit:
    /* Some of the tests failed */
    return -1;
}

/*
 * Read application data and increase read counter and fragments counter
 * if necessary.
 */
int mbedtls_ssl_read_fragment(mbedtls_ssl_context *ssl,
                              unsigned char *buf, int buf_len,
                              int *read, int *fragments,
                              const int expected_fragments)
{
    int ret;

    /* Verify that calling mbedtls_ssl_write with a NULL buffer and zero length is
     * a valid no-op for TLS connections. */
    if (ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        TEST_ASSERT(mbedtls_ssl_read(ssl, NULL, 0) == 0);
    }

    ret = mbedtls_ssl_read(ssl, buf + *read, buf_len - *read);
    if (ret > 0) {
        (*fragments)++;
        *read += ret;
    }

    if (expected_fragments == 0) {
        TEST_ASSERT(ret == 0);
    } else if (expected_fragments == 1) {
        TEST_ASSERT(ret == buf_len ||
                    ret == MBEDTLS_ERR_SSL_WANT_READ ||
                    ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    } else {
        TEST_ASSERT(expected_fragments > 1);
        TEST_ASSERT((ret >= 0 && ret <= buf_len) ||
                    ret == MBEDTLS_ERR_SSL_WANT_READ ||
                    ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    }

    return 0;

exit:
    /* Some of the tests failed */
    return -1;
}

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && \
    defined(MBEDTLS_CERTS_C)                        && \
    defined(MBEDTLS_ENTROPY_C)                      && \
    defined(MBEDTLS_CTR_DRBG_C)
static void set_ciphersuite(mbedtls_ssl_config *conf, const char *cipher,
                            int *forced_ciphersuite)
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    forced_ciphersuite[0] = mbedtls_ssl_get_ciphersuite_id(cipher);
    forced_ciphersuite[1] = 0;

    ciphersuite_info =
        mbedtls_ssl_ciphersuite_from_id(forced_ciphersuite[0]);

    TEST_ASSERT(ciphersuite_info != NULL);
    TEST_ASSERT(ciphersuite_info->min_minor_ver <= conf->max_minor_ver);
    TEST_ASSERT(ciphersuite_info->max_minor_ver >= conf->min_minor_ver);

    if (conf->max_minor_ver > ciphersuite_info->max_minor_ver) {
        conf->max_minor_ver = ciphersuite_info->max_minor_ver;
    }
    if (conf->min_minor_ver < ciphersuite_info->min_minor_ver) {
        conf->min_minor_ver = ciphersuite_info->min_minor_ver;
    }

    mbedtls_ssl_conf_ciphersuites(conf, forced_ciphersuite);

exit:
    return;
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED && MBEDTLS_CERTS_C &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && \
    defined(MBEDTLS_CERTS_C)                        && \
    defined(MBEDTLS_ENTROPY_C)                      && \
    defined(MBEDTLS_CTR_DRBG_C)                     && \
    defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
static int psk_dummy_callback(void *p_info, mbedtls_ssl_context *ssl,
                              const unsigned char *name, size_t name_len)
{
    (void) p_info;
    (void) ssl;
    (void) name;
    (void) name_len;

    return 0;
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED && MBEDTLS_CERTS_C &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

int mbedtls_test_ssl_build_transforms(mbedtls_ssl_transform *t_in,
                                      mbedtls_ssl_transform *t_out,
                                      int cipher_type, int hash_id,
                                      int etm, int tag_mode, int ver,
                                      size_t cid0_len,
                                      size_t cid1_len)
{
    mbedtls_cipher_info_t const *cipher_info;
    int ret = 0;

    size_t keylen, maclen, ivlen;
    unsigned char *key0 = NULL, *key1 = NULL;
    unsigned char *md0 = NULL, *md1 = NULL;
    unsigned char iv_enc[16], iv_dec[16];

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    unsigned char cid0[SSL_CID_LEN_MIN];
    unsigned char cid1[SSL_CID_LEN_MIN];

    mbedtls_test_rnd_std_rand(NULL, cid0, sizeof(cid0));
    mbedtls_test_rnd_std_rand(NULL, cid1, sizeof(cid1));
#else
    ((void) cid0_len);
    ((void) cid1_len);
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    maclen = 0;

    /* Pick cipher */
    cipher_info = mbedtls_cipher_info_from_type(cipher_type);
    CHK(cipher_info != NULL);
    CHK(cipher_info->iv_size <= 16);
    CHK(cipher_info->key_bitlen % 8 == 0);

    /* Pick keys */
    keylen = cipher_info->key_bitlen / 8;
    /* Allocate `keylen + 1` bytes to ensure that we get
     * a non-NULL pointers from `mbedtls_calloc` even if
     * `keylen == 0` in the case of the NULL cipher. */
    CHK((key0 = mbedtls_calloc(1, keylen + 1)) != NULL);
    CHK((key1 = mbedtls_calloc(1, keylen + 1)) != NULL);
    memset(key0, 0x1, keylen);
    memset(key1, 0x2, keylen);

    /* Setup cipher contexts */
    CHK(mbedtls_cipher_setup(&t_in->cipher_ctx_enc,  cipher_info) == 0);
    CHK(mbedtls_cipher_setup(&t_in->cipher_ctx_dec,  cipher_info) == 0);
    CHK(mbedtls_cipher_setup(&t_out->cipher_ctx_enc, cipher_info) == 0);
    CHK(mbedtls_cipher_setup(&t_out->cipher_ctx_dec, cipher_info) == 0);

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    if (cipher_info->mode == MBEDTLS_MODE_CBC) {
        CHK(mbedtls_cipher_set_padding_mode(&t_in->cipher_ctx_enc,
                                            MBEDTLS_PADDING_NONE) == 0);
        CHK(mbedtls_cipher_set_padding_mode(&t_in->cipher_ctx_dec,
                                            MBEDTLS_PADDING_NONE) == 0);
        CHK(mbedtls_cipher_set_padding_mode(&t_out->cipher_ctx_enc,
                                            MBEDTLS_PADDING_NONE) == 0);
        CHK(mbedtls_cipher_set_padding_mode(&t_out->cipher_ctx_dec,
                                            MBEDTLS_PADDING_NONE) == 0);
    }
#endif /* MBEDTLS_CIPHER_MODE_CBC */

    CHK(mbedtls_cipher_setkey(&t_in->cipher_ctx_enc, key0,
                              (keylen << 3 > INT_MAX) ? INT_MAX : (int) keylen << 3,
                              MBEDTLS_ENCRYPT)
        == 0);
    CHK(mbedtls_cipher_setkey(&t_in->cipher_ctx_dec, key1,
                              (keylen << 3 > INT_MAX) ? INT_MAX : (int) keylen << 3,
                              MBEDTLS_DECRYPT)
        == 0);
    CHK(mbedtls_cipher_setkey(&t_out->cipher_ctx_enc, key1,
                              (keylen << 3 > INT_MAX) ? INT_MAX : (int) keylen << 3,
                              MBEDTLS_ENCRYPT)
        == 0);
    CHK(mbedtls_cipher_setkey(&t_out->cipher_ctx_dec, key0,
                              (keylen << 3 > INT_MAX) ? INT_MAX : (int) keylen << 3,
                              MBEDTLS_DECRYPT)
        == 0);

    /* Setup MAC contexts */
#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
    if (cipher_info->mode == MBEDTLS_MODE_CBC ||
        cipher_info->mode == MBEDTLS_MODE_STREAM) {
        mbedtls_md_info_t const *md_info;

        /* Pick hash */
        md_info = mbedtls_md_info_from_type(hash_id);
        CHK(md_info != NULL);

        /* Pick hash keys */
        maclen = mbedtls_md_get_size(md_info);
        CHK((md0 = mbedtls_calloc(1, maclen)) != NULL);
        CHK((md1 = mbedtls_calloc(1, maclen)) != NULL);
        memset(md0, 0x5, maclen);
        memset(md1, 0x6, maclen);

        CHK(mbedtls_md_setup(&t_out->md_ctx_enc, md_info, 1) == 0);
        CHK(mbedtls_md_setup(&t_out->md_ctx_dec, md_info, 1) == 0);
        CHK(mbedtls_md_setup(&t_in->md_ctx_enc,  md_info, 1) == 0);
        CHK(mbedtls_md_setup(&t_in->md_ctx_dec,  md_info, 1) == 0);

        if (ver > MBEDTLS_SSL_MINOR_VERSION_0) {
            CHK(mbedtls_md_hmac_starts(&t_in->md_ctx_enc,
                                       md0, maclen) == 0);
            CHK(mbedtls_md_hmac_starts(&t_in->md_ctx_dec,
                                       md1, maclen) == 0);
            CHK(mbedtls_md_hmac_starts(&t_out->md_ctx_enc,
                                       md1, maclen) == 0);
            CHK(mbedtls_md_hmac_starts(&t_out->md_ctx_dec,
                                       md0, maclen) == 0);
        }
#if defined(MBEDTLS_SSL_PROTO_SSL3)
        else {
            memcpy(&t_in->mac_enc, md0, maclen);
            memcpy(&t_in->mac_dec, md1, maclen);
            memcpy(&t_out->mac_enc, md1, maclen);
            memcpy(&t_out->mac_dec, md0, maclen);
        }
#endif
    }
#else
    ((void) hash_id);
#endif /* MBEDTLS_SSL_SOME_MODES_USE_MAC */


    /* Pick IV's (regardless of whether they
     * are being used by the transform). */
    ivlen = cipher_info->iv_size;
    memset(iv_enc, 0x3, sizeof(iv_enc));
    memset(iv_dec, 0x4, sizeof(iv_dec));

    /*
     * Setup transforms
     */

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC) && \
    defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
    t_out->encrypt_then_mac = etm;
    t_in->encrypt_then_mac = etm;
#else
    ((void) etm);
#endif

    t_out->minor_ver = ver;
    t_in->minor_ver = ver;
    t_out->ivlen = ivlen;
    t_in->ivlen = ivlen;

    switch (cipher_info->mode) {
        case MBEDTLS_MODE_GCM:
        case MBEDTLS_MODE_CCM:
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
            if (ver == MBEDTLS_SSL_MINOR_VERSION_4) {
                t_out->fixed_ivlen = 12;
                t_in->fixed_ivlen  = 12;
            } else
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
            {
                t_out->fixed_ivlen = 4;
                t_in->fixed_ivlen = 4;
            }
            t_out->maclen = 0;
            t_in->maclen = 0;
            switch (tag_mode) {
                case 0: /* Full tag */
                    t_out->taglen = 16;
                    t_in->taglen = 16;
                    break;
                case 1: /* Partial tag */
                    t_out->taglen = 8;
                    t_in->taglen = 8;
                    break;
                default:
                    ret = 1;
                    goto cleanup;
            }
            break;

        case MBEDTLS_MODE_CHACHAPOLY:
            t_out->fixed_ivlen = 12;
            t_in->fixed_ivlen = 12;
            t_out->maclen = 0;
            t_in->maclen = 0;
            switch (tag_mode) {
                case 0: /* Full tag */
                    t_out->taglen = 16;
                    t_in->taglen = 16;
                    break;
                case 1: /* Partial tag */
                    t_out->taglen = 8;
                    t_in->taglen = 8;
                    break;
                default:
                    ret = 1;
                    goto cleanup;
            }
            break;

        case MBEDTLS_MODE_STREAM:
        case MBEDTLS_MODE_CBC:
            t_out->fixed_ivlen = 0; /* redundant, must be 0 */
            t_in->fixed_ivlen = 0;  /* redundant, must be 0 */
            t_out->taglen = 0;
            t_in->taglen = 0;
            switch (tag_mode) {
                case 0: /* Full tag */
                    t_out->maclen = maclen;
                    t_in->maclen = maclen;
                    break;
                case 1: /* Partial tag */
                    t_out->maclen = 10;
                    t_in->maclen = 10;
                    break;
                default:
                    ret = 1;
                    goto cleanup;
            }
            break;
        default:
            ret = 1;
            goto cleanup;
            break;
    }

    /* Setup IV's */

    memcpy(&t_in->iv_dec, iv_dec, sizeof(iv_dec));
    memcpy(&t_in->iv_enc, iv_enc, sizeof(iv_enc));
    memcpy(&t_out->iv_dec, iv_enc, sizeof(iv_enc));
    memcpy(&t_out->iv_enc, iv_dec, sizeof(iv_dec));

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    /* Add CID */
    memcpy(&t_in->in_cid,  cid0, cid0_len);
    memcpy(&t_in->out_cid, cid1, cid1_len);
    t_in->in_cid_len = (uint8_t) cid0_len;
    t_in->out_cid_len = (uint8_t) cid1_len;
    memcpy(&t_out->in_cid,  cid1, cid1_len);
    memcpy(&t_out->out_cid, cid0, cid0_len);
    t_out->in_cid_len = (uint8_t) cid1_len;
    t_out->out_cid_len = (uint8_t) cid0_len;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

cleanup:

    mbedtls_free(key0);
    mbedtls_free(key1);

    mbedtls_free(md0);
    mbedtls_free(md1);

    return ret;
}

#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
int mbedtls_test_ssl_prepare_record_mac(mbedtls_record *record,
                                        mbedtls_ssl_transform *transform_out)
{
    /* Serialized version of record header for MAC purposes */
    unsigned char add_data[13];
    memcpy(add_data, record->ctr, 8);
    add_data[8] = record->type;
    add_data[9] = record->ver[0];
    add_data[10] = record->ver[1];
    add_data[11] = (record->data_len >> 8) & 0xff;
    add_data[12] = (record->data_len >> 0) & 0xff;

    /* MAC with additional data */
    TEST_EQUAL(0, mbedtls_md_hmac_update(&transform_out->md_ctx_enc, add_data, 13));
    TEST_EQUAL(0, mbedtls_md_hmac_update(&transform_out->md_ctx_enc,
                                         record->buf + record->data_offset,
                                         record->data_len));
    /* Use a temporary buffer for the MAC, because with the truncated HMAC
     * extension, there might not be enough room in the record for the
     * full-length MAC. */
    unsigned char mac[MBEDTLS_MD_MAX_SIZE];
    TEST_EQUAL(0, mbedtls_md_hmac_finish(&transform_out->md_ctx_enc, mac));
    memcpy(record->buf + record->data_offset + record->data_len, mac, transform_out->maclen);
    record->data_len += transform_out->maclen;

    return 0;

exit:
    return -1;
}
#endif /* MBEDTLS_SSL_SOME_MODES_USE_MAC */

int mbedtls_test_ssl_populate_session(mbedtls_ssl_session *session,
                                      int ticket_len,
                                      const char *crt_file)
{
#if defined(MBEDTLS_HAVE_TIME)
    session->start = mbedtls_time(NULL) - 42;
#endif
    session->ciphersuite = 0xabcd;
    session->compression = 1;
    session->id_len = sizeof(session->id);
    memset(session->id, 66, session->id_len);
    memset(session->master, 17, sizeof(session->master));

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && \
    defined(MBEDTLS_CERTS_C) &&                        \
    defined(MBEDTLS_FS_IO)
    if (strlen(crt_file) != 0) {
        mbedtls_x509_crt tmp_crt;
        int ret;

        mbedtls_x509_crt_init(&tmp_crt);
        ret = mbedtls_x509_crt_parse_file(&tmp_crt, crt_file);
        if (ret != 0) {
            return ret;
        }

#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
        /* Move temporary CRT. */
        session->peer_cert = mbedtls_calloc(1, sizeof(*session->peer_cert));
        if (session->peer_cert == NULL) {
            return -1;
        }
        *session->peer_cert = tmp_crt;
        memset(&tmp_crt, 0, sizeof(tmp_crt));
#else /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
        /* Calculate digest of temporary CRT. */
        session->peer_cert_digest =
            mbedtls_calloc(1, MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN);
        if (session->peer_cert_digest == NULL) {
            return -1;
        }
        ret = mbedtls_md(mbedtls_md_info_from_type(
                             MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_TYPE),
                         tmp_crt.raw.p, tmp_crt.raw.len,
                         session->peer_cert_digest);
        if (ret != 0) {
            return ret;
        }
        session->peer_cert_digest_type =
            MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_TYPE;
        session->peer_cert_digest_len =
            MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN;
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

        mbedtls_x509_crt_free(&tmp_crt);
    }
#else /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED && MBEDTLS_CERTS_C && MBEDTLS_FS_IO */
    (void) crt_file;
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED && MBEDTLS_CERTS_C && MBEDTLS_FS_IO */
    session->verify_result = 0xdeadbeef;

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
    if (ticket_len != 0) {
        session->ticket = mbedtls_calloc(1, ticket_len);
        if (session->ticket == NULL) {
            return -1;
        }
        memset(session->ticket, 33, ticket_len);
    }
    session->ticket_len = ticket_len;
    session->ticket_lifetime = 86401;
#else
    (void) ticket_len;
#endif

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    session->mfl_code = 1;
#endif
#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
    session->trunc_hmac = 1;
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    session->encrypt_then_mac = 1;
#endif

    return 0;
}

int mbedtls_test_ssl_exchange_data(
    mbedtls_ssl_context *ssl_1,
    int msg_len_1, const int expected_fragments_1,
    mbedtls_ssl_context *ssl_2,
    int msg_len_2, const int expected_fragments_2)
{
    unsigned char *msg_buf_1 = malloc(msg_len_1);
    unsigned char *msg_buf_2 = malloc(msg_len_2);
    unsigned char *in_buf_1  = malloc(msg_len_2);
    unsigned char *in_buf_2  = malloc(msg_len_1);
    int msg_type, ret = -1;

    /* Perform this test with two message types. At first use a message
     * consisting of only 0x00 for the client and only 0xFF for the server.
     * At the second time use message with generated data */
    for (msg_type = 0; msg_type < 2; msg_type++) {
        int written_1 = 0;
        int written_2 = 0;
        int read_1 = 0;
        int read_2 = 0;
        int fragments_1 = 0;
        int fragments_2 = 0;

        if (msg_type == 0) {
            memset(msg_buf_1, 0x00, msg_len_1);
            memset(msg_buf_2, 0xff, msg_len_2);
        } else {
            int i, j = 0;
            for (i = 0; i < msg_len_1; i++) {
                msg_buf_1[i] = j++ & 0xFF;
            }
            for (i = 0; i < msg_len_2; i++) {
                msg_buf_2[i] = (j -= 5) & 0xFF;
            }
        }

        while (read_1 < msg_len_2 || read_2 < msg_len_1) {
            /* ssl_1 sending */
            if (msg_len_1 > written_1) {
                ret = mbedtls_ssl_write_fragment(ssl_1, msg_buf_1,
                                                 msg_len_1, &written_1,
                                                 expected_fragments_1);
                if (expected_fragments_1 == 0) {
                    /* This error is expected when the message is too large and
                     * cannot be fragmented */
                    TEST_ASSERT(ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
                    msg_len_1 = 0;
                } else {
                    TEST_ASSERT(ret == 0);
                }
            }

            /* ssl_2 sending */
            if (msg_len_2 > written_2) {
                ret = mbedtls_ssl_write_fragment(ssl_2, msg_buf_2,
                                                 msg_len_2, &written_2,
                                                 expected_fragments_2);
                if (expected_fragments_2 == 0) {
                    /* This error is expected when the message is too large and
                     * cannot be fragmented */
                    TEST_ASSERT(ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
                    msg_len_2 = 0;
                } else {
                    TEST_ASSERT(ret == 0);
                }
            }

            /* ssl_1 reading */
            if (read_1 < msg_len_2) {
                ret = mbedtls_ssl_read_fragment(ssl_1, in_buf_1,
                                                msg_len_2, &read_1,
                                                &fragments_2,
                                                expected_fragments_2);
                TEST_ASSERT(ret == 0);
            }

            /* ssl_2 reading */
            if (read_2 < msg_len_1) {
                ret = mbedtls_ssl_read_fragment(ssl_2, in_buf_2,
                                                msg_len_1, &read_2,
                                                &fragments_1,
                                                expected_fragments_1);
                TEST_ASSERT(ret == 0);
            }
        }

        ret = -1;
        TEST_ASSERT(0 == memcmp(msg_buf_1, in_buf_2, msg_len_1));
        TEST_ASSERT(0 == memcmp(msg_buf_2, in_buf_1, msg_len_2));
        TEST_ASSERT(fragments_1 == expected_fragments_1);
        TEST_ASSERT(fragments_2 == expected_fragments_2);
    }

    ret = 0;

exit:
    free(msg_buf_1);
    free(in_buf_1);
    free(msg_buf_2);
    free(in_buf_2);

    return ret;
}

/*
 * Perform data exchanging between \p ssl_1 and \p ssl_2. Both of endpoints
 * must be initialized and connected beforehand.
 *
 * \retval  0 on success, otherwise error code.
 */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && \
    defined(MBEDTLS_CERTS_C)                        && \
    defined(MBEDTLS_ENTROPY_C)                      && \
    defined(MBEDTLS_CTR_DRBG_C)                     && \
    (defined(MBEDTLS_SSL_RENEGOTIATION)             || \
    defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH))
static int exchange_data(mbedtls_ssl_context *ssl_1,
                         mbedtls_ssl_context *ssl_2)
{
    return mbedtls_test_ssl_exchange_data(ssl_1, 256, 1,
                                          ssl_2, 256, 1);
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED && MBEDTLS_CERTS_C &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          (MBEDTLS_SSL_RENEGOTIATION              ||
          MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH) */

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && \
    defined(MBEDTLS_CERTS_C)                        && \
    defined(MBEDTLS_ENTROPY_C)                      && \
    defined(MBEDTLS_CTR_DRBG_C)
void mbedtls_test_ssl_perform_handshake(
    mbedtls_test_handshake_test_options *options)
{
    /* forced_ciphersuite needs to last until the end of the handshake */
    int forced_ciphersuite[2];
    enum { BUFFSIZE = 17000 };
    mbedtls_test_ssl_endpoint client, server;
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    const char *psk_identity = "foo";
#endif
#if defined(MBEDTLS_TIMING_C)
    mbedtls_timing_delay_context timer_client, timer_server;
#endif
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
    unsigned char *context_buf = NULL;
    size_t context_buf_len;
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    int ret = -1;
#endif
    int expected_handshake_result = 0;

    USE_PSA_INIT();
    mbedtls_platform_zeroize(&client, sizeof(client));
    mbedtls_platform_zeroize(&server, sizeof(server));

    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;
    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);

    /* Client side */
    if (options->dtls != 0) {
        TEST_ASSERT(mbedtls_test_ssl_endpoint_init(&client,
                                                   MBEDTLS_SSL_IS_CLIENT,
                                                   options->pk_alg,
                                                   &client_context,
                                                   &client_queue,
                                                   &server_queue, NULL) == 0);
#if defined(MBEDTLS_TIMING_C)
        mbedtls_ssl_set_timer_cb(&client.ssl, &timer_client,
                                 mbedtls_timing_set_delay,
                                 mbedtls_timing_get_delay);
#endif
    } else {
        TEST_ASSERT(mbedtls_test_ssl_endpoint_init(&client,
                                                   MBEDTLS_SSL_IS_CLIENT,
                                                   options->pk_alg, NULL, NULL,
                                                   NULL, NULL) == 0);
    }

    if (options->client_min_version != TEST_SSL_MINOR_VERSION_NONE) {
        mbedtls_ssl_conf_min_version(&client.conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                     options->client_min_version);
    }

    if (options->client_max_version != TEST_SSL_MINOR_VERSION_NONE) {
        mbedtls_ssl_conf_max_version(&client.conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                     options->client_max_version);
    }

    if (strlen(options->cipher) > 0) {
        set_ciphersuite(&client.conf, options->cipher, forced_ciphersuite);
    }

#if defined(MBEDTLS_DEBUG_C)
    if (options->cli_log_fun) {
        mbedtls_debug_set_threshold(4);
        mbedtls_ssl_conf_dbg(&client.conf, options->cli_log_fun,
                             options->cli_log_obj);
    }
#endif

    /* Server side */
    if (options->dtls != 0) {
        TEST_ASSERT(mbedtls_test_ssl_endpoint_init(&server,
                                                   MBEDTLS_SSL_IS_SERVER,
                                                   options->pk_alg,
                                                   &server_context,
                                                   &server_queue,
                                                   &client_queue, NULL) == 0);
#if defined(MBEDTLS_TIMING_C)
        mbedtls_ssl_set_timer_cb(&server.ssl, &timer_server,
                                 mbedtls_timing_set_delay,
                                 mbedtls_timing_get_delay);
#endif
    } else {
        TEST_ASSERT(mbedtls_test_ssl_endpoint_init(&server,
                                                   MBEDTLS_SSL_IS_SERVER,
                                                   options->pk_alg, NULL, NULL,
                                                   NULL, NULL) == 0);
    }

    mbedtls_ssl_conf_authmode(&server.conf, options->srv_auth_mode);

    if (options->server_min_version != TEST_SSL_MINOR_VERSION_NONE) {
        mbedtls_ssl_conf_min_version(&server.conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                     options->server_min_version);
    }

    if (options->server_max_version != TEST_SSL_MINOR_VERSION_NONE) {
        mbedtls_ssl_conf_max_version(&server.conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                     options->server_max_version);
    }

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    TEST_ASSERT(mbedtls_ssl_conf_max_frag_len(&(server.conf),
                                              (unsigned char) options->mfl)
                == 0);
    TEST_ASSERT(mbedtls_ssl_conf_max_frag_len(&(client.conf),
                                              (unsigned char) options->mfl)
                == 0);
#else
    TEST_ASSERT(MBEDTLS_SSL_MAX_FRAG_LEN_NONE == options->mfl);
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if (options->psk_str != NULL && options->psk_str->len > 0) {
        TEST_ASSERT(mbedtls_ssl_conf_psk(
                        &client.conf, options->psk_str->x,
                        options->psk_str->len,
                        (const unsigned char *) psk_identity,
                        strlen(psk_identity)) == 0);

        TEST_ASSERT(mbedtls_ssl_conf_psk(
                        &server.conf, options->psk_str->x,
                        options->psk_str->len,
                        (const unsigned char *) psk_identity,
                        strlen(psk_identity)) == 0);

        mbedtls_ssl_conf_psk_cb(&server.conf, psk_dummy_callback, NULL);
    }
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if (options->renegotiate) {
        mbedtls_ssl_conf_renegotiation(&(server.conf),
                                       MBEDTLS_SSL_RENEGOTIATION_ENABLED);
        mbedtls_ssl_conf_renegotiation(&(client.conf),
                                       MBEDTLS_SSL_RENEGOTIATION_ENABLED);

        mbedtls_ssl_conf_legacy_renegotiation(&(server.conf),
                                              options->legacy_renegotiation);
        mbedtls_ssl_conf_legacy_renegotiation(&(client.conf),
                                              options->legacy_renegotiation);
    }
#endif /* MBEDTLS_SSL_RENEGOTIATION */

#if defined(MBEDTLS_DEBUG_C)
    if (options->srv_log_fun) {
        mbedtls_debug_set_threshold(4);
        mbedtls_ssl_conf_dbg(&server.conf, options->srv_log_fun,
                             options->srv_log_obj);
    }
#endif

    TEST_ASSERT(mbedtls_test_mock_socket_connect(&(client.socket),
                                                 &(server.socket),
                                                 BUFFSIZE) == 0);

#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    if (options->resize_buffers != 0) {
        /* Ensure that the buffer sizes are appropriate before resizes */
        TEST_ASSERT(client.ssl.out_buf_len == MBEDTLS_SSL_OUT_BUFFER_LEN);
        TEST_ASSERT(client.ssl.in_buf_len == MBEDTLS_SSL_IN_BUFFER_LEN);
        TEST_ASSERT(server.ssl.out_buf_len == MBEDTLS_SSL_OUT_BUFFER_LEN);
        TEST_ASSERT(server.ssl.in_buf_len == MBEDTLS_SSL_IN_BUFFER_LEN);
    }
#endif

    if (options->expected_negotiated_version == TEST_SSL_MINOR_VERSION_NONE) {
        expected_handshake_result = MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION;
    }

    TEST_ASSERT(mbedtls_test_move_handshake_to_state(
                    &(client.ssl), &(server.ssl), MBEDTLS_SSL_HANDSHAKE_OVER)
                ==  expected_handshake_result);

    if (expected_handshake_result != 0) {
        /* Connection will have failed by this point, skip to cleanup */
        goto exit;
    }

    TEST_ASSERT(client.ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER);
    TEST_ASSERT(server.ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER);

    /* Check that we agree on the version... */
    TEST_ASSERT(client.ssl.minor_ver == server.ssl.minor_ver);

    /* And check that the version negotiated is the expected one. */
    TEST_EQUAL(client.ssl.minor_ver, options->expected_negotiated_version);

#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    if (options->resize_buffers != 0) {
        if (options->expected_negotiated_version != MBEDTLS_SSL_MINOR_VERSION_0 &&
            options->expected_negotiated_version != MBEDTLS_SSL_MINOR_VERSION_1) {
            /* A server, when using DTLS, might delay a buffer resize to happen
             * after it receives a message, so we force it. */
            TEST_ASSERT(exchange_data(&(client.ssl), &(server.ssl)) == 0);

            TEST_ASSERT(client.ssl.out_buf_len ==
                        mbedtls_ssl_get_output_buflen(&client.ssl));
            TEST_ASSERT(client.ssl.in_buf_len ==
                        mbedtls_ssl_get_input_buflen(&client.ssl));
            TEST_ASSERT(server.ssl.out_buf_len ==
                        mbedtls_ssl_get_output_buflen(&server.ssl));
            TEST_ASSERT(server.ssl.in_buf_len ==
                        mbedtls_ssl_get_input_buflen(&server.ssl));
        }
    }
#endif

    if (options->cli_msg_len != 0 || options->srv_msg_len != 0) {
        /* Start data exchanging test */
        TEST_ASSERT(mbedtls_test_ssl_exchange_data(
                        &(client.ssl), options->cli_msg_len,
                        options->expected_cli_fragments,
                        &(server.ssl), options->srv_msg_len,
                        options->expected_srv_fragments)
                    == 0);
    }
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
    if (options->serialize == 1) {
        TEST_ASSERT(options->dtls == 1);

        TEST_ASSERT(mbedtls_ssl_context_save(&(server.ssl), NULL,
                                             0, &context_buf_len)
                    == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);

        context_buf = mbedtls_calloc(1, context_buf_len);
        TEST_ASSERT(context_buf != NULL);

        TEST_ASSERT(mbedtls_ssl_context_save(&(server.ssl), context_buf,
                                             context_buf_len,
                                             &context_buf_len)
                    == 0);

        mbedtls_ssl_free(&(server.ssl));
        mbedtls_ssl_init(&(server.ssl));

        TEST_ASSERT(mbedtls_ssl_setup(&(server.ssl), &(server.conf)) == 0);

        mbedtls_ssl_set_bio(&(server.ssl), &server_context,
                            mbedtls_test_mock_tcp_send_msg,
                            mbedtls_test_mock_tcp_recv_msg,
                            NULL);

#if defined(MBEDTLS_TIMING_C)
        mbedtls_ssl_set_timer_cb(&server.ssl, &timer_server,
                                 mbedtls_timing_set_delay,
                                 mbedtls_timing_get_delay);
#endif
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
        if (options->resize_buffers != 0) {
            /* Ensure that the buffer sizes are appropriate before resizes */
            TEST_ASSERT(server.ssl.out_buf_len == MBEDTLS_SSL_OUT_BUFFER_LEN);
            TEST_ASSERT(server.ssl.in_buf_len == MBEDTLS_SSL_IN_BUFFER_LEN);
        }
#endif
        TEST_ASSERT(mbedtls_ssl_context_load(&(server.ssl), context_buf,
                                             context_buf_len) == 0);

#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
        /* Validate buffer sizes after context deserialization */
        if (options->resize_buffers != 0) {
            TEST_ASSERT(server.ssl.out_buf_len ==
                        mbedtls_ssl_get_output_buflen(&server.ssl));
            TEST_ASSERT(server.ssl.in_buf_len ==
                        mbedtls_ssl_get_input_buflen(&server.ssl));
        }
#endif
        /* Retest writing/reading */
        if (options->cli_msg_len != 0 || options->srv_msg_len != 0) {
            TEST_ASSERT(mbedtls_test_ssl_exchange_data(
                            &(client.ssl), options->cli_msg_len,
                            options->expected_cli_fragments,
                            &(server.ssl), options->srv_msg_len,
                            options->expected_srv_fragments)
                        == 0);
        }
    }
#endif /* MBEDTLS_SSL_CONTEXT_SERIALIZATION */

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if (options->renegotiate) {
        /* Start test with renegotiation */
        TEST_ASSERT(server.ssl.renego_status ==
                    MBEDTLS_SSL_INITIAL_HANDSHAKE);
        TEST_ASSERT(client.ssl.renego_status ==
                    MBEDTLS_SSL_INITIAL_HANDSHAKE);

        /* After calling this function for the server, it only sends a handshake
         * request. All renegotiation should happen during data exchanging */
        TEST_ASSERT(mbedtls_ssl_renegotiate(&(server.ssl)) == 0);
        TEST_ASSERT(server.ssl.renego_status ==
                    MBEDTLS_SSL_RENEGOTIATION_PENDING);
        TEST_ASSERT(client.ssl.renego_status ==
                    MBEDTLS_SSL_INITIAL_HANDSHAKE);

        TEST_ASSERT(exchange_data(&(client.ssl), &(server.ssl)) == 0);
        TEST_ASSERT(server.ssl.renego_status ==
                    MBEDTLS_SSL_RENEGOTIATION_DONE);
        TEST_ASSERT(client.ssl.renego_status ==
                    MBEDTLS_SSL_RENEGOTIATION_DONE);

        /* After calling mbedtls_ssl_renegotiate for the client,
         * all renegotiation should happen inside this function.
         * However in this test, we cannot perform simultaneous communication
         * between client and server so this function will return waiting error
         * on the socket. All rest of renegotiation should happen
         * during data exchanging */
        ret = mbedtls_ssl_renegotiate(&(client.ssl));
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
        if (options->resize_buffers != 0) {
            /* Ensure that the buffer sizes are appropriate before resizes */
            TEST_ASSERT(client.ssl.out_buf_len == MBEDTLS_SSL_OUT_BUFFER_LEN);
            TEST_ASSERT(client.ssl.in_buf_len == MBEDTLS_SSL_IN_BUFFER_LEN);
        }
#endif
        TEST_ASSERT(ret == 0 ||
                    ret == MBEDTLS_ERR_SSL_WANT_READ ||
                    ret == MBEDTLS_ERR_SSL_WANT_WRITE);
        TEST_ASSERT(server.ssl.renego_status ==
                    MBEDTLS_SSL_RENEGOTIATION_DONE);
        TEST_ASSERT(client.ssl.renego_status ==
                    MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS);

        TEST_ASSERT(exchange_data(&(client.ssl), &(server.ssl)) == 0);
        TEST_ASSERT(server.ssl.renego_status ==
                    MBEDTLS_SSL_RENEGOTIATION_DONE);
        TEST_ASSERT(client.ssl.renego_status ==
                    MBEDTLS_SSL_RENEGOTIATION_DONE);
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
        /* Validate buffer sizes after renegotiation */
        if (options->resize_buffers != 0) {
            TEST_ASSERT(client.ssl.out_buf_len ==
                        mbedtls_ssl_get_output_buflen(&client.ssl));
            TEST_ASSERT(client.ssl.in_buf_len ==
                        mbedtls_ssl_get_input_buflen(&client.ssl));
            TEST_ASSERT(server.ssl.out_buf_len ==
                        mbedtls_ssl_get_output_buflen(&server.ssl));
            TEST_ASSERT(server.ssl.in_buf_len ==
                        mbedtls_ssl_get_input_buflen(&server.ssl));
        }
#endif /* MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH */
    }
#endif /* MBEDTLS_SSL_RENEGOTIATION */

exit:
    mbedtls_test_ssl_endpoint_free(&client,
                                   options->dtls != 0 ? &client_context : NULL);
    mbedtls_test_ssl_endpoint_free(&server,
                                   options->dtls != 0 ? &server_context : NULL);
#if defined(MBEDTLS_DEBUG_C)
    if (options->cli_log_fun || options->srv_log_fun) {
        mbedtls_debug_set_threshold(0);
    }
#endif
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
    if (context_buf != NULL) {
        mbedtls_free(context_buf);
    }
#endif
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED && MBEDTLS_CERTS_C &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */

#endif /* MBEDTLS_SSL_TLS_C */
