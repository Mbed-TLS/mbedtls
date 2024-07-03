/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include "client.h"
#include "common.h"
#include "error_ext.h"
#include "util.h"

int sockfd = -1;
static psa_message_t psa_message;

static psa_status_t fill_psa_message(int32_t psa_function,
                                     const psa_invec *in_vec, size_t in_vec_count,
                                     psa_outvec *out_vec, size_t out_vec_count,
                                     size_t *payload_len)
{
    size_t remaining_bytes = MAX_PSA_MESSAGE_PAYLOAD;
    uint8_t *ptr = (uint8_t *) psa_message.payload;
    *payload_len = 0;

    memset(&psa_message, 0, sizeof(psa_message_t));
    psa_message.psa_function = psa_function;

    /* Copy input vectors first... */
    for (int i = 0; i < in_vec_count; i++) {
        psa_message.invec_sizes[i] = in_vec[i].len;
        if ((in_vec[i].len > 0) && (in_vec[i].base != NULL)) {
            if (in_vec[i].len > remaining_bytes) {
                ERROR("Not enough space in psa message.");
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }
            memcpy(ptr, in_vec[i].base, in_vec[i].len);
            ptr += in_vec[i].len;
            remaining_bytes -= in_vec[i].len;
            *payload_len += in_vec[i].len;
        }
    }
    /* ... and then output ones. */
    for (int i = 0; i < out_vec_count; i++) {
        psa_message.outvec_sizes[i] = out_vec[i].len;
        if ((out_vec[i].len > 0) && (out_vec[i].base != NULL)) {
            if (out_vec[i].len > remaining_bytes) {
                ERROR("Not enough space in psa message.");
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }
            memcpy(ptr, out_vec[i].base, out_vec[i].len);
            ptr += out_vec[i].len;
            remaining_bytes -= out_vec[i].len;
            *payload_len += out_vec[i].len;
        }
    }

    return PSA_SUCCESS;
}

static psa_status_t read_reply()
{
    size_t read_bytes, total_read_bytes = 0;
    socket_message_t socket_message = { 0 };
    uint8_t *ptr = (uint8_t *) &psa_message;

    memset(&psa_message, 0, sizeof(psa_message_t));

    /* Try to reconstruct the psa_message_t sent from the server. */
    do {
        read_bytes = read(sockfd, &socket_message, sizeof(socket_message_t));
        memcpy(ptr, socket_message.payload, socket_message.length);
        ptr += socket_message.length;
        memset(socket_message.payload, 0, sizeof(socket_message.length));
        total_read_bytes += read_bytes;
    } while (socket_message.is_last_message == 0);

    INFO("Received %lu bytes", total_read_bytes);

    return PSA_SUCCESS;
}

static psa_status_t unwrap_psa_reply(psa_outvec *out_vec, size_t out_vec_count)
{
    uint8_t *ptr = (uint8_t *) psa_message.payload;

    /* First of all we must skip invec data from the psa_message_t payload. */
    for (int i = 0; i < PSA_MAX_IOVEC; i++) {
        ptr += psa_message.invec_sizes[i];
    }

    /* Now we can fill out_vec with data returned from the server. */
    for (int i = 0; i < out_vec_count; i++) {
        memcpy(out_vec[i].base, ptr, psa_message.outvec_sizes[i]);
        out_vec[i].len = psa_message.outvec_sizes[i];
        ptr += psa_message.outvec_sizes[i];
    }

    return PSA_SUCCESS;
}

psa_status_t psa_call(int32_t psa_function,
                      const psa_invec *in_vec,
                      size_t in_len,
                      psa_outvec *out_vec,
                      size_t out_len)
{
    psa_status_t status;
    size_t psa_message_payload_len;

    if (sockfd < 0) {
        ERROR("Socket was not open");
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    if ((in_len > PSA_MAX_IOVEC) || (out_len > PSA_MAX_IOVEC)) {
        ERROR("Too many iovecs: in_len=%lu - out_len=%lu", in_len, out_len);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = fill_psa_message(psa_function, in_vec, in_len, out_vec, out_len,
                              &psa_message_payload_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = send_psa_message(&psa_message, psa_message_payload_len, sockfd);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = read_reply();
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = unwrap_psa_reply(out_vec, out_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return status;
}

psa_status_t psa_connect(void)
{
    struct sockaddr_in serv_addr = { 0 };
    int ret;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        ERROR("Could not create socket");
        return PSA_ERROR_CONNECTION_REFUSED;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(SOCKET_CONNECTION_PORT);

    /* Set a timeout for socket operations in order to be sure we won't hang
     * forever if something weird happens. */
    struct timeval socket_operation_timeout = { 0 };
    int sock_reuse = 1;
    socket_operation_timeout.tv_sec = SOCKET_OPERATION_TIMEOUT_S;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
               (const char *) &socket_operation_timeout, sizeof(socket_operation_timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
               (const void *) &sock_reuse, sizeof(sock_reuse));

    ret = connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    if (ret < 0) {
        ERROR("Connect failed (%d)", errno);
        sockfd = -1;
        return PSA_ERROR_CONNECTION_REFUSED;
    }

    return PSA_SUCCESS;
}

void psa_close(void)
{
    if (sockfd < 0) {
        return;
    }

    close(sockfd);
    sockfd = -1;
}
