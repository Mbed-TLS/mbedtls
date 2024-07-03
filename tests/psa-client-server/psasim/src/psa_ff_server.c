/* PSA Firmware Framework service API */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include "common.h"
#include "server.h"
#include "util.h"

static psa_message_t psa_message;
int sockfd = -1;
int connfd = -1;

psa_status_t psa_setup_socket(void)
{
    struct sockaddr_in serv_addr;
    int ret;

    if (sockfd > 0) {
        ERROR("Socket is already open.");
        return PSA_ERROR_BAD_STATE;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(SOCKET_CONNECTION_PORT);

    /* Set a timeout for socket operations in order to be sure we won't hang
     * forever if something weird happens. */
    struct timeval socket_operation_timeout = { 0 };
    socket_operation_timeout.tv_sec = SOCKET_OPERATION_TIMEOUT_S;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
               (const char *) &socket_operation_timeout, sizeof(socket_operation_timeout));

    INFO("Create socket");
    bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));

    /* Limit to just 1 client at a time. */
    INFO("Listen on socket");
    listen(sockfd, 1);

    return PSA_SUCCESS;
}

psa_status_t psa_wait_for_connection(void)
{
    int ret;

    if (sockfd < 0) {
        ERROR("Socket was not created so it cannot wait for connection");
        return PSA_ERROR_BAD_STATE;
    }

    /* Wait for incoming connections. */
    ret = accept(sockfd, NULL, NULL);
    if (ret < 0) {
        ERROR("Socket accept failed (%d)", errno);
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    connfd = ret;
    INFO("Incoming connection");

    return PSA_SUCCESS;
}

psa_status_t psa_wait_for_command(void)
{
    size_t read_bytes, total_bytes_read = 0;
    uint8_t *ptr = (uint8_t *) &psa_message;
    socket_message_t socket_message = { 0 };

    if ((sockfd < 0) || (connfd < 0)) {
        ERROR("Invalid socket (sockfd=%d - connfd=%d).", sockfd, connfd);
        return PSA_ERROR_BAD_STATE;
    }

    do {
        /* Try to read as much bytes as possible. Wait if no data is available. */
        read_bytes = read(connfd, &socket_message, sizeof(socket_message));
        if (read_bytes <= 0) {
            return PSA_ERROR_COMMUNICATION_FAILURE;
        }
        memcpy(ptr, &socket_message.payload, socket_message.length);
        ptr += socket_message.length;
        total_bytes_read += read_bytes;
        INFO("Read %zu bytes", socket_message.length);
    } while (socket_message.is_last_message == 0);

    INFO("Received command total length:%zu bytes", total_bytes_read);

    return PSA_SUCCESS;
}

size_t psa_get_invec(uint32_t invec_idx, void *buffer, size_t num_bytes)
{
    uint8_t *ptr = (uint8_t *) &psa_message.payload;

    if (invec_idx >= PSA_MAX_IOVEC) {
        ERROR("Invalid vector index");
        return 0;
    }

    if (num_bytes < psa_message.invec_sizes[invec_idx]) {
        ERROR("Specified buffer is too small to contain the specified invec");
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Go to the requested vector. */
    for (int i = 0; i < invec_idx; i++) {
        ptr += psa_message.invec_sizes[i];
    }

    memcpy(buffer, ptr, psa_message.invec_sizes[invec_idx]);
    INFO("Read %zu bytes from invec %u", psa_message.invec_sizes[invec_idx], invec_idx);

    return psa_message.invec_sizes[invec_idx];
}

size_t psa_set_outvec(uint32_t outvec_idx, const void *buffer, size_t num_bytes)
{
    uint8_t *ptr = (uint8_t *) &psa_message.payload;

    if (outvec_idx >= PSA_MAX_IOVEC) {
        ERROR("Invalid vector index");
        return 0;
    }

    /* Go to the requested vector. */
    for (int i = 0; i < PSA_MAX_IOVEC; i++) {
        ptr += psa_message.invec_sizes[i];
    }
    for (int i = 0; i < outvec_idx; i++) {
        ptr += psa_message.outvec_sizes[i];
    }

    memcpy(ptr, buffer, num_bytes);
    INFO("Wrote %zd bytes to outvec %d", psa_message.outvec_sizes[outvec_idx], outvec_idx);

    return num_bytes;
}

int32_t psa_get_psa_function(void)
{
    return psa_message.psa_function;
}

void psa_get_vectors_sizes(size_t *invec_sizes, size_t *outvec_sizes)
{
    memcpy(invec_sizes, psa_message.invec_sizes, sizeof(psa_message.invec_sizes));
    memcpy(outvec_sizes, psa_message.outvec_sizes, sizeof(psa_message.outvec_sizes));
}

psa_status_t psa_send_reply(void)
{
    psa_status_t status;
    size_t psa_message_payload_len = 0;

    for (int i = 0; i < PSA_MAX_IOVEC; i++) {
        psa_message_payload_len += psa_message.invec_sizes[i];
        psa_message_payload_len += psa_message.outvec_sizes[i];
    }

    status = send_psa_message(&psa_message, psa_message_payload_len, connfd);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return PSA_SUCCESS;
}

void psa_close_connection(void)
{
    if (connfd > 0) {
        close(connfd);
        connfd = -1;
    }
}

void psa_close_socket(void)
{
    if (sockfd > 0) {
        close(sockfd);
        sockfd = -1;
    }
}
