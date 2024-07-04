/* Common definitions used for clients and services */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdint.h>
#include <stddef.h>

#include "psa/crypto.h"

typedef int32_t psa_handle_t;

/* Both client and server will declare local buffers for command and replies
 * in order to avoid heap memory usage.
 */
#define MAX_PSA_MESSAGE_LENGTH          (65536)
#define PSA_MESSAGE_HEADER_LENGTH       (sizeof(int32_t) + 2 * PSA_MAX_IOVEC * sizeof(size_t))
#define MAX_PSA_MESSAGE_PAYLOAD         (MAX_PSA_MESSAGE_LENGTH - PSA_MESSAGE_HEADER_LENGTH)

#define PSA_MAX_IOVEC (4u)
struct psa_message_s {
    int32_t psa_function;
    size_t invec_sizes[PSA_MAX_IOVEC];
    size_t outvec_sizes[PSA_MAX_IOVEC];
    /* Payload will contain all invec first and then all outvec. */
    char payload[MAX_PSA_MESSAGE_PAYLOAD];
} __attribute__((packed));
typedef struct psa_message_s psa_message_t;

/* This is the name of the socket file that will be created by the server. */
#define SOCKET_NAME                "psasim-socket"

#define MAX_SOCKET_MESSAGE_LENGTH   (65536)
/* Sum of is_last_message + length fields of the structure */
#define SOCKET_MESSAGE_HEADER_LENGTH (sizeof(uint8_t) + sizeof(size_t))
#define MAX_SOCKET_PAYLOAD_LENGTH   (MAX_SOCKET_MESSAGE_LENGTH - SOCKET_MESSAGE_HEADER_LENGTH)
#define SOCKET_OPERATION_TIMEOUT_S  (10)

/* Since psa_message_t can easily be quite large and the amount
 * of data that can be exchanged on the socket is limited, we split it into
 * chunks.
 */
struct socket_message_s {
    uint8_t is_last_message; /* In case the message is split in multiple parts,
                                are there any blocks after this one? */
    size_t length; /* Length of valid data in the payload. */
    char payload[MAX_SOCKET_PAYLOAD_LENGTH]; /* Payload, i.e. a chunk of psa_message_t */
} __attribute__((packed));
typedef struct socket_message_s socket_message_t;

psa_status_t send_psa_message(psa_message_t *psa_message, size_t payload_len, int sockfd);

#endif /* _COMMON_H_ */
