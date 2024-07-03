/* Common definitions used for clients and services */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

#include "psa/crypto.h"

#define PSASIM_SHM_PATH     "psasim-shm"

/* This is the structure of the PSA message that will be exchanged between
 * server and client.
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

#define COMMUNICATION_TIMEOUT_S  (60)

#define SHARED_MEMORY_OWNER_UNDEFINED   0 /* Default value at startup */
#define SHARED_MEMORY_OWNER_CLIENT      1
#define SHARED_MEMORY_OWNER_SERVER      2

/* This is the layout the shared memory between client and server. It embeds
 * the psa_message and some communication's control logic.
 */
struct shared_memory_s {
    atomic_char owner; /* who controls the shared memory (client or server)? */
    psa_message_t psa_message;
} __attribute__((packed));
typedef struct shared_memory_s shared_memory_t;

#endif /* _COMMON_H_ */
