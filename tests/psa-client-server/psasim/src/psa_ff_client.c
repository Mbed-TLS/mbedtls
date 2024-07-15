/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <sys/types.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <time.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "client.h"
#include "common.h"
#include "error_ext.h"
#include "util.h"

static int shm_id = -1;
static key_t shm_key = -1;
static shared_memory_t *shared_memory = NULL;
static psa_message_t *psa_message;

static psa_status_t fill_psa_message(int32_t psa_function,
                                     const psa_invec *in_vec, size_t in_vec_count,
                                     psa_outvec *out_vec, size_t out_vec_count,
                                     size_t *payload_len)
{
    size_t remaining_bytes = MAX_PSA_MESSAGE_PAYLOAD;
    uint8_t *ptr = (uint8_t *) psa_message->payload;
    *payload_len = 0;

    memset((void *) psa_message, 0, sizeof(psa_message_t));
    psa_message->psa_function = psa_function;

    /* Copy input vectors first... */
    for (int i = 0; i < in_vec_count; i++) {
        psa_message->invec_sizes[i] = in_vec[i].len;
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
        psa_message->outvec_sizes[i] = out_vec[i].len;
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

static psa_status_t wait_for_reply()
{
    struct timespec start_ts;
    struct timespec current_ts;

    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    while (atomic_load(&(shared_memory->owner)) != SHARED_MEMORY_OWNER_CLIENT) {
        clock_gettime(CLOCK_MONOTONIC, &current_ts);
        if ((current_ts.tv_sec - start_ts.tv_sec) > COMMUNICATION_TIMEOUT_S) {
            ERROR("Communication timed out");
            return PSA_ERROR_COMMUNICATION_FAILURE;
        }
    }

    return PSA_SUCCESS;
}

static psa_status_t unwrap_psa_reply(psa_outvec *out_vec, size_t out_vec_count)
{
    uint8_t *ptr = (uint8_t *) psa_message->payload;

    /* First of all we must skip invec data from the psa_message_t payload. */
    for (int i = 0; i < PSA_MAX_IOVEC; i++) {
        ptr += psa_message->invec_sizes[i];
    }

    /* Now we can fill out_vec with data returned from the server. */
    for (int i = 0; i < out_vec_count; i++) {
        memcpy(out_vec[i].base, ptr, psa_message->outvec_sizes[i]);
        out_vec[i].len = psa_message->outvec_sizes[i];
        ptr += psa_message->outvec_sizes[i];
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

    if (shared_memory == NULL) {
        /* Likely the PSA connection has not been established. */
        return PSA_ERROR_BAD_STATE;
    }

    if ((in_len > PSA_MAX_IOVEC) || (out_len > PSA_MAX_IOVEC)) {
        ERROR("Too many iovecs: in_len=%lu - out_len=%lu", in_len, out_len);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    INFO("Prepare and send PSA message");
    status = fill_psa_message(psa_function, in_vec, in_len, out_vec, out_len,
                              &psa_message_payload_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Change the ownweship of the shared memory to the server.  */
    atomic_store(&(shared_memory->owner), SHARED_MEMORY_OWNER_SERVER);

    INFO("Wait for reply");
    status = wait_for_reply();
    if (status != PSA_SUCCESS) {
        return status;
    }

    INFO("Reply received. Unwrap it");
    status = unwrap_psa_reply(out_vec, out_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return status;
}

psa_status_t psa_connect(void)
{
    shm_key = ftok(PSASIM_SHM_PATH, 'X');
    if (shm_key < 0) {
        ERROR("Unable to generate SystemV IPC key (%d)", errno);
        return PSA_ERROR_GENERIC_ERROR;
    }

    shm_id = shmget(shm_key, sizeof(shared_memory_t), IPC_CREAT | 0660);
    if (shm_id < 0) {
        ERROR("Unable to allocate shared memory (%d)", errno);
        return PSA_ERROR_GENERIC_ERROR;
    }

    shared_memory = (shared_memory_t *) shmat(shm_id, NULL, 0);
    if (shared_memory == (shared_memory_t *) -1) {
        ERROR("Unable to attach process to shared memory (%d)", errno);
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_message = &(shared_memory->psa_message);

    /* The shared memory is already zeroed by the server, so no action is
     * expected from the client here. */

    return PSA_SUCCESS;
}

void psa_close(void)
{
    if (shared_memory != NULL) {
        shmdt(shared_memory);
        shared_memory = NULL;
    }
}
