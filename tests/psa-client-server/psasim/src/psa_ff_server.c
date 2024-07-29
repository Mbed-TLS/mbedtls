/* PSA Firmware Framework service API */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <sys/types.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/stat.h>
#include <time.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "common.h"
#include "service.h"
#include "util.h"

static int shm_id = -1;
static key_t shm_key = -1;
static shared_memory_t *shared_memory = NULL;
static psa_message_t *psa_message;

psa_status_t psa_setup(void)
{
    FILE *fp = NULL;

    /* Check if the required file exists. If yes, then cancel it before
     * (re)creating it. */
    fp = fopen(PSASIM_SHM_PATH, "wb");
    if (fp == NULL) {
        ERROR("Unable to create temporary file");
        return PSA_ERROR_GENERIC_ERROR;
    }
    fclose(fp);

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

    memset((void *) shared_memory, 0, sizeof(shared_memory_t));
    psa_message = &(shared_memory->psa_message);

    return PSA_SUCCESS;
}

void psa_close(void)
{
    if (shared_memory != NULL) {
        shmdt(shared_memory);
        shared_memory = NULL;
    }

    if (shm_id != -1) {
        shmctl(shm_id, IPC_RMID, NULL);
        shm_id = -1;
    }

    remove(PSASIM_SHM_PATH);
}

psa_status_t psa_wait(psa_signal_t signal_mask, uint32_t timeout)
{
    struct timespec start_ts;
    struct timespec current_ts;
    (void) signal_mask;

    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    while (atomic_load(&(shared_memory->owner)) != SHARED_MEMORY_OWNER_SERVER) {
        clock_gettime(CLOCK_MONOTONIC, &current_ts);
        if ((current_ts.tv_sec - start_ts.tv_sec) > timeout) {
            return PSA_ERROR_COMMUNICATION_FAILURE;
        }
    }

    return PSA_SUCCESS;
}

size_t psa_read(psa_handle_t msg_handle, uint32_t invec_idx, void *buffer, size_t num_bytes)
{
    (void) msg_handle;
    uint8_t *ptr = (uint8_t *) &psa_message->payload;

    if (invec_idx >= PSA_MAX_IOVEC) {
        ERROR("Invalid vector index");
        return 0;
    }

    if (num_bytes < psa_message->invec_sizes[invec_idx]) {
        ERROR("Specified buffer is too small to contain the specified invec");
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Go to the requested vector. */
    for (int i = 0; i < invec_idx; i++) {
        ptr += psa_message->invec_sizes[i];
    }

    memcpy(buffer, ptr, psa_message->invec_sizes[invec_idx]);
    INFO("Read %zu bytes from invec %u", psa_message->invec_sizes[invec_idx], invec_idx);

    return psa_message->invec_sizes[invec_idx];
}

size_t psa_write(psa_handle_t msg_handle, uint32_t outvec_idx, const void *buffer, size_t num_bytes)
{
    (void) msg_handle;
    uint8_t *ptr = (uint8_t *) &psa_message->payload;

    if (outvec_idx >= PSA_MAX_IOVEC) {
        ERROR("Invalid vector index");
        return 0;
    }

    if (atomic_load(&(shared_memory->owner)) != SHARED_MEMORY_OWNER_SERVER) {
        ERROR("Cannot write on shared memory while it's owned by the client");
        return PSA_ERROR_BAD_STATE;
    }

    /* Go to the requested vector. */
    for (int i = 0; i < PSA_MAX_IOVEC; i++) {
        ptr += psa_message->invec_sizes[i];
    }
    for (int i = 0; i < outvec_idx; i++) {
        ptr += psa_message->outvec_sizes[i];
    }

    memcpy(ptr, buffer, num_bytes);
    INFO("Wrote %zd bytes to outvec %d", psa_message->outvec_sizes[outvec_idx], outvec_idx);

    return num_bytes;
}

int32_t psa_get_psa_function(void)
{
    return psa_message->psa_function;
}

void psa_get_vectors_sizes(size_t *invec_sizes, size_t *outvec_sizes)
{
    memcpy(invec_sizes, psa_message->invec_sizes, sizeof(psa_message->invec_sizes));
    memcpy(outvec_sizes, psa_message->outvec_sizes, sizeof(psa_message->outvec_sizes));
}

psa_status_t psa_reply(psa_handle_t msg_handle, psa_status_t status)
{
    if (atomic_load(&(shared_memory->owner)) != SHARED_MEMORY_OWNER_SERVER) {
        ERROR("Cannot write on shared memory while it's owned by the client");
        return PSA_ERROR_BAD_STATE;
    }

    /* Just toggle the ownership of the shared memory */
    atomic_store(&(shared_memory->owner), SHARED_MEMORY_OWNER_CLIENT);

    return PSA_SUCCESS;
}
