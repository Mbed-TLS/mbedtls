/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef __PSA_SERVICE_H__
#define __PSA_SERVICE_H__

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#include "psa/crypto.h"

#include "common.h"

typedef uint32_t psa_signal_t;
typedef int32_t psa_handle_t;
#define PSA_NULL_HANDLE ((psa_handle_t) 0)

typedef struct psa_msg_t {
    int32_t type;
    psa_handle_t handle;
    int32_t client_id;
    void *rhandle;
    size_t in_size[PSA_MAX_IOVEC];
    size_t out_size[PSA_MAX_IOVEC];
} psa_msg_t;

/* Implemented functions */
psa_status_t psa_wait(psa_signal_t signal_mask, uint32_t timeout);
size_t psa_read(psa_handle_t msg_handle, uint32_t invec_idx, void *buffer, size_t num_bytes);
size_t psa_write(psa_handle_t msg_handle, uint32_t outvec_idx, const void *buffer,
                 size_t num_bytes);
psa_status_t psa_reply(psa_handle_t msg_handle, psa_status_t status);

/* Not implemented functions */
psa_status_t psa_get(psa_signal_t signal, psa_msg_t *msg);
void psa_set_rhandle(psa_handle_t msg_handle, void *rhandle);
void psa_clear(void);
void psa_notify(int32_t partition_id);
size_t psa_skip(psa_handle_t msg_handle, uint32_t invec_idx, size_t num_bytes);
void psa_eoi(psa_signal_t irq_signal);
void psa_panic(void);

/* Extra functions*/
psa_status_t psa_setup(void);
void psa_close(void);
int32_t psa_get_psa_function(void);
void psa_get_vectors_sizes(size_t *invec_sizes, size_t *outvec_sizes);

#endif /* __PSA_SERVICE_H__ */
