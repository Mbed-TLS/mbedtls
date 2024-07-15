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

psa_status_t psa_setup(void);
void psa_close(void);

psa_status_t psa_wait_for_command(void);
psa_status_t psa_send_reply(void);
int32_t psa_get_psa_function(void);
void psa_get_vectors_sizes(size_t *invec_sizes, size_t *outvec_sizes);
size_t psa_get_invec(uint32_t invec_idx, void *buffer, size_t num_bytes);
size_t psa_set_outvec(uint32_t outvec_idx, const void *buffer, size_t num_bytes);

#endif /* __PSA_SERVICE_H__ */
