/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef __PSA_CLIENT_H__
#define __PSA_CLIENT_H__

#include <stdint.h>
#include <stddef.h>

#include "psa/crypto.h"

#include "error_ext.h"

#define PSA_FRAMEWORK_VERSION (0x0100u)
static inline uint32_t psa_framework_version(void)
{
    return PSA_FRAMEWORK_VERSION;
}

#define PSA_VERSION_NONE (0u)
static inline uint32_t psa_version(uint32_t sid)
{
    return PSA_VERSION_NONE;
}

typedef int32_t psa_handle_t;
#define PSA_NULL_HANDLE ((psa_handle_t) 0)

typedef struct psa_invec {
    const void *base;
    size_t len;
} psa_invec;

typedef struct psa_outvec {
    void *base;
    size_t len;
} psa_outvec;

psa_handle_t psa_connect(uint32_t sid, uint32_t version);
psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec *in_vec, size_t in_len,
                      psa_outvec *out_vec, size_t out_len);
void psa_close(psa_handle_t handle);

#endif /* __PSA_CLIENT_H__ */
