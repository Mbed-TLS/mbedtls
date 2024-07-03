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

typedef struct psa_invec {
    const void *base;
    size_t len;
} psa_invec;

typedef struct psa_outvec {
    void *base;
    size_t len;
} psa_outvec;

psa_status_t psa_connect(void);

psa_status_t psa_call(int32_t type,
                      const psa_invec *in_vec, size_t in_len,
                      psa_outvec *out_vec, size_t out_len);

void psa_close(void);

#endif /* __PSA_CLIENT_H__ */
