/*
 * Dummy program for on-host profiling.
 * See prof-vg.sh, prof-g.sh, prof-gpt.sh
 *
 * Author: Manuel Pégourié-Gonnard.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include "p256-m.h"

/* test version based on stdlib - never do this in production! */
int p256_generate_random(uint8_t *output, unsigned output_size)
{
    for (unsigned i = 0; i < output_size; i++) {
        output[i] = (uint8_t) rand();
    }

    return 0;
}

#if !defined(TIMES)
#define TIMES 1
#endif

int main(void)
{
    uint8_t priv[32], pub[64], secret[32], sig[64], hash[32];
    int ret = 0;

    for (unsigned i = 0; i < TIMES; i++)
    {
        ret |= p256_gen_keypair(priv, pub);
        ret |= p256_ecdh_shared_secret(secret, priv, pub);
        ret |= p256_ecdsa_sign(sig, priv, hash, sizeof hash);
        ret |= p256_ecdsa_verify(sig, pub, hash, sizeof hash);
    }

    return ret;
}
