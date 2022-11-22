/*
 * See deps.sh - this provides an entry point for the linker.
 *
 * Author: Manuel Pégourié-Gonnard.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "p256-m.h"

/* dummy non-random version just to make the linker happy */
int p256_generate_random(uint8_t *output, unsigned output_size)
{
    for (unsigned i = 0; i < output_size; i++) {
        output[i] = 0;
    }

    return 0;
}

int p256_entry(void)
{
    uint8_t priv[32], pub[64], secret[32], sig[64], hash[32];

    p256_gen_keypair(priv, pub);
    p256_ecdh_shared_secret(secret, priv, pub);
    p256_ecdsa_sign(sig, priv, hash, sizeof hash);
    p256_ecdsa_verify(sig, pub, hash, sizeof hash);

    return 0;
}
