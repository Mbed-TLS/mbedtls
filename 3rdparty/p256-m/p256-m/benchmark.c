/*
 * On-host benchmark program. See bench.sh.
 * See also: on-target-bencmark.
 *
 * Author: Manuel Pégourié-Gonnard.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <inttypes.h>

#include "p256-m.h"

/* test version based on stdlib - never do this in production! */
int p256_generate_random(uint8_t *output, unsigned output_size)
{
    for (unsigned i = 0; i < output_size; i++) {
        output[i] = (uint8_t) rand();
    }

    return 0;
}

static uint64_t usec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t) tv.tv_sec * 1000000 + (uint64_t) tv.tv_usec;
}

#define SUCCESS     P256_SUCCESS
#define TIMES       100
#define TIMEIT(N, CODE)                                             \
do {                                                                \
    if (CODE != SUCCESS)                                            \
        printf("%s failed\n", names[N]);                            \
    const uint64_t start = usec();                                  \
    for (unsigned i = 0; i < TIMES; i++) {                          \
        CODE;                                                       \
    }                                                               \
    results[N][i] = (usec() - start) / TIMES;                       \
} while (0)

#define RUNS 5

int cmp_u64(const void *a, const void *b) {
    uint64_t x = *((uint64_t *) a);
    uint64_t y = *((uint64_t *) b);
    if (x < y)
        return -1;
    if (x > y)
        return 1;
    return 0;
}

int main(void)
{
    uint8_t priv[32], pub[64], secret[32], sig[64], hash[32];
    uint64_t results[4][RUNS], total = 0;
    const char * names[4] = {"Keygen", "ECDH", "Sign", "Verify"};

    for (unsigned i = 0; i < RUNS; i++) {
        TIMEIT(0, p256_gen_keypair(priv, pub));
        TIMEIT(1, p256_ecdh_shared_secret(secret, priv, pub));
        TIMEIT(2, p256_ecdsa_sign(sig, priv, hash, sizeof hash));
        TIMEIT(3, p256_ecdsa_verify(sig, pub, hash, sizeof hash));
    }

    for (unsigned n = 0; n < 4; n++) {
        qsort(results[n], RUNS, sizeof results[n][0], cmp_u64);
        uint64_t median = results[n][RUNS / 2];
        printf("%s: %"PRIu64" us\n", names[n], median);
        total += median;
    }
    printf("%s: %"PRIu64" us\n", "Total", total);

    return 0;
}
