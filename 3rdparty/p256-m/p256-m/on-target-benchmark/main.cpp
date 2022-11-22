/*
 * On-target benchmark program for p256-m using Mbed OS.
 */
#include "mbed.h"

extern "C" {
#include "p256-m.h"
}

/* test version based on stdlib - never do this in production! */
int p256_generate_random(uint8_t *output, unsigned output_size)
{
    for (unsigned i = 0; i < output_size; i++) {
        output[i] = (uint8_t) rand();
    }

    return 0;
}

Timer t;
int total_ms = 0;

#define FMT "%10s: %5d ms\n"

#define TIMEIT(NAME, CODE)          \
    t.reset();                      \
    t.start();                      \
    CODE;                           \
    t.stop();                       \
    total_ms += t.read_ms();        \
    printf(FMT, NAME, t.read_ms());

int main()
{
    uint8_t priv[32], pub[64], secret[32], sig[64], hash[32];

    puts("\np256-m benchmark");
    TIMEIT("Keygen", p256_gen_keypair(priv, pub));
    TIMEIT("ECDH", p256_ecdh_shared_secret(secret, priv, pub));
    TIMEIT("Sign", p256_ecdsa_sign(sig, priv, hash, sizeof hash));
    TIMEIT("Verify", p256_ecdsa_verify(sig, pub, hash, sizeof hash));

    /* The total is useful for quick comparisons.
     *
     * It also happens to represent the computation time for a mutually
     * authenticated TLS handshake with directly-trusted certs or raw public
     * keys (with actual cert chains there are extra signature verifications).
     */
    printf(FMT, "Total", total_ms);
}
