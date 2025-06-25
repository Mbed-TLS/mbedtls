## High-level API tweaks for PSA

A number of existing functions now take a different list of arguments, to migrate them to the PSA API.

### Public functions no longer take a RNG callback

Functions that need randomness no longer take an RNG callback in the form of `f_rng, p_rng` arguments. Instead, they use the PSA Crypto random generator (accessible as `psa_generate_random()`). All software using the X.509 or SSL modules must call `psa_crypto_init()` before calling any of the functions listed here.

### RNG removal in X.509

The following function prototypes have been changed in `mbedtls/x509_crt.h`:

```c
int mbedtls_x509write_crt_der(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);

int mbedtls_x509write_crt_pem(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);
```

to

```c
int mbedtls_x509write_crt_der(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size);

int mbedtls_x509write_crt_pem(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size);
```

The following function prototypes have been changed in `mbedtls/x509_csr.h`:
```c
int mbedtls_x509write_csr_der(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);

int mbedtls_x509write_csr_pem(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);
```

to

```c
int mbedtls_x509write_csr_der(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size);

int mbedtls_x509write_csr_pem(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size);
```

### RNG removal in SSL

The following function prototypes have been changed in `mbedtls/ssl.h`:

```c
int mbedtls_ssl_ticket_setup(mbedtls_ssl_ticket_context *ctx,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                             psa_algorithm_t alg, psa_key_type_t key_type, psa_key_bits_t key_bits, uint32_t lifetime);
```

```c
int mbedtls_ssl_cookie_setup(mbedtls_ssl_cookie_ctx *ctx,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng);
```

to

```c
int mbedtls_ssl_ticket_setup(mbedtls_ssl_ticket_context *ctx,
                             psa_algorithm_t alg, psa_key_type_t key_type, psa_key_bits_t key_bits, uint32_t lifetime);
```

```c
int mbedtls_ssl_cookie_setup(mbedtls_ssl_cookie_ctx *ctx);
```

The following structs have also been changed in SSL

```c
typedef struct mbedtls_ssl_ticket_context {
    mbedtls_ssl_ticket_key MBEDTLS_PRIVATE(keys)[2]; /*!< ticket protection keys             */
    unsigned char MBEDTLS_PRIVATE(active);           /*!< index of the currently active key  */

    uint32_t MBEDTLS_PRIVATE(ticket_lifetime);       /*!< lifetime of tickets in seconds     */

    /** Callback for getting (pseudo-)random numbers                        */
    int(*MBEDTLS_PRIVATE(f_rng))(void *, unsigned char *, size_t);
    void *MBEDTLS_PRIVATE(p_rng);                    /*!< context for the RNG function       */

#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t MBEDTLS_PRIVATE(mutex);
#endif
}
mbedtls_ssl_ticket_context;
```


to

```c
typedef struct mbedtls_ssl_ticket_context {
    mbedtls_ssl_ticket_key MBEDTLS_PRIVATE(keys)[2]; /*!< ticket protection keys             */
    unsigned char MBEDTLS_PRIVATE(active);           /*!< index of the currently active key  */

    uint32_t MBEDTLS_PRIVATE(ticket_lifetime);       /*!< lifetime of tickets in seconds     */

#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t MBEDTLS_PRIVATE(mutex);
#endif
}
mbedtls_ssl_ticket_context;
```

### Removal of `mbedtls_ssl_conf_rng`

`mbedtls_ssl_conf_rng()` has been removed from the library. Its sole purpose was to configure the RNG used for TLS, but now the PSA Crypto random generator is used throughout the library.
