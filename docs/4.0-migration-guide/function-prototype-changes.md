## Function prototype changes

A number of existing functions now take a different list of arguments, mostly to migrate them to the PSA API.

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

The following function prototype has been changed in `mbedtls/ssl_cookie.h`:

```c
int mbedtls_ssl_cookie_setup(mbedtls_ssl_cookie_ctx *ctx,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng);
```

to

```c
int mbedtls_ssl_cookie_setup(mbedtls_ssl_cookie_ctx *ctx);
```

### Removal of `mbedtls_ssl_conf_rng`

`mbedtls_ssl_conf_rng()` has been removed from the library. Its sole purpose was to configure the RNG used for TLS, but now the PSA Crypto random generator is used throughout the library.

### Changes to mbedtls_ssl_ticket_setup

In the arguments of the function `mbedtls_ssl_ticket_setup()`, the `mbedtls_cipher_type_t` argument specifying the AEAD mechanism for ticket protection has been replaced by an equivalent PSA description consisting of a key type, a size and an algorithm. Also, the function no longer takes RNG arguments.

The prototype in `mbedtls/ssl_ticket.h` has changed from

```c
int mbedtls_ssl_ticket_setup(mbedtls_ssl_ticket_context *ctx,
                             mbedtls_f_rng_t *f_rng, void *p_rng,
                             mbedtls_cipher_type_t cipher,
                             uint32_t lifetime);
```

to

```c
int mbedtls_ssl_ticket_setup(mbedtls_ssl_ticket_context *ctx,
                             psa_algorithm_t alg, psa_key_type_t key_type, psa_key_bits_t key_bits,
                             uint32_t lifetime);
```
