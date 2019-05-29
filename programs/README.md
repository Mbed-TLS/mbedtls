Mbed TLS sample programs
========================

This subdirectory mostly contains sample programs that illustrate specific features of the library, as well as a few test and support programs.

## Symmetric cryptography (AES) examples

* [`aes/aescrypt2.c`](aes/aescrypt2.c): file encryption and authentication with a key derived from a low-entropy secret, demonstrating the low-level AES interface, the digest interface and HMAC.  
  Warning: this program illustrates how to use low-level functions in the library. It should not be taken as an example of how to build a secure encryption mechanism. To derive a key from a low-entropy secret such as a password, use a standard key stretching mechanism such as PBKDF2 (provided by the `pkcs5` module). To encrypt and authenticate data, use a standard mode such as GCM or CCM (both available as library module).

* [`aes/crypt_and_hash.c`](aes/crypt_and_hash.c): file encryption and authentication, demonstrating the generic cipher interface and the generic hash interface.

## Hash (digest) examples

* [`hash/generic_sum.c`](hash/generic_sum.c): file hash calculator and verifier, demonstrating the message digest (`md`) interface.

* [`hash/hello.c`](hash/hello.c): hello-world program for MD5.

## Public-key cryptography examples

### Generic public-key cryptography (`pk`) examples

* [`pkey/gen_key.c`](pkey/gen_key.c): generates a key for any of the supported public-key algorithms (RSA or ECC) and writes it to a file that can be used by the other pk sample programs.

* [`pkey/key_app.c`](pkey/key_app.c): loads a PEM or DER public key or private key file and dumps its content.

* [`pkey/key_app_writer.c`](pkey/key_app_writer.c): loads a PEM or DER public key or private key file and writes it to a new PEM or DER file.

* [`pkey/pk_encrypt.c`](pkey/pk_encrypt.c), [`pkey/pk_decrypt.c`](pkey/pk_decrypt.c): loads a PEM or DER public/private key file and uses the key to encrypt/decrypt a short string through the generic public-key interface.

* [`pkey/pk_sign.c`](pkey/pk_sign.c), [`pkey/pk_verify.c`](pkey/pk_verify.c): loads a PEM or DER private/public key file and uses the key to sign/verify a short string.

### ECDSA and RSA signature examples

* [`pkey/ecdsa.c`](pkey/ecdsa.c): generates an ECDSA key, signs a fixed message and verifies the signature.

* [`pkey/rsa_encrypt.c`](pkey/rsa_encrypt.c), [`pkey/rsa_decrypt.c`](pkey/rsa_decrypt.c): loads an RSA public/private key and uses it to encrypt/decrypt a short string through the low-level RSA interface.

* [`pkey/rsa_genkey.c`](pkey/rsa_genkey.c): generates an RSA key and writes it to a file that can be used with the other RSA sample programs.

* [`pkey/rsa_sign.c`](pkey/rsa_sign.c), [`pkey/rsa_verify.c`](pkey/rsa_verify.c): loads an RSA private/public key and uses it to sign/verify a short string with the RSA PKCS#1 v1.5 algorithm.

* [`pkey/rsa_sign_pss.c`](pkey/rsa_sign_pss.c), [`pkey/rsa_verify_pss.c`](pkey/rsa_verify_pss.c): loads an RSA private/public key and uses it to sign/verify a short string with the RSASSA-PSS algorithm.

### Diffie-Hellman key exchange examples

* [`pkey/ecdh_curve25519.c`](pkey/ecdh_curve25519.c): demonstration of a elliptic curve Diffie-Hellman (ECDH) key agreement.

### Bignum (`mpi`) usage examples

* [`pkey/dh_genprime.c`](pkey/dh_genprime.c): shows how to use the bignum (`mpi`) interface to generate Diffie-Hellman parameters.

* [`pkey/mpi_demo.c`](pkey/mpi_demo.c): demonstrates operations on big integers.

## Random number generator (RNG) examples

* [`random/gen_entropy.c`](random/gen_entropy.c): shows how to use the default entropy sources to generate random data.  
  Note: most applications should only use the entropy generator to seed a cryptographic pseudorandom generator, as illustrated by `random/gen_random_ctr_drbg.c`.

* [`random/gen_random_ctr_drbg.c`](random/gen_random_ctr_drbg.c): shows how to use the default entropy sources to seed a pseudorandom generator, and how to use the resulting random generator to generate random data.

* [`random/gen_random_havege.c`](random/gen_random_havege.c): demonstrates the HAVEGE entropy collector.

## Test utilities

* [`test/benchmark.c`](test/benchmark.c): benchmark for cryptographic algorithms.

* [`test/selftest.c`](test/selftest.c): runs the self-test function in each library module.

* [`test/udp_proxy.c`](test/udp_proxy.c): a UDP proxy that can inject certain failures (delay, duplicate, drop). Useful for testing DTLS.

* [`test/zeroize.c`](test/zeroize.c): a test program for `mbedtls_platform_zeroize`, used by [`tests/scripts/test_zeroize.gdb`](tests/scripts/test_zeroize.gdb).

## Development utilities

* [`util/pem2der.c`](util/pem2der.c): a PEM to DER converter. Mbed TLS can read PEM files directly, but this utility can be useful for interacting with other tools or with minimal Mbed TLS builds that lack PEM support.

* [`util/strerror.c`](util/strerror.c): prints the error description corresponding to an integer status returned by an Mbed TLS function.
