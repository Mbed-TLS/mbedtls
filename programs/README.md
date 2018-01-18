Mbed TLS sample programs
========================

This subdirectory mostly contains sample programs that illustrate specific features of the library, as well as a few test and support programs.

## Symmetric cryptography (AES) examples

* [`aes/aescrypt2.c`](aes/aescrypt2.c): file encryption and authentication, demonstrating the low-level AES interface and HMAC.  
  Warning: this program illustrates how to roll your own block cipher mode. Most applications should not do this and should instead use the standard library functions (e.g. `mbedtls_aes_crypt_cbc`).

* [`aes/crypt_and_hash.c`](aes/crypt_and_hash.c): file encryption and authentication, demonstrating the generic cipher interface and the generic hash interface.

## Hash (digest) examples

* [`hash/generic_sum.c`](hash/generic_sum.c): file hash calculator and verifier, demonstrating the message digest (`md`) interface.

* [`hash/hello.c`](hash/hello.c): hello-world program for MD5.

## Public-key cryptography examples

### Generic public-key cryptography (`pk`) examples

* [`pkey/gen_key.c`](pkey/gen_key.c): generate a key for any of the supported public-key algorithms (RSA or ECC) and write it to a file that can be used by the other pk sample programs.

* [`pkey/key_app.c`](pkey/key_app.c): Load a PEM or DER public key or private key file and dump its content.

* [`pkey/key_app_writer.c`](pkey/key_app_writer.c): Load a PEM or DER public key or private key file and write it to a new PEM or DER file.

* [`pkey/pk_encrypt.c`](pkey/pk_encrypt.c), [`pkey/pk_decrypt.c`](pkey/pk_decrypt.c): Load a PEM or DER public/private key file and use the key to encrypt/decrypt a short string through the generic public-key interface.

* [`pkey/pk_sign.c`](pkey/pk_sign.c), [`pkey/pk_verify.c`](pkey/pk_verify.c): Load a PEM or DER private/public key file and use the key to sign/verify a short string.

### ECDSA and RSA signature examples

* [`pkey/ecdsa.c`](pkey/ecdsa.c): generate an ECDSA key, sign a fixed message and verify the signature.

* [`pkey/rsa_encrypt.c`](pkey/rsa_encrypt.c), [`pkey/rsa_decrypt.c`](pkey/rsa_decrypt.c): load an RSA public/private key and use it to encrypt/decrypt a short string through the low-level RSA interface.

* [`pkey/rsa_genkey.c`](pkey/rsa_genkey.c): generate an RSA key and write it to a file that can be used with the other RSA sample programs.

* [`pkey/rsa_sign.c`](pkey/rsa_sign.c), [`pkey/rsa_verify.c`](pkey/rsa_verify.c): load an RSA private/public key and use it to sign/verify a short string with the RSA PKCS#1 v1.5 algorithm.

* [`pkey/rsa_sign_pss.c`](pkey/rsa_sign_pss.c), [`pkey/rsa_verify_pss.c`](pkey/rsa_verify_pss.c): load an RSA private/public key and use it to sign/verify a short string with the RSASSA-PSS algorithm.

### Diffie-Hellman key exchange examples

* [`pkey/dh_client.c`](pkey/dh_client.c), [`pkey/dh_server.c`](pkey/dh_server.c): secure channel demonstrator (client, server). Illustrates how to set up a secure channel using RSA for authentication and Diffie-Hellman to set up a shared AES session key.

* [`pkey/ecdh_curve25519.c`](pkey/ecdh_curve25519.c): demonstration of a elliptic curve Diffie-Hellman (ECDH) key agreement.

### Bignum (`mpi`) usage examples

* [`pkey/dh_genprime.c`](pkey/dh_genprime.c): illustrates the bignum (`mpi`) interface by generating Diffie-Hellman parameters.

* [`pkey/mpi_demo.c`](pkey/mpi_demo.c): demonstrates operations on big integers.

## Random number generator (RNG) examples

* [`random/gen_entropy.c`](random/gen_entropy.c): illustrates using the default entropy sources to generate random data.  
  Note: most applications should use the entropy generator only to seed a cryptographic pseudorandom generator, as illustrated by `random/gen_random_ctr_drbg.c`.

* [`random/gen_random_ctr_drbg.c`](random/gen_random_ctr_drbg.c): illustrates using the default entropy sources to seed a pseudorandom generator, and using the resulting random generator to generate random data.

* [`random/gen_random_havege.c`](random/gen_random_havege.c): illustrates the HAVEGE entropy collector.

## SSL/TLS examples

### SSL/TLS sample applications

* [`ssl/dtls_client.c`](ssl/dtls_client.c): a simple DTLS client program which sends one datagram to the server and reads one datagram in response.

* [`ssl/dtls_server.c`](ssl/dtls_server.c): a simple DTLS server program which expects one datagram from the client and writes one datagram in response. This program supports DTLS cookies for hello verification.

* [`ssl/mini_client.c`](ssl/mini_client.c): a minimalistic SSL client which sends a short string and disconnects. This is intended more as a benchmark; for a better example of a typical TLS client, see `ssl/ssl_client1.c`.

* [`ssl/ssl_client1.c`](ssl/ssl_client1.c): a simple HTTPS client that sends a fixed request and displays the response.

* [`ssl/ssl_fork_server.c`](ssl/ssl_fork_server.c): a simple HTTPS server using one process per client to send a fixed response. This program requires a Unix/POSIX environment implementing the `fork` system call.

* [`ssl/ssl_mail_client.c`](ssl/ssl_mail_client.c): a simple SMTP-over-TLS or SMTP-STARTTLS client. This client sends an email with a fixed content.

* [`ssl/ssl_pthread_server.c`](ssl/ssl_pthread_server.c): a simple HTTPS server using one thread per client to send a fixed response. This program requires a the pthread library.

* [`ssl/ssl_server.c`](ssl/ssl_server.c): a simple HTTPS server that sends a fixed response. This server serves a single client at a time.

### SSL/TLS feature demonstrators

Note: unlike most of the other programs under the `programs/` directory, these two programs are not intended as a basis to start writing an application. They combine most of the features supported by the library, and most applications require only a few features. It is recommended to start with `ssl_client1.c` or `ssl_server.c`, and to look inside `ssl/ssl_client2.c` or `ssl/ssl_server2.c` to see how to use the specific features that your application needs.

* [`ssl/ssl_client2.c`](ssl/ssl_client2.c): an HTTPS client that sends a fixed request and displays the response, with options to select TLS protocol features and Mbed TLS library features.

* [`ssl/ssl_server2.c`](ssl/ssl_server2.c): an HTTPS server that sends a fixed response, with options to select TLS protocol features and Mbed TLS library features.

These programs have options to trigger certain behaviors (e.g. reconnection, renegotiation) so the `ssl_server2` program can be useful to test features in your TLS client and the `ssl_client2` program can be useful to test features in your TLS server.

## Test utilities

* [`test/benchmark.c`](test/benchmark.c): benchmark for cryptographic algorithms.

* [`test/selftest.c`](test/selftest.c): runs the self-test functions in all the library modules.

* [`test/ssl_cert_test.c`](test/ssl_cert_test.c): verify some X.509 certificates, and verify that each certificate matches the corresponding private key (supported for RSA keys only).

* [`test/udp_proxy.c`](test/udp_proxy.c): a UDP proxy that can inject certain failures (delay, duplicate, drop). Useful to test DTLS.

## Development utilities

* [`util/pem2der.c`](util/pem2der.c): a PEM to DER converter. Mbed TLS can read PEM files directly, but this utility can be useful to interact with other tools or with minimal Mbed TLS builds that lack PEM support.

* [`util/strerror.c`](util/strerror.c): print the error description corresponding to an integer status returned by an Mbed TLS function.

## X.509 certificate examples

* [`x509/cert_app.c`](x509/cert_app.c): connect to a TLS server and verify its certificate chain.

* [`x509/cert_req.c`](x509/cert_req.c): generate a certificate signing request (CSR) for a private key.

* [`x509/cert_write.c`](x509/cert_write.c): sign a certificate signing request, or self-sign a certificate.

* [`x509/crl_app.c`](x509/crl_app.c): load and dump a certificate revocation list (CRL).

* [`x509/req_app.c`](x509/req_app.c): load and dump a certificate signing request (CSR).

