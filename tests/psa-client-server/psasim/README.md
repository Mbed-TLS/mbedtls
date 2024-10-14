# psasim

Psasim is part of the Mbed TLS test system and it provides a way to test
client/server separation for PSA crypto APIs. This is also known as "pure crypto
client" support.

In this scenario the client is built with `MBEDTLS_PSA_CRYPTO_CLIENT && !MBEDTLS_PSA_CRYPTO_C`
so that it does not embed any PSA crypto implementation. These implementations are
instead in the server which is built with `MBEDTLS_PSA_CRYPTO_C`. Therefore
every time the client needs to perform some PSA crypto operation, it communicates
with the server in order to get the proper support for that operation. Psasim
is the one that implements such communication:

* provides entry points for all PSA crypto APIs on the client and server sides;
* serializes/deserializes all the data passed as parameters to PSA crypto APIs on both sides;
* implements the physical low-level communication between the client and the server.

Based on performance testing, we decided to use Linux's shared memory as the
medium for such low-level communication.

## Limitations/disclaimers

This tool is partially inspired by the PSA Firmware Framework (PSA-FF), but
it not completely compliant to it.

Albeit psasim implements the client/server separaton, it only allows one single
client and one single server at the time. So far no multiple instances of any
of the two is supported.

Please note that the code in this directory is maintained by the Mbed TLS / PSA Crypto
project solely for the purpose of testing the client/service separation.
We do not recommend using this code for any other purpose.

## How to test

Since psasim implements only the communnication part between the client and
the server, it cannot not be built as standalone, but it must be part
of some executable (like the `crypto`, `x509` and `tls` libraries, for example).
The following test components make use of it in order to validate che client/server
separation:

* component_test_psasim: run some basic tests in order to check if psasim
  communication works correctly.

* component_test_suite_with_psasim: run almost all the standard test suites (with the
  exception of `test_suite_constant_time_hmac`, `test_suite_lmots`, `test_suite_lms` -
  because they are too much time consuming) to extensively validate the crypto
  client support.
