This document describes the compile-time configuration option
`MBEDTLS_USE_PSA_CRYPTO` from a user's perspective.

This option makes the X.509 and TLS library use PSA for cryptographic
operations, and enables new APIs for using keys handled by PSA Crypto.

General considerations
----------------------

**Application code:** when this option is enabled, you need to call
`psa_crypto_init()` before calling any function from the SSL/TLS, X.509 or PK
module.

**Scope:** `MBEDTLS_USE_PSA_CRYPTO` has no effect on the most of the TLS 1.3
code, which always uses PSA crypto. The parts of the TLS 1.3 code that will
use PSA Crypto or not depending on the value of this option are:
- record protection;
- running handshake hash;
- asymmetric signature verification & generation;
- X.509 certificate chain verification.
You need to enable `MBEDTLS_USE_PSA_CRYPTO` if you want TLS 1.3 to use PSA
everywhere.

New APIs / API extensions
-------------------------

### PSA-held (opaque) keys in the PK layer

**New API function:** `mbedtls_pk_setup_opaque()` - can be used to
wrap a PSA key pair into a PK context. The key can be used for private-key
operations and its public part can be exported.

**Benefits:** isolation of long-term secrets, use of PSA Crypto drivers.

**Limitations:** can only wrap a key pair, can only use it for private key
operations. (That is, signature generation, and for RSA decryption too.)
Note: for ECDSA, currently this uses randomized ECDSA while Mbed TLS uses
deterministic ECDSA by default. The following operations are not supported
with a context set this way, while they would be available with a normal
context: `mbedtls_pk_check_pair()`, `mbedtls_pk_debug()`, all public key
operations.

**Use in X.509 and TLS:** opt-in. The application needs to construct the PK context
using the new API in order to get the benefits; it can then pass the
resulting context to the following existing APIs:

- `mbedtls_ssl_conf_own_cert()` or `mbedtls_ssl_set_hs_own_cert()` to use the
  key together with a certificate for certificate-based key exchanges;
- `mbedtls_x509write_csr_set_key()` to generate a CSR (certificate signature
  request);
- `mbedtls_x509write_crt_set_issuer_key()` to generate a certificate.

### PSA-held (opaque) keys for TLS pre-shared keys (PSK)

**New API functions:** `mbedtls_ssl_conf_psk_opaque()` and
`mbedtls_ssl_set_hs_psk_opaque()`. Call one of these from an application to
register a PSA key for use with a PSK key exchange.

**Benefits:** isolation of long-term secrets.

**Limitations:** none.

**Use in TLS:** opt-in. The application needs to register the key using one of
the new APIs to get the benefits.

### PSA-based operations in the Cipher layer

There is a new API function `mbedtls_cipher_setup_psa()` to set up a context
that will call PSA to store the key and perform the operations.

This function only worked for a small number of ciphers. It is now deprecated
and it is recommended to use `psa_cipher_xxx()` or `psa_aead_xxx()` functions
directly instead.

**Warning:** This function will be removed in a future version of Mbed TLS. If
you are using it and would like us to keep it, please let us know about your
use case.

Internal changes
----------------

All of these internal changes are active as soon as `MBEDTLS_USE_PSA_CRYPTO`
is enabled, no change required on the application side.

### TLS: most crypto operations based on PSA

Current exceptions:

- Finite-field (non-EC) Diffie-Hellman (used in key exchanges: DHE-RSA,
  DHE-PSK).
- Restartable operations when `MBEDTLS_ECP_RESTARTABLE` is also enabled (see
  the documentation of that option).

Other than the above exceptions, all crypto operations are based on PSA when
`MBEDTLS_USE_PSA_CRYPTO` is enabled.

### X.509: most crypto operations based on PSA

Current exceptions:

- Restartable operations when `MBEDTLS_ECP_RESTARTABLE` is also enabled (see
  the documentation of that option).

Other than the above exception, all crypto operations are based on PSA when
`MBEDTLS_USE_PSA_CRYPTO` is enabled.

### PK layer: most crypto operations based on PSA

Current exceptions:

- Verification of RSA-PSS signatures with an MGF hash that's different from
  the message hash.
- Restartable operations when `MBEDTLS_ECP_RESTARTABLE` is also enabled (see
  the documentation of that option).

Other than the above exceptions, all crypto operations are based on PSA when
`MBEDTLS_USE_PSA_CRYPTO` is enabled.

