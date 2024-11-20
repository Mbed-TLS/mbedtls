This document describes how PSA Crypto is used in the X.509 and TLS libraries
from a user's perspective.

In particular:
- X.509 and TLS libraries use PSA for cryptographic operations as much as
  possible, see "Internal changes" below;
- APIs for using keys handled by PSA Crypto, such as
  `mbedtls_pk_setup_opaque()` and `mbedtls_ssl_conf_psk_opaque()`, see
"PSA key APIs" below.

General considerations
----------------------

**Application code:** you need to call `psa_crypto_init()` before calling any
function from the SSL/TLS, X.509 or PK modules, except for the various
mbedtls_xxx_init() functions which can be called at any time.

PSA Key APIs
-------------------------

### PSA-held (opaque) keys in the PK layer

**API function:** `mbedtls_pk_setup_opaque()` - can be used to wrap a PSA key
pair into a PK context. The key can be used for private-key operations and its
public part can be exported.

**Benefits:** isolation of long-term secrets, use of PSA Crypto drivers.

**Limitations:** please refer to the documentation of `mbedtls_pk_setup_opaque()`
for a full list of supported operations and limitations.

**Use in X.509 and TLS:** opt-in. The application needs to construct the PK context
using the new API in order to get the benefits; it can then pass the
resulting context to the following existing APIs:

- `mbedtls_ssl_conf_own_cert()` or `mbedtls_ssl_set_hs_own_cert()` to use the
  key together with a certificate for certificate-based key exchanges;
- `mbedtls_x509write_csr_set_key()` to generate a CSR (certificate signature
  request);
- `mbedtls_x509write_crt_set_issuer_key()` to generate a certificate.

### PSA-held (opaque) keys for TLS pre-shared keys (PSK)

**API functions:** `mbedtls_ssl_conf_psk_opaque()` and
`mbedtls_ssl_set_hs_psk_opaque()`. Call one of these from an application to
register a PSA key for use with a PSK key exchange.

**Benefits:** isolation of long-term secrets.

**Limitations:** none.

**Use in TLS:** opt-in. The application needs to register the key using one of
the above APIs to get the benefits.

### PSA-held (opaque) keys for TLS 1.2 EC J-PAKE key exchange

**API function:** `mbedtls_ssl_set_hs_ecjpake_password_opaque()`.  Call this
function from an application to register a PSA key for use with the TLS 1.2 EC
J-PAKE key exchange.

**Benefits:** isolation of long-term secrets.

**Limitations:** none.

**Use in TLS:** opt-in. The application needs to register the key using one of
the above APIs to get the benefits.

### PSA-based operations in the Cipher layer

There is an API function `mbedtls_cipher_setup_psa()` to set up a context
that will call PSA to store the key and perform the operations.

This function only worked for a small number of ciphers. It is now deprecated
and it is recommended to use `psa_cipher_xxx()` or `psa_aead_xxx()` functions
directly instead.

**Warning:** This function will be removed in a future version of Mbed TLS. If
you are using it and would like us to keep it, please let us know about your
use case.

Internal uses
----------------

All of these internal uses are relying on PSA Crypto.

### TLS: most crypto operations based on PSA

Current exceptions:

- Finite-field (non-EC) Diffie-Hellman (used in key exchanges: DHE-RSA,
  DHE-PSK).
- Restartable operations when `MBEDTLS_ECP_RESTARTABLE` is also enabled (see
  the documentation of that option).

Other than the above exceptions, all crypto operations are based on PSA.

### X.509: most crypto operations based on PSA

Current exceptions:

- Restartable operations when `MBEDTLS_ECP_RESTARTABLE` is also enabled (see
  the documentation of that option).

Other than the above exception, all crypto operations are based on PSA.

### PK layer: most crypto operations based on PSA

Current exceptions:

- Verification of RSA-PSS signatures with an MGF hash that's different from
  the message hash.
- Restartable operations when `MBEDTLS_ECP_RESTARTABLE` is also enabled (see
  the documentation of that option).

Other than the above exceptions, all crypto operations are based on PSA.

