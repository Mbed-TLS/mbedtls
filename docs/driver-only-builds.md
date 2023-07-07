This document explains how to create builds of Mbed TLS where some
cryptographic mechanisms are provided only by PSA drivers (that is, no
built-in implementation of those algorithms), from a user's perspective.

This is useful to save code size for people who are using either a hardware
accelerator, or an alternative software implementation that's more
aggressively optimized for code size than the default one in Mbed TLS.

General considerations
----------------------

This document assumes that you already have a working driver.
Otherwise, please see the [PSA driver example and
guide](psa-driver-example-and-guide.md) for information on writing a
driver.

In order to have some mechanism provided only by a driver, you'll want
the following compile-time configuration options enabled:
- `MBEDTLS_PSA_CRYPTO_C` (enabled by default) - this enables PSA Crypto.
- `MBEDTLS_USE_PSA_CRYPTO` (disabled by default) - this makes PK, X.509 and
  TLS use PSA Crypto. You need to enable this if you're using PK, X.509 or TLS
and want them to have access to the algorithms provided by your driver. (See
[the dedicated document](use-psa-crypto.md) for details.)
- `MBEDTLS_PSA_CRYPTO_CONFIG` (disabled by default) - this enables
  configuration of cryptographic algorithms using `PSA_WANT` macros in
`include/psa/crypto_config.h`. See [Conditional inclusion of cryptographic
mechanism through the PSA API in Mbed
TLS](proposed/psa-conditional-inclusion-c.md) for details.

In addition, for each mechanism you want provided only by your driver:
- Define the corresponding `PSA_WANT` macro in `psa/crypto_config.h` - this
  means the algorithm will be available in the PSA Crypto API.
- Define the corresponding `MBEDTLS_PSA_ACCEL` in your build (could be in
  `psa/crypto_config.h` or your compiler's command line). This informs the PSA
code that an accelerator is available for this.
- Undefine / comment out the corresponding `MBEDTLS_xxx_C` macro in
  `mbedtls/mbedtls_config.h`. This ensures the built-in implementation is not
included in the build.

For example, if you want SHA-256 to be provided only by a driver, you'll want
`PSA_WANT_ALG_SHA_256` and `MBEDTLS_PSA_ACCEL_SHA_256` defined, and
`MBEDTLS_SHA256_C` undefined.

In addition to these compile-time considerations, at runtime you'll need to
make sure you call `psa_crypto_init()` before any function that uses the
mechanisms provided only by drivers. Note that this is already a requirement
for any use of the PSA Crypto API, as well as for use of the PK, X.509 and TLS
modules when `MBEDTLS_USE_PSA_CRYPTO` is enabled, so in most cases your
application will already be doing this.

Mechanisms covered
------------------

For now, only two families are supported:
- hashes: SHA-3, SHA-2, SHA-1, MD5, etc.
- elliptic-curve cryptography (ECC): ECDH, ECDSA, EC J-PAKE, ECC key types.

Supported means that when those are provided only by drivers, everything
(including PK, X.509 and TLS if `MBEDTLS_USE_PSA_CRYPTO` is enabled) should
work in the same way as if the mechanisms where built-in, except as documented
in the "Limitations" sub-sections of the sections dedicated to each family
below.

In the near future (end of 2023), we are planning to also add support for
ciphers (AES) and AEADs (GCM, CCM, ChachaPoly).

Currently (mid-2023) we don't have plans to extend this to RSA of FFDH. If
you're interested in driver-only support for those, please let us know.

Hashes
------

TODO

Elliptic-curve cryptography (ECC)
---------------------------------

TODO
