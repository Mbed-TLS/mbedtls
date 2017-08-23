README for Thales e-Security fork of mbed TLS
=============================================

This is a fork of the [ARMmbed/mbedtls](https://github.com/ARMmbed/mbedtls)
project that adds support for [New Hope key
exchange](https://eprint.iacr.org/2015/1092),
[Salsa20](https://cr.yp.to/salsa20.html) and
[ChaCha8](https://cr.yp.to/chacha.html).

New Hope key exchange is believed to be resistant against the attacks introduced
by quantum algorithms.

The following experimental ciphersuites are defined in this fork:

- TLS-NEWHOPE-ECDSA-WITH-RC4-128-SHA (0xC0B0)
- TLS-NEWHOPE-ECDSA-WITH-AES-128-CBC-SHA (0xC0B1)
- TLS-NEWHOPE-ECDSA-WITH-AES-256-CBC-SHA (0xC0B2)
- TLS-NEWHOPE-ECDSA-WITH-AES-128-CBC-SHA256 (0xC0B3)
- TLS-NEWHOPE-ECDSA-WITH-AES-128-GCM-SHA256 (0xC0B4)
- TLS-NEWHOPE-ECDSA-WITH-AES-256-CBC-SHA384 (0xC0B5)
- TLS-NEWHOPE-ECDSA-WITH-AES-256-GCM-SHA384 (0xC0B6)
- TLS-NEWHOPE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256 (0xC0B7)
- TLS-NEWHOPE-ECDSA-WITH-CAMELLIA-256-CBC-SHA384 (0xC0B8)
- TLS-NEWHOPE-ECDSA-WITH-CAMELLIA-128-GCM-SHA256 (0xC0B9)
- TLS-NEWHOPE-ECDSA-WITH-CAMELLIA-256-GCM-SHA384 (0xC0BA)
- TLS-NEWHOPE-ECDSA-WITH-3DES-EDE-CBC-SHA (0xC0BB)
- TLS-NEWHOPE-ECDSA-WITH-SALSA20-256-SHA (0xC0BC)
- TLS-NEWHOPE-ECDSA-WITH-CHACHA8-256-SHA (0xC0BD)

The library is configured (in `ssl_ciphersuites.c`) to prefer one of the
following three suites, in descending order:

- TLS-NEWHOPE-ECDSA-WITH-SALSA20-256-SHA
- TLS-NEWHOPE-ECDSA-WITH-CHACHA8-256-SHA
- TLS-NEWHOPE-ECDSA-WITH-RC4-128-SHA

Interoperability
----------------

This fork will interoperate with libraries that do not support these
ciphersuites. In such cases, the parties will negotiate to use the strongest
mutually supported ciphersuite.

Important note: there are no [IANA
ciphersuites](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)
yet defined for New Hope, so the constants used in this fork are taken from the
unassigned pool. This means its unlikely this fork will play nicely with other
implementations that have chosen different constant values.

Configuration/Compiling/etc.
----------------------------

Please refer to the [ARMmbed/mbedtls](https://github.com/ARMmbed/mbedtls)
project documentation for advice on building the library.
