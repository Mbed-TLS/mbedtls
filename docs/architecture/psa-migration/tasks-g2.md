This document is temporary; it lists tasks to achieve G2 as described in
`strategy.md` while the strategy is being reviewed - once that's done,
corresponding github issues will be created and this document removed.

For all of the tasks here, specific testing (integration and unit test depending
on the task) is required, see `testing.md`.

RSA Signature operations
========================

In PK
-----

### Modify existing `PK_OPAQUE` type to allow for RSA keys

- the following must work and be tested: `mbedtls_pk_get_type()`,
  `mbedtls_pk_get_name()`, `mbedtls_pk_get_bitlen()`, `mbedtls_pk_get_len()`,
`mbedtls_pk_can_do()`.
- most likely adapt `pk_psa_genkey()` in `test_suite_pk.function`.
- all other function (sign, verify, encrypt, decrypt, check pair, debug) will
  return `MBEDTLS_ERR_PK_TYPE_MISMATCH` and this will be tested too.

### Modify `mbedtls_pk_wrap_as_opaque()` to work with RSA.

- OK to have policy hardcoded on signing with PKCS1v1.5, or allow more if
  available at this time

### Modify `mbedtls_pk_write_pubkey_der()` to work with RSA-opaque.

- OK to just test that a generated key (with `pk_psa_genkey()`) can be
  written, without checking for correctness of the result - this will be
tested as part of another task

### Make `mbedtls_pk_sign()` work with RSA-opaque.

- testing may extend `pk_psa_sign()` in `test_suite_pk_function` by adding
  selector for ECDSA/RSA.

In X.509
--------

### Test using RSA-opaque for CSR generation

- similar to what's already done with ECDSA-opaque

### Test using opaque keys for Certificate generation

- similar to what's done with testing CSR generation
- should test both RSA and ECDSA as ECDSA is not tested yet
- might require slight code adaptations, even if unlikely


In TLS
------

### Test using RSA-opaque for TLS client auth

- similar to what's already done with ECDSA-opaque

### Test using RSA-opaque for TLS server auth

- similar to what's already done with ECDSA-opaque
- key exchanges: ECDHE-RSA and DHE-RSA

RSA decrypt
===========

### Extend `PK_OPAQUE` to allow RSA decryption (PKCS1 v1.5)

### Test using that in TLS for RSA and RSA-PSK key exchange.

Support opaque PSKs for "mixed-PSK" key exchanges
=================================================

See `PSA-limitations.md`.

Possible split:
- one task to extend PSA (see `PSA-limitations.md`)
- then one task per handshake: DHE-PSK, ECDHE-PSK, RSA-PSK (with tests for
  each)
