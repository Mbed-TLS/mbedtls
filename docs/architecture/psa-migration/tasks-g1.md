This document is temporary; it lists tasks to achieve G1 as described in
`strategy.md` while the strategy is being reviewed - once that's done,
corresponding github issues will be created and this document removed.

For all of the tasks here, no specific testing is expected to be required,
beyond passing the existing tests in a build with `MBEDTLS_USE_PSA_ENABLED`,
see `testing.md`.

Symmetric crypto
================

Hashes
------

### Use `psa_hash` in all of X.509

Conditionally on `MBEDTLS_USE_PSA_CRYPTO`, replace all remaining calls to
`mbedtls_md()` or `mbedtls_sha1_ret()` by calls `psa_hash` functions, namely:
- replace `mbedtls_md()` in `x509_crt_verifycrl()` in `x509_crt.c`
- replace `mbedtls_md()` in `mbedtls_x509write_crt_der()` in `x509write_crt.c`
- replace `mbedtls_sha1_ret() in
  `mbedtls_x509write_crt_set_subject_key_identifier()` in `x509write_crt.c`
- replace `mbedtls_sha1_ret() in
  `mbedtls_x509write_crt_set_authority_key_identifier()` in `x509write_crt.c`
- already done in `x509_crt_check_signature()` in `x509_crt.c`, but might
  want to replace multi-part with single-part.
- already done in `mbedtls_x509write_csr_der_internal()` in
  `x509write_csr.c`, but might want to replace multi-part with single-part.

HMAC
----

### Variable-time HMAC in TLS record protection

- This is about the calls to `mbedtls_md_hmac_xxx()` in
`mbedtls_ssl_decrypt_buf()` and `mbedtls_ssl_encrypt_buf()`, but excludes the
call in `mbedtls_ssl_cf_hmad()` (which it its own task).
- Might need to change the `transform` structure to hold a PSA context instead
  of an MD context. Note: might keep the MD context in parallel until the
constant-time part is done as well.

TODO: study this better so it can be estimated.

### Constant-time HMAC in TLS record protection

This is `mbedtls_ssl_cf_hmac()`. The PSA code might look a bit different as
we'll probably need to store the HMAC key somewhere and compute the ipad/opad
explicitly instead of using (the internals of) the MD layers for that.

TODO: study this better so it can be estimated.

Ciphers
-------

### Use PSA for all cipher operations in TLS

- extend existing `mbedtls_cipher_setup_psa()` and related code to support
  other ciphers than AES that can be used in TLS: ARIA (depends on #4959),
Camellia, ChachaPoly.
- extend unit-testing in `test_suite_cipher` to test those new ciphers as
  AES-based cipher are already tested
- remove the fallback mechanism in all places where `cipher_setup_psa()` is
  called from TLS code
- expand use of `run_test_psa()` in `ssl-opt.sh`

Asymmetric crypto
=================

ECDSA
-----

### Make `mbedtls_pk_sign()` use PSA for ECDSA operations

- This is already done with `PK_OPAQUE` contexts, but this task is about doing
it for regulard `ECKEY`/`ECDSA` contexts.
- May share some code (transcoding) with the exist support for `PK_OPAQUE`
  contexts

RSA signature (and verification)
--------------------------------

### Make `mbedtls_pk_sign()` use PSA for RSA operations

- with regular `PK_RSA` context
- only PKCS#1 v1.5 for this task
- similar to what's done for ECDSA, except no need for transcoding (I think)

### Make `mbedtls_pk_verify()` use PSA for RSA operations

- with regular `PK_RSA` context
- only PKCS#1 v1.5 for this task
- similar to what's done for ECDSA, except no need for transcoding (I think)

### Make `mbedtls_pk_verify_ext()` use PSA for RSA operations

- with regular `PK_RSA` context
- this is for RSA-PSS
- similar to what's done for ECDSA, except no need for transcoding (I think)
- acceptable to enforce that all hashes are equal in the parameters (as
  imposed by the PSA API) and reject the signature otherwise
- then need to check if all X.509 tests still pass, and if some don't, make
  them depend on `!MBEDTLS_USE_PSA_CRYPTO`

RISK: see `psa-limitations.md`

RSA en/decryption
-----------------

### Make `mbedtls_pk_encrypt()` use PSA for RSA operations

- with regular `PK_RSA` context

### Make `mbedtls_pk_decrypt()` use PSA for RSA operations

- with regular `PK_RSA` context

ECDH
----

### Write remaining utilities for ECDH parsing/writing

- PSA only provides an API for the operation, need to parse and write
  parameters and public keys to/from grp ID + string of bytes
- need to complete what was done in 4a.1
- testing: positive: extract known-good inputs/outputs from actual handshakes?
- testing: negative: manipulate known-good input to make it invalid

Note: future task in this section depend on this one, but not on each other.

### Use PSA for ECDHE in ECDHE-ECDSA and ECDHE-RSA server-side

- may need to separate branches from other ECDHE-based key exchanges
- only server-side (client-side is already done, can be used for inspiration)

### Use PSA for ECDH in ECDHE-PSK (all sides and versions)

- only with non-opaque PSK (support for opaque PSK here is part of G2)

### Use PSA for ECDH in static-ECDH key exchanges

- may require additional utility functions to load from cert to PSA

FFDH
----

This may be hard, see `psa-limitations.md`

EC J-PAKE
---------

Use PSA for all EC J-PAKE operations in TLS (both sides).
(TODO: consider how this could be split.)
