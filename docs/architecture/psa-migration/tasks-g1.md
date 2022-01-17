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

https://github.com/ARMmbed/mbedtls/issues/5157

HMAC
----

### Variable-time HMAC in TLS record protection

https://github.com/ARMmbed/mbedtls/issues/5177

### Constant-time HMAC in TLS record protection

https://github.com/ARMmbed/mbedtls/issues/5178


Ciphers
-------

### Use PSA for all cipher operations in TLS

https://github.com/ARMmbed/mbedtls/issues/5181
https://github.com/ARMmbed/mbedtls/issues/5182
https://github.com/ARMmbed/mbedtls/issues/5203
https://github.com/ARMmbed/mbedtls/issues/5204
https://github.com/ARMmbed/mbedtls/issues/5205
https://github.com/ARMmbed/mbedtls/issues/5206

Asymmetric crypto
=================

ECDSA
-----

### Make `mbedtls_pk_sign()` use PSA for ECDSA operations

https://github.com/ARMmbed/mbedtls/issues/5274

RSA signature (and verification)
--------------------------------

### Make `mbedtls_pk_sign()` use PSA for RSA operations

https://github.com/ARMmbed/mbedtls/issues/5162

### Make `mbedtls_pk_verify()` use PSA for RSA operations

https://github.com/ARMmbed/mbedtls/issues/5159

### Make `mbedtls_pk_verify_ext()` use PSA for RSA operations

https://github.com/ARMmbed/mbedtls/issues/5333 (partial)
https://github.com/ARMmbed/mbedtls/issues/5277 (futher)

RSA en/decryption
-----------------

### Make `mbedtls_pk_encrypt()` use PSA for RSA operations


https://github.com/ARMmbed/mbedtls/issues/5161

### Make `mbedtls_pk_decrypt()` use PSA for RSA operations

https://github.com/ARMmbed/mbedtls/issues/5160

ECDH
----

Additional:
https://github.com/ARMmbed/mbedtls/issues/5291 (pre clean-up)
https://github.com/ARMmbed/mbedtls/issues/5321 (TLS 1.3)
https://github.com/ARMmbed/mbedtls/issues/5322 (post clean-up)

### Write remaining utilities for ECDH parsing/writing

(not a task on its own, part of other tasks)

### Use PSA for ECDHE in ECDHE-ECDSA and ECDHE-RSA server-side

https://github.com/ARMmbed/mbedtls/issues/5317

### Use PSA for ECDH in ECDHE-PSK (all sides and versions)

https://github.com/ARMmbed/mbedtls/issues/5318

### Use PSA for ECDH in static-ECDH key exchanges

https://github.com/ARMmbed/mbedtls/issues/5319
https://github.com/ARMmbed/mbedtls/issues/5320

FFDH
----

https://github.com/ARMmbed/mbedtls/issues/5287

EC J-PAKE
---------

https://github.com/ARMmbed/mbedtls/issues/5275
