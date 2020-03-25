# Mbed Crypto change history

## Unreleased changes

### Interface changes

* In the PSA API, forbid zero-length keys. To pass a zero-length input to a key derivation function, use a buffer instead (this is now always possible).
* Rename `psa_asymmetric_sign()` to `psa_sign_hash()` and `psa_asymmetric_verify()` to `psa_verify_hash()`.

### Default behavior changes

* The initial seeding of a CTR\_DRBG instance makes a second call to the entropy function to obtain entropy for a nonce if the entropy size is less than 3/2 times the key size. In case you want to disable the extra call to grab entropy, you can call `mbedtls_ctr_drbg_set_nonce_len()` to force the nonce length to 0.

### New features

* Key derivation inputs in the PSA API can now either come from a key object or from a buffer regardless of the step type.
* The CTR_DRBG module can grab a nonce from the entropy source during the initial seeding. The default nonce length is chosen based on the key size to achieve the security strength defined by NIST SP 800-90A. You can change it with `mbedtls_ctr_drbg_set_nonce_len()`.
* Add ENUMERATED tag support to the ASN.1 module. Contributed by msopiha-linaro in #307.

### Security

* Enforce that `mbedtls_entropy_func()` gathers a total of `MBEDTLS_ENTROPY_BLOCK_SIZE` bytes or more from strong sources. In the default configuration, on a platform with a single entropy source, the entropy module formerly only grabbed 32 bytes, which is good enough for security if the source is genuinely strong, but less than the expected 64 bytes (size of the entropy accumulator).

### Bug fixes

* Fix a buffer overflow in the PSA HMAC code when using a long key with an unsupported algorithm. Fixes #254.
* Fix `mbedtls_asn1_get_int` to support any number of leading zeros. Credit to OSS-Fuzz for finding a bug in an intermediate version of the fix.
* Fix `mbedtls_asn1_get_bitstring_null` to correctly parse bitstrings of at most 2 bytes.
* `mbedtls_ctr_drbg_set_entropy_len()` and `mbedtls_hmac_drbg_set_entropy_len()` now work if you call them before `mbedtls_ctr_drbg_seed()` or `mbedtls_hmac_drbg_seed()`.
* Fix some false-positive uninitialized variable warnings. Fix contributed by apple-ihack-geek in ARMmbed/mbedtls#2663.

### Performance improvements

* Remove a useless call to `mbedtls_ecp_group_free()`. Contributed by Alexander Krizhanovsky in #210.
* Speed up PBKDF2 by caching the digest calculation. Contributed by Jack Lloyd and Fortanix Inc in #277.
* Small performance improvement of `mbedtls_mpi_div_mpi()`. Contributed by Alexander Krizhanovsky in #308.

### Other changes

* Remove the technical possibility to define custom `mbedtls_md_info` structures, which was exposed only in an internal header.
* `psa_close_key(0)` and `psa_destroy_key(0)` now succeed (doing nothing, as before).
* Variables containing error codes are now initialized to an error code rather than success, so that coding mistakes or memory corruption tends to cause functions to return this error code rather than a success. There are no known instances where this changes the behavior of the library: this is merely a robustness improvement. #323

## Mbed Crypto 2.0.0
