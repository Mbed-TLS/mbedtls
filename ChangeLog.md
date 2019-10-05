# Mbed Crypto change history

## Unreleased changes

### Interface changes

* In the PSA API, forbid zero-length keys. To pass a zero-length input to a key derivation function, use a buffer instead (this is now always possible).

### New features

* Key derivation inputs in the PSA API can now either come from a key object or from a buffer regardless of the step type.

### Bug fixes

* Fix a buffer overflow in the PSA HMAC code when using a long key with an unsupported algorithm. Fixes #254.
* Fix `mbedtls_asn1_get_int` to support any number of leading zeros.
* Fix `mbedtls_asn1_get_bitstring_null` to correctly parse bitstrings of at most 2 bytes.

### Performance improvements

* Remove a useless call to mbedtls_ecp_group_free(). Contributed by Alexander Krizhanovsky in #210.
* Speed up PBKDF2 by caching the digest calculation. Contributed by Jack Lloyd and Fortanix Inc in #277.

### Other changes

* Remove the technical possibility to define custom md_info structures, which was exposed only in an internal header.

## Mbed Crypto 2.0.0
