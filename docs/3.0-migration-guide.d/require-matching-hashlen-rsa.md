Signature functions now require the hash length to match the expected value
---------------------------------------------------------------------------

This affects users of the PK API as well as users of the low-level API in the RSA module. Users of the PSA API or of the ECDSA module are unaffected.

All the functions in the RSA module that accept a `hashlen` parameter used to
ignore it unless the `md_alg` parameter was `MBEDTLS_MD_NONE`, indicating raw
data was signed. The `hashlen` parameter is now always the size that is read
from the `hash` input buffer. This length must be equal to the output size of
the hash algorithm used when signing a hash. (The requirements when signing
raw data are unchanged.) This affects the following functions:

* `mbedtls_rsa_pkcs1_sign`, `mbedtls_rsa_pkcs1_verify`
* `mbedtls_rsa_rsassa_pkcs1_v15_sign`, `mbedtls_rsa_rsassa_pkcs1_v15_verify`
* `mbedtls_rsa_rsassa_pss_sign`, `mbedtls_rsa_rsassa_pss_verify`
* `mbedtls_rsa_rsassa_pss_sign_ext`, `mbedtls_rsa_rsassa_pss_verify_ext`

The signature functions in the PK module no longer accept 0 as the `hash_len` parameter. The `hash_len` parameter is now always the size that is read from the `hash` input buffer. This affects the following functions:

* `mbedtls_pk_sign`, `mbedtls_pk_verify`
* `mbedtls_pk_sign_restartable`, `mbedtls_pk_verify_restartable`
* `mbedtls_pk_verify_ext`

The migration path is to pass the correct value to those functions.
