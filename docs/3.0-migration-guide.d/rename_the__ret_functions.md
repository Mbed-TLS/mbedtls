Rename mbedtls_*_ret() cryptography functions whose deprecated variants
have been removed
-----------------

This change affects users who were using the `mbedtls_*_ret()` cryptography
functions.

Those functions were created based on now-deprecated functions according to a
requirement that a function needs to return a value. This change brings back the
original names of those functions. The renamed functions are:

| name before this change      | after the change         |
|------------------------------|--------------------------|
| mbedtls_ctr_drbg_update_ret  | mbedtls_ctr_drbg_update  |
| mbedtls_hmac_drbg_update_ret | mbedtls_hmac_drbg_update |
| mbedtls_md5_starts_ret       | mbedtls_md5_starts       |
| mbedtls_md5_update_ret       | mbedtls_md5_update       |
| mbedtls_md5_finish_ret       | mbedtls_md5_finish       |
| mbedtls_md5_ret              | mbedtls_md5              |
| mbedtls_ripemd160_starts_ret | mbedtls_ripemd160_starts |
| mbedtls_ripemd160_update_ret | mbedtls_ripemd160_update |
| mbedtls_ripemd160_finish_ret | mbedtls_ripemd160_finish |
| mbedtls_ripemd160_ret        | mbedtls_ripemd160        |
| mbedtls_sha1_starts_ret      | mbedtls_sha1_starts      |
| mbedtls_sha1_update_ret      | mbedtls_sha1_update      |
| mbedtls_sha1_finish_ret      | mbedtls_sha1_finish      |
| mbedtls_sha1_ret             | mbedtls_sha1             |
| mbedtls_sha256_starts_ret    | mbedtls_sha256_starts    |
| mbedtls_sha256_update_ret    | mbedtls_sha256_update    |
| mbedtls_sha256_finish_ret    | mbedtls_sha256_finish    |
| mbedtls_sha256_ret           | mbedtls_sha256           |
| mbedtls_sha512_starts_ret    | mbedtls_sha512_starts    |
| mbedtls_sha512_update_ret    | mbedtls_sha512_update    |
| mbedtls_sha512_finish_ret    | mbedtls_sha512_finish    |
| mbedtls_sha512_ret           | mbedtls_sha512           |

To migrate to the this change the user can keep the `*_ret` names in their code
and include the `compat_2.x.h` header file which holds macros with proper
renaming or to rename those function in their code according to the list from
mentioned header file.



