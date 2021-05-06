Deprecated functions were removed from AES
------------------------------------------

The functions `mbedtls_aes_encrypt()` and `mbedtls_aes_decrypt()` were
removed.

If you're simply using the AES module, you should be calling the higher-level
functions `mbedtls_aes_crypt_xxx()`.

If you're providing an alternative implementation using
`MBEDTLS_AES_ENCRYPT_ALT` or `MBEDTLS_AES_DECRYPT_ALT`, you should be
replacing the removed functions with `mbedtls_internal_aes_encrypt()` and
`mbedtls_internal_aes_decrypt()` respectively.

Deprecated functions were removed from bignum
---------------------------------------------

The function `mbedtls_mpi_is_prime()` was removed. Please use
`mbedtls_mpi_is_prime_ext()` instead which additionally allows specifying the
number of Miller-Rabin rounds.

Deprecated functions were removed from cipher
---------------------------------------------

The functions `mbedtls_cipher_auth_encrypt()` and
`mbedtls_cipher_auth_decrypt()` were removed. They were superseded by
`mbedtls_cipher_auth_encrypt_ext()` and `mbedtls_cipher_auth_decrypt_ext()`
respectively which additionally support key wrapping algorithms such as
NIST_KW.

Deprecated functions were removed from DRBGs
--------------------------------------------

The functions `mbedtls_ctr_drbg_update()` and `mbedtls_hmac_drbg_update()`
were removed. They were superseded by `mbedtls_ctr_drbg_update_ret()` and
`mbedtls_hmac_drbg_update_ret()` respectively.

Deprecated functions were removed from ECDSA
--------------------------------------------

The functions `mbedtls_ecdsa_write_signature_det()` and
`mbedtls_ecdsa_sign_det()` were removed. They were superseded by
`mbedtls_ecdsa_write_signature()` and `mbedtls_ecdsa_sign_det_ext()`
respectively.

Deprecated functions were removed from SSL
------------------------------------------

The function `mbedtls_ssl_conf_dh_param()` was removed. Please use
`mbedtls_ssl_conf_dh_param_bin()` or `mbedtls_ssl_conf_dh_param_ctx()` instead.

The function `mbedtls_ssl_get_max_frag_len()` was removed. Please use
`mbedtls_ssl_get_output_max_frag_len()` instead.

Deprecated hex-encoded primes were removed from DHM
---------------------------------------------------

The macros `MBEDTLS_DHM_RFC5114_MODP_2048_P`, `MBEDTLS_DHM_RFC5114_MODP_2048_G`,
`MBEDTLS_DHM_RFC3526_MODP_2048_P`, `MBEDTLS_DHM_RFC3526_MODP_2048_G`,
`MBEDTLS_DHM_RFC3526_MODP_3072_P`, `MBEDTLS_DHM_RFC3526_MODP_3072_G`,
`MBEDTLS_DHM_RFC3526_MODP_4096_P `and `MBEDTLS_DHM_RFC3526_MODP_4096_G` were
removed. The primes from RFC 5114 are deprecated because their derivation is not
documented and therefore their usage constitutes a security risk; they are fully
removed from the library. Please use parameters from RFC3526 (still in the
library, only in binary form) or RFC 7919 (also available in the library) or
other trusted sources instead.

Deprecated net.h file was removed
---------------------------------

The file `include/mbedtls/net.h` was removed because its only function was to
include `mbedtls/net_sockets.h` which now should be included directly.
