Dependencies of the TLS library on the Crypto library
=====================================================

This document is part of the technical study on how to port Mbed TLS to PSA
Crypto. It describes the dependencies of libmbedtls.a on libmbedcrypto.a.

More precisely, it describes what functions from libmbedcrypto.a are called
from libmbedtls.a - other forms of dependencies such as using static inline
functions or types, accessing private struct members, etc., are not listed.

It is based on Mbed TLS 3.0, excluding experimental support for TLS 1.3, and
also excluding support for restartble ECP operations.

Non-Crypto dependencies
-----------------------

The TLS library has a number of dependencies on libmbedcrypto.a that are not
cryptographic, hence are unlikely to be covered by the PSA Crypto API.

These involve the following modules:

- threading
- platform

It also depends on the X.509 library, which is excluded from further analysis
as the focus here is on dependencies on libmbedcrypto.a.

Crypto dependencies (high-level)
--------------------------------

The TLS library depends on the following cryptographic modules:

- cipher
- dhm
- ecdh
- ecjpake
- ecp
- md
- mpi
- pk
- sha256
- sha512

More specifically, calls are made to the following API functions:

```
mbedtls_cipher_auth_decrypt_ext
mbedtls_cipher_auth_encrypt_ext
mbedtls_cipher_crypt
mbedtls_cipher_free
mbedtls_cipher_info_from_type
mbedtls_cipher_init
mbedtls_cipher_set_padding_mode
mbedtls_cipher_setkey
mbedtls_cipher_setup

mbedtls_dhm_calc_secret
mbedtls_dhm_free
mbedtls_dhm_get_bitlen
mbedtls_dhm_get_len
mbedtls_dhm_get_value
mbedtls_dhm_init
mbedtls_dhm_make_params
mbedtls_dhm_make_public
mbedtls_dhm_read_params
mbedtls_dhm_read_public
mbedtls_dhm_set_group

mbedtls_ecdh_calc_secret
mbedtls_ecdh_free
mbedtls_ecdh_get_params
mbedtls_ecdh_init
mbedtls_ecdh_make_params
mbedtls_ecdh_make_public
mbedtls_ecdh_read_params
mbedtls_ecdh_read_public
mbedtls_ecdh_setup

mbedtls_ecjpake_check
mbedtls_ecjpake_derive_secret
mbedtls_ecjpake_free
mbedtls_ecjpake_init
mbedtls_ecjpake_read_round_one
mbedtls_ecjpake_read_round_two
mbedtls_ecjpake_set_point_format
mbedtls_ecjpake_setup
mbedtls_ecjpake_write_round_one
mbedtls_ecjpake_write_round_two

mbedtls_ecp_curve_info_from_grp_id
mbedtls_ecp_curve_info_from_tls_id

mbedtls_md_clone
mbedtls_md_finish
mbedtls_md_free
mbedtls_md_get_size
mbedtls_md_get_type
mbedtls_md_hmac_finish
mbedtls_md_hmac_reset
mbedtls_md_hmac_starts
mbedtls_md_hmac_update
mbedtls_md_info_from_type
mbedtls_md_init
mbedtls_md_setup
mbedtls_md_starts
mbedtls_md_update

mbedtls_mpi_bitlen
mbedtls_mpi_free
mbedtls_mpi_read_binary

mbedtls_pk_can_do
mbedtls_pk_debug
mbedtls_pk_decrypt
mbedtls_pk_encrypt
mbedtls_pk_get_bitlen
mbedtls_pk_sign
mbedtls_pk_sign_restartable
mbedtls_pk_verify
mbedtls_pk_verify_restartable

mbedtls_sha256_clone
mbedtls_sha256_finish
mbedtls_sha256_free
mbedtls_sha256_init
mbedtls_sha256_starts
mbedtls_sha256_update

mbedtls_sha512_clone
mbedtls_sha512_finish
mbedtls_sha512_free
mbedtls_sha512_init
mbedtls_sha512_starts
mbedtls_sha512_update
```

Note: the direct dependency on MPI functions is in order to manage DHM
parameters, that are currently stored as a pair of MPIs in the
`mbedtls_ssl_config` structure. (The public API uses byte arrays or a
`mbedtls_dhm_context` structure.)

Note: the direct dependency on ECP APIs is in order to access information;
no crypto operation is done directly via this API, only via the PK and ECDH
APIs.

Note: the direct dependencies on the SHA-2 modules instead of using the
MD layer is for convenience (and perhaps to save some memory as well) and can
easily be replace by use of a more generic API.

Key exchanges and other configuration options
---------------------------------------------

In the file-level analysis below, many things are only used if certain key
exchanges or other configuration options are enabled. This section sums up
those key exchanges and options.

Key exchanges:

- DHE-PSK
- DHE-RSA
- ECDH-ECDSA
- ECDH-RSA
- ECDHE-ECDSA
- ECDHE-PSK
- ECDHE-RSA
- ECJPAKE
- PSK
- RSA
- RSA-PSK

Protocol:

- `MBEDTLS_SSL_PROTO_TLS1_2`
- `MBEDTLS_SSL_PROTO_DTLS`
- `MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL` (excluded from this analysis)

TLS sides:

- `MBEDTLS_SSL_CLI_C`
- `MBEDTLS_SSL_SRV_C`

TLS support modules:

- `MBEDTLS_SSL_CACHE_C`
- `MBEDTLS_SSL_COOKIE_C`
- `MBEDTLS_SSL_TICKET_C`

Cipher modes:

- `MBEDTLS_CIPHER_MODE_CBC`
- `MBEDTLS_CIPHER_NULL_CIPHER`
- `MBEDTLS_GCM_C`
- `MBEDTLS_CCM_C`
- `MBEDTLS_CHACHAPOLY_C`

Hashes:

- `MBEDTLS_MD5_C` (ciphersuites using HMAC-MD5)
- `MBEDTLS_SHA1_C` (ciphersuites using HMAC-SHA1)
- `MBEDTLS_SHA256_C`
- `MBEDTLS_SHA512_C`

Other options:

- `MBEDTLS_X509_CRT_PARSE_C`
- `MBEDTLS_SSL_SESSION_TICKETS`
- `MBEDTLS_SSL_ENCRYPT_THEN_MAC`


File-level analysis
-------------------

The TLS library consists of the following files (excluding TLS 1.3 which is
currently experimental and changing rapidly):

```
library/debug.c
library/net_sockets.c
library/ssl_cache.c
library/ssl_ciphersuites.c
library/ssl_cli.c
library/ssl_cookie.c
library/ssl_msg.c
library/ssl_srv.c
library/ssl_ticket.c
library/ssl_tls.c
```

The file `net_sockets.c` is excluded from further analysis as it's unrelated.

**Note:** Calls to `f_rng` in the files below could also be replaced with
direct calls to the global PSA RNG; however these calls are not included in
the current analysis, since the PSA RNG can already be used by setting it
explicitly.

### `debug.c`

- In `debug_print_pk()`
  call `mbedtls_pk_debug()`
  to print info (or "invalid PK context" on failure)
  if `MBEDTLS_X509_CRT_PARSE_C` is enabled.

- In `mbedtls_debug_print_mpi()`
  call `mbedtls_mpi_print_mpi()`

### `ssl_cache.c`

**Note:** This module is only used server side.

No call to any crypto API function from this file.

_Note :_ in the future, work may be required in order to securely store
session secrets in the cache, but it's outside the scope of this analysis.

### `ssl_ciphersuites.c`

No call to any crypto API function from this file.

### `ssl_cookie.c`

**Note:** this module is only used server-side, only for DTLS.

- In `mbedtls_ssl_cookie_init()` / `mbedtls_ssl_cookie_free()`
  call  `mbedtls_md_init()` / `mbedtls_md_free()`

- In `mbedtls_ssl_cookie_setup()`
  call `mbedtls_md_setup()`, `mbedtls_md_info_from_type()` and `mbedtls_md_hmac_starts()`
  to set up an HMAC key.

- In `ssl_cookie_hmac()`
  call  `mbedtls_md_hmac_reset()`, `mbedtls_md_hmac_update()` and `mbedtls_md_hmac_finish()`

### `ssl_ticket.c`

**Note:** This module is only used server-side.

- In `ssl_ticket_gen_key()`
  call `mbedtls_cipher_setkey()` and `mbedtls_cipher_get_key_bitlen()`

- In `mbedtls_ssl_ticket_setup()`
  call `mbedtls_cipher_info_from_type()` and `mbedtls_cipher_setup()`

- In `mbedtls_ssl_ticket_write()`
  call `mbedtls_cipher_auth_encrypt_ext()`

- In `mbedtls_ssl_ticket_parse()`
  call `mbedtls_cipher_auth_decrypt_ext()`

### `ssl_cli.c`

**Note:** This module is only used client-side.

- In `ssl_write_supported_elliptic_curves_ext()`
  call `mbedtls_ecp_curve_list()` and `mbedtls_ecp_curve_info_from_grp_id()`
  if ECDH, ECDSA or ECJPAKE is enabled

- In `ssl_write_ecjpake_kkpp_ext()`
  call `mbedtls_ecjpake_check()` and `mbedtls_ecjpake_write_round_one()`
  if ECJPAKE is enabled

- In `ssl_parse_supported_point_formats_ext()`
  call `mbedtls_ecjpake_set_point_format()`
  if ECJPAKE is enabled.

- In `ssl_validate_ciphersuite()`
  call `mbedtls_ecjpake_check()`
  if ECJPAKE is enabled.

- In `ssl_parse_ecjpake_kkpp()`
  call `mbedtls_ecjpake_read_round_one()`
  if ECJPAKE is enabled.

- In `ssl_parse_server_dh_params()`
  call `mbedtls_dhm_read_params()` and `mbedtls_dhm_get_bitlen()`
  if DHE-RSA or DHE-PSK key echange is enabled.

- In `ssl_check_server_ecdh_params()`
  call `mbedtls_ecp_curve_info_from_grp_id()`
  if ECDHE-RSA, ECDHE-ECDSA, ECDHE-PSK, ECDH-RSA or ECDH-ECDSA key exchange is enabled.

- In `ssl_parse_server_ecdh_params()`
  call `mbedtls_ecdh_read_params()`
  if ECDHE-RSA, ECDHE-ECDSA or ECDHE-PSK is enabled.

- In `ssl_write_encrypted_pms()`
  call `mbedtls_pk_can_do()` and `mbedtls_pk_encrypt()` on peer's public key
  if RSA or RSA-PSK key exchange enabled.

- In `ssl_get_ecdh_params_from_cert()`
  call `mbedtls_pk_can_do()` and `mbedtls_pk_ec()` and `mbedtls_ecdh_get_params()`
  if ECDH-RSA or ECDH-ECDSA key exchange is enabled
  to import public key of peer's cert to ECDH context.

- In `ssl_parse_server_key_exchange()`
  call `mbedtls_ecjpake_read_round_two()`
  if ECJPAKE is enabled.

- In `ssl_parse_server_key_exchange()`
  call `mbedtls_pk_can_do()` and `mbedtls_pk_verify_restartable()`
  if DHE-RSA, ECDHE-RSA or ECDHE-ECDSA is enabled.
  (Note: the hash is computed by `mbedtls_ssl_get_key_exchange_md_tls1_2()`.)

- In `ssl_write_client_key_exchange()`
  call `mbedtls_dhm_make_public()`, `mbedtls_dhm_get_len()` and `mbedtls_dhm_calc_secret()`
  if DHE-RSA key exchange is enabled.

- In `ssl_write_client_key_exchange()`
  call `mbedtls_ecdh_make_public()` and `mbedtls_ecdh_calc_secret()`
  if ECDHE-RSA, ECDHE-ECDSA, ECDH-RSA or ECDH-ECDSA is enabled.

- In `ssl_write_client_key_exchange()`
  call  `mbedtls_dhm_make_public()` and `mbedtls_dhm_get_len()`
  if DHE-PSK is enabled.

- In `ssl_write_client_key_exchange()`
  call `mbedtls_ecdh_make_public()`
  if ECDHE-PSK is enabled.

- In `ssl_write_client_key_exchange()`
  call `mbedtls_ecjpake_write_round_two()` and `mbedtls_ecjpake_derive_secret()`
  if ECJPAKE is enabled.

- In `ssl_write_certificate_verify()`
  call `mbedtls_pk_can_do()` and `mbedtls_pk_sign_restartable()`
  if RSA, DHE-RSA, ECDH-RSA, ECDHE-RSA, ECDH-ECDSA or ECDHE-ECDSA is enabled.
  (Note: the hash is computed by `calc_verify()`.)

### `ssl_srv.c`

**Note:** This module is only used server-side.

- In `ssl_parse_supported_elliptic_curves()`
  call `mbedtls_ecp_curve_info_from_tls_id()`
  if ECDH, ECDSA or ECJPAKE is enabled.

- In `ssl_parse_supported_point_formats()`
  call `mbedtls_ecjpake_set_point_format()`
  if ECJPAKE is enabled.

- In `ssl_parse_ecjpake_kkpp()`
  call `mbedtls_ecjpake_check()` and  `mbedtls_ecjpake_read_round_one()`
  if ECJPAKE is enabled.

- In `ssl_check_key_curve()` to get group ID
  call `mbedtls_pk_ec()`
  if certificates and ECDSA are enabled.

- In `ssl_pick_cert()`
  call `mbedtls_pk_can_do()`
  if certificates are enabled.

- In `ssl_write_encrypt_then_mac_ext()`
  call `mbedtls_cipher_info_from_type()` on ciphersuite info
  if EtM is enabled

- In `ssl_write_ecjpake_kkpp_ext()`
  call `mbedtls_ecjpake_write_round_one()`
  if ECJPAKE is enabled.

- In `ssl_get_ecdh_params_from_cert()`
  call `mbedtls_pk_can_do()`, `mbedtls_pk_ec()` and `mbedtls_ecdh_get_params()`
  if ECDH-RSA or ECDH-ECDSA is enabled,
  in order to import own private key to ecdh context.

- In `ssl_prepare_server_key_exchange()`
  call `mbedtls_ecjpake_write_round_two()`
  if ECJPAKE is enabled.

- In `ssl_prepare_server_key_exchange()`
  call `mbedtls_dhm_set_group()`, `mbedtls_dhm_make_params()` and `mbedtls_dhm_get_len()`
  if DHE-RSA or DHE-PSK key exchange is enabled.

- In `ssl_prepare_server_key_exchange()`
  call `mbedtls_ecdh_setup()` and `mbedtls_ecdh_make_params()`
  if ECDHE-RSA, ECDHE-ECDSA or ECDHE-PSK is enabled.

- In `ssl_prepare_server_key_exchange()`
  call `mbedtls_pk_sign()` from `ssl_prepare_server_key_exchange()`
  if DHE-RSA, ECDHE-RSA or ECDHE-ECDSA is enabled.

- In `ssl_parse_client_dh_public()`
  call `mbedtls_dhm_read_public()`
  if DHE-RSA or DHE-PSK is enabled.

- In `ssl_decrypt_encrypted_pms()`
  call `mbedtls_pk_get_len()`, `mbedtls_pk_can_do()` and `mbedtls_pk_decrypt()`
  if RSA or RSA-PSK key exchange is enabled.

- In `ssl_parse_client_key_exchange()`
  call `mbedtls_dhm_calc_secret()`
  if DHE-RSA enabled.
  (Note: `ssl_parse_client_dh_public()` called first.)

- In `ssl_parse_client_key_exchange()`
  call `mbedtls_ecdh_read_public()` and `mbedtls_ecdh_calc_secret()`
  if ECDHE-RSA, ECDHE-ECDSA, ECDH-RSA or ECDH-ECDSA enabled.

- In `ssl_parse_client_key_exchange()`
  call `mbedtls_ecdh_read_public()`
  if ECDHE-PSK enabled.
  (Note: calling `mbedtls_ssl_psk_derive_premaster()` afterwards.)

- In `ssl_parse_client_key_exchange()`
  call `mbedtls_ecjpake_read_round_two()` and `mbedtls_ecjpake_derive_secret()`
  if ECJPAKE enabled.

- In `ssl_parse_certificate_verify()`
  call `mbedtls_pk_can_do()` and `mbedtls_pk_verify()`
  if RSA, DHE-RSA, ECDH-RSA, ECDHE-RSA, ECDH-ECDSA or ECDHE-ECDSA enabled.

### `ssl_tls.c`

**Note:** This module is used both server-side and client-side.

- In `tls_prf_generic()`
  call `mbedtls_md_init()`, `mbedtls_md_info_from_type()`, `mbedtls_md_get_size()`, `mbedtls_md_setup()`, `mbedtls_md_hmac_starts()`, `mbedtls_md_hmac_update()`, `mbedtls_md_hmac_finish()`, `mbedtls_md_hmac_reset()` and `mbedtls_md_free()`

- In `mbedtls_ssl_derive_keys()`
  call `mbedtls_cipher_info_from_type()`, `mbedtls_cipher_setup_psa()` or `mbedtls_cipher_setup()`, `mbedtls_cipher_setkey()`, and `mbedtls_cipher_set_padding_mode()`

- In `mbedtls_ssl_derive_keys()`.
  call `mbedtls_md_info_from_type()`, `mbedtls_md_setup()`, `mbedtls_md_get_size()` and `mbedtls_md_hmac_starts()`
  Note: should be only if CBC/NULL ciphersuites enabled, but is currently unconditional.

- In `ssl_calc_verify_tls_sha256()`
  call `mbedtls_sha256_init()` `mbedtls_sha256_clone()` `mbedtls_sha256_finish()` `mbedtls_sha256_free()`
  if SHA256 is enabled.

- In `ssl_calc_verify_tls_sha384()`
  call `mbedtls_sha512_init()` `mbedtls_sha512_clone()` `mbedtls_sha512_finish()` `mbedtls_sha512_free()`
  if SHA512 is enabled.

- In `mbedtls_ssl_psk_derive_premaster()`
  call `mbedtls_dhm_calc_secret()`
  if DHE-PSK is enabled.

- In `mbedtls_ssl_psk_derive_premaster()`
  call `mbedtls_ecdh_calc_secret()`
  if ECDHE-PSK is enabled.

- In `ssl_encrypt_buf()`
  call `mbedtls_cipher_get_cipher_mode()` `mbedtls_md_hmac_update()` `mbedtls_md_hmac_finish()` `mbedtls_md_hmac_reset()` `mbedtls_cipher_crypt()`
  if CBC or NULL is enabled.

- In `ssl_encrypt_buf()`
  call `mbedtls_cipher_get_cipher_mode()`, `mbedtls_cipher_auth_encrypt()`
  if GCM, CCM or CHACHAPOLY is enabled.

- In `ssl_decrypt_buf()`
  call `mbedtls_cipher_get_cipher_mode()` `mbedtls_md_hmac_update()` `mbedtls_md_hmac_finish()` `mbedtls_md_hmac_reset()` `mbedtls_cipher_crypt()`
  if CBC and Encrypt-then-Mac
are enabled.

- In `mbedtls_ssl_cf_hmac()`
  call `mbedtls_md_clone()`
  if CBC or NULL is enabled.

- In `ssl_decrypt_buf()`
  call `mbedtls_cipher_get_cipher_mode()`, `mbedtls_cipher_auth_decrypt()`
  if GCM, CCM or CHACHAPOLY is enabled.

- In `mbedtls_ssl_parse_certificate()`
  call `mbedtls_pk_can_do()` and `mbedtls_pk_ec()`
  to get and check group ID.

- In `mbedtls_ssl_reset_checksum()`.
  call `mbedtls_sha256_starts()` `mbedtls_sha512_starts()`

- In `ssl_update_checksum_start()`.
  call `mbedtls_sha256_update()` `mbedtls_sha512_update()`

- In `ssl_update_checksum_sha256()`
  call `mbedtls_sha256_update()`
  if SHA256 is enabled.

- In `ssl_update_checksum_sha512()`
  call `mbedtls_sha512_update()`
  if SHA512 is enabled.

- In `ssl_calc_finished_tls_sha256()`
  call `mbedtls_sha256_init()` `mbedtls_sha256_clone()` `mbedtls_sha256_finish()` `mbedtls_sha256_free()`
  if SHA256 is enabled.

- In `ssl_calc_finished_tls_sha512()`
  call `mbedtls_sha512_init()` `mbedtls_sha512_clone()` `mbedtls_sha512_finish()` `mbedtls_sha512_free()`
  if SHA512 is enabled.

- In `ssl_handshake_params_init()`.
  call `mbedtls_sha256_init()` `mbedtls_sha256_starts()` `mbedtls_sha512_init()` `mbedtls_sha512_starts()` `mbedtls_dhm_init()` `mbedtls_ecdh_init()` `mbedtls_ecjpake_init()`

- In `ssl_transform_init()`.
  call `mbedtls_cipher_init()` `mbedtls_md_init()`

- In `mbedtls_ssl_set_hs_ecjpake_password()`
  call `mbedtls_ecjpake_setup()`
  if ECJPAKE is enabled.

- In `mbedtls_ssl_conf_dh_param_bin()`
  call `mbedtls_mpi_read_binary()` and `mbedtls_mpi_free()`
  if DHM and SRV are enabled.

- In `mbedtls_ssl_conf_dh_param_ctx()`
  call `mbedtls_dhm_get_value()` and `mbedtls_mpi_free()`
  if DHM and SRV are enabled.

- In `mbedtls_ssl_get_record_expansion()`.
  call `mbedtls_cipher_get_cipher_mode()` and `mbedtls_cipher_get_block_size()`

- In `mbedtls_ssl_transform_free()`.
  call `mbedtls_cipher_free()` and `mbedtls_md_free()`

- In `mbedtls_ssl_handshake_free()`.
  call `mbedtls_sha256_free()` `mbedtls_sha512_free()` `mbedtls_dhm_free()` `mbedtls_ecdh_free()` `mbedtls_ecjpake_free()`

- In `mbedtls_ssl_config_free()`
  call `mbedtls_mpi_free()`
  if DHM is enabled.

- In `mbedtls_ssl_sig_from_pk()`.
  call `mbedtls_pk_can_do()`

- In  `mbedtls_ssl_get_key_exchange_md_tls1_2()`
  call  `mbedtls_md_info_from_type()` `mbedtls_md_get_size()` `mbedtls_md_init()` `mbedtls_md_setup()` `mbedtls_md_starts()` `mbedtls_md_update()` `mbedtls_md_update()` `mbedtls_md_finish()` `mbedtls_md_free()`
