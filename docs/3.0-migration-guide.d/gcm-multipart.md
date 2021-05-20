GCM multipart interface: application changes
--------------------------------------------

The GCM module now supports arbitrary chunked input in the multipart interface.

For applications using GCM for multipart operations, this means the following changes:

* `mbedtls_gcm_starts()` now only sets the mode and the nonce (IV). Call the new function `mbedtls_gcm_update_ad()` to pass the associated data.
* The current implementation has a limitation that `mbedtls_gcm_update_ad()` may only be called once. This limitation will be lifted shortly; watch https://github.com/ARMmbed/mbedtls/issues/4351 for updates.
* `mbedtls_gcm_update()` now takes an extra parameter to indicate the actual output length. In Mbed TLS 2.x, applications had to pass inputs consisting of whole 16-byte blocks except for the last block (this limitation has been lifted). In this case:
    * As long as the input remains block-aligned, the output length is exactly the input length, as before.
    * If the length of the last input is not a multiple of 16, alternative implementations may return the last partial block in the call to `mbedtls_gcm_finish()` instead of returning it in the last call to `mbedtls_gcm_update()`.
* `mbedtls_gcm_finish()` now takes an extra output buffer for the last partial block. This is needed for alternative implementations that can only process a whole block at a time.

Applications using one-shot GCM or using GCM via the `mbedtls_cipher_xxx` or `psa_aead_xxx` interfaces do not require any changes.
