GCM interface changes: impact for alternative implementations
-------------------------------------------------------------

The GCM multipart interface has changed as described in [“GCM multipart interface: application changes”](#gcm-multipart-interface:-application-changes). The consequences for an alternative implementation of GCM (`MBEDTLS_GCM_ALT`) are as follows:

* `mbedtls_gcm_starts()` now only sets the mode and the nonce (IV). The new function `mbedtls_gcm_update_ad()` receives the associated data. It may be called multiple times.
* `mbedtls_gcm_update()` now allows arbitrary-length inputs, takes an extra parameter to indicate the actual output length. Alternative implementations may choose between two modes:
    * Always return the partial output immediately, even if it does not consist of a whole number of blocks.
    * Buffer the data for the last partial block, to be returned in the next call to `mbedtls_gcm_update()` or `mbedtls_gcm_finish()`.
* `mbedtls_gcm_finish()` now takes an extra output buffer for the last partial block if needed.
