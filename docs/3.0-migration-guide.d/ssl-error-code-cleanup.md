Removal of some SSL error codes
-----------------------------------------------------------------

This affects users manually checking for the following error codes:
- `MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED`
- `MBEDTLS_ERR_SSL_INVALID_VERIFY_HASH`
- `MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE`

Migration paths:
- `MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED` and `MBEDTLS_ERR_SSL_INVALID_VERIFY_HASH`
  should never be returned from Mbed TLS, and there is no need to check for it.
  Users should simply remove manual checks for those codes, and let the Mbed TLS
  team know if -- contrary to the team's understanding -- there is in fact a situation
  where one of them was ever returned.
- `MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE` has been removed, and
  `MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL` is returned instead if the user's own certificate
  is too large to fit into the output buffers. Users should check for
  `MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL` instead, and potentially compare the size of their
  own certificate against the configured size of the output buffer to understand if
  the error is due to an overly large certificate.
