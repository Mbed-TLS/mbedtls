Modified semantics of mbedtls_ssl_{get,set}_session()
-----------------------------------------------------------------

This affects users who call `mbedtls_ssl_get_session()` or
`mbedtls_ssl_session_set()` multiple times on the same SSL context
representing an established TLS 1.2 connection.
Those users will now observe the second call to fail with
`MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE`.

Migration path:
- Exporting the same TLS 1.2 connection multiple times via
  `mbedtls_ssl_get_session()` leads to multiple copies of
  the same session. This use of `mbedtls_ssl_get_session()`
  is discouraged, and the following should be considered:
  * If the various session copies are later loaded into
    fresh SSL contexts via `mbedtls_ssl_set_session()`,
    export via `mbedtls_ssl_get_session()` only once and
    load the same session into different contexts via
    `mbedtls_ssl_set_session()`. Since `mbedtls_ssl_set_session()`
    makes a copy of the session that's being loaded, this
    is functionally equivalent.
  * If the various session copies are later serialized
    via `mbedtls_ssl_session_save()`, export and serialize
    the session only once via `mbedtls_ssl_get_session()` and
    `mbedtls_ssl_session_save()` and make copies of the raw
    data instead.
- Calling `mbedtls_ssl_set_session()` multiple times in Mbed TLS 2.x
  is not useful since subsequent calls overwrite the effect of previous
  calls. Applications achieve equivalent functional behaviour by
  issuing only the very last call to `mbedtls_ssl_set_session()`.
