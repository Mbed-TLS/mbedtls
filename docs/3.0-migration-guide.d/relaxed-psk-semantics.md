Relaxed semantics for PSK configuration
-----------------------------------------------------------------

This affects users which call the PSK configuration APIs
`mbedtlsl_ssl_conf_psk()` and `mbedtls_ssl_conf_psk_opaque()`
multiple times on the same SSL configuration.

In Mbed TLS 2.x, users would observe later calls overwriting
the effect of earlier calls, with the prevailing PSK being
the one that has been configured last.

To achieve equivalent functionality when migrating to Mbed TLS 3.0,
users calling `mbedtls_ssl_conf_[opaque_]psk()` multiple times should
remove all but the last call, so that only one call to _either_
`mbedtls_ssl_conf_psk()` _or_ `mbedtls_ssl_conf_psk_opaque()`
remains.

However, if the _intent_ of the multiple calls to
`mbedtls_ssl_conf_[opaque_]psk()` was to offer multiple PSKs, then
users should _keep_ all calls and only check for the expected
non-fatal failure code `MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE`
indicating that no more PSKs could be buffered by the
implementation.
