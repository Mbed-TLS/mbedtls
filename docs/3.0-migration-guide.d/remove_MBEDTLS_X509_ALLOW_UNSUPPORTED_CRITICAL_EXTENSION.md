Remove the X509 parser sensitivity control for an unknown critical extension from config.h
------------------------------------------------------------------------------------------

It affects users who use the `MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION`
option which if set, allowed the X509 parser to parse an X509 certificate
even when it encountered an unknown critical extension.

The migration path from that option is to use the
`mbedtls_x509_crt_parse_der_with_ext_cb()` function which is functionally
equivalent to `mbedtls_x509_crt_parse_der()`, and/or
`mbedtls_x509_crt_parse_der_nocopy()` but it calls the callback with every
unsupported certificate extension and additionally the "certificate policies"
extension if it contains any unsupported certificate policies.
