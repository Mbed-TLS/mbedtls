Remove the config option MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION
--------------------------------------------------------------------------

This change does not affect users of the default configuration; it only affect
users who enable this option.

The X.509 standard says that implementations must reject critical extensions that
they don't recognize, and this is what Mbed TLS does by default. This option
allowed to continue parsing those certificates but didn't provide a convenient
way to handle those extensions.

The migration path from that option is to use the
`mbedtls_x509_crt_parse_der_with_ext_cb()` function which is functionally
equivalent to `mbedtls_x509_crt_parse_der()`, and/or
`mbedtls_x509_crt_parse_der_nocopy()` but it calls the callback with every
unsupported certificate extension and additionally the "certificate policies"
extension if it contains any unsupported certificate policies.
