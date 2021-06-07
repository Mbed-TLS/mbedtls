Remove the `MBEDTLS_X509_ALLOW_EXTENSIONS_NON_V3` option
--

This change does not affect users who were using the default configuration, as
this option was already disabled by default. Also, it does not affect users who
are working with current V3 X.509 certificates.

Extensions were added in V3 of the X.509 specification, so pre-V3 certificates
containing extensions were never compliant. Mbed TLS now rejects them with a
parsing error in all configurations, as it did previously in the default
configuration.

If you are working with the pre-V3 certificates you need to switch to the
current ones.
