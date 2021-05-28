Remove the `MBEDTLS_X509_ALLOW_EXTENSIONS_NON_V3` option
--

This change does not affect users who are working with current V3 X.509
certificates.

This change makes the pre-V3 X.509 certificates both with or without optional
extensions obsolete.

If you are working with the pre-V3 certificates you need to switch to the
current ones.
