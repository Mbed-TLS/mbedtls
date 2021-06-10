Remove `MBEDTLS_X509_CHECK_*_KEY_USAGE` options from `config.h`
-------------------------------------------------------------------

This change affects users who have chosen the configuration options to disable the
library's verification of the `keyUsage` and `extendedKeyUsage` fields of x509
certificates.

The `MBEDTLS_X509_CHECK_KEY_USAGE` and `MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE`
configuration options are removed and the X509 code now behaves as if they were
always enabled. It is consequently not possible anymore to disable at compile
time the verification of the `keyUsage` and `extendedKeyUsage` fields of X509
certificates.

The verification of the `keyUsage` and `extendedKeyUsage` fields is important,
disabling it can cause security issues and it is thus not recommended. If the
verification is for some reason undesirable, it can still be disabled by means
of the verification callback function passed to `mbedtls_x509_crt_verify()` (see
the documentation of this function for more information).
