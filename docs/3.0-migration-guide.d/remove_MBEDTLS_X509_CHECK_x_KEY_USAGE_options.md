Remove `MBEDTLS_X509_CHECK_*_KEY_USAGE` options from `config.h`
--

This change affects users who have chosen the compilation time options to disable
the library's verification of the `keyUsage` and `extendedKeyUsage` fields of an x509
certificate.

The change is to remove MBEDTLS_X509_CHECK_KEY_USAGE and
MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE from the configuration.

After the change the options are removed and the compilation is done in a way that
the verification of the key usage fields is allways enabled by default.

This verification is an important step and disabling it can cause security issues.
If the verification is for some reason undesirable it can still be disabled at
a runtime with even more flexibility by using the callback parameter in
`mbedtls_x509_crt_verify()`.

For example the user can disable the verification by using the callback which
clears the corresponding flags when they've been set.
