Remove MBEDTLS_SSL_RECORD_CHECKING option and enable its action by default
--------------------------------------------------------------------------

This change does not affects users who use the default config.h, as the
option MBEDTLS_SSL_RECORD_CHECKING was already on by default.

This option was added only to controls compilation of one function
(mbedtls_ssl_check_record()) used in DTLS to check a buffer's validity and
authenticity. Switching it off poses a security risk.

For users who changed the default setting of the option there is no real path
of migration.

