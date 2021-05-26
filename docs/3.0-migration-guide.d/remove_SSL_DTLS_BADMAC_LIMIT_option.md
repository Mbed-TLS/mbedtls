Remove MBEDTLS_SSL_DTLS_BADMAC_LIMIT option
-------------------------------------------

This change does not affect users who used the default `config.h`, as the option
MBEDTLS_SSL_DTLS_BADMAC_LIMIT was already on by default.

This option was a trade-off between functionality and code size: it allowed
users who didn't need that feature to avoid paying the cost in code size, by
disabling it.

This option is no longer present, but its functionality is now always enabled.
