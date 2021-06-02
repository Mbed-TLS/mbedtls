Combine the `MBEDTLS_SSL_CID_PADDING_GRANULARITY` and `MBEDTLS_SSL_TLS1_3_PADDING_GRANULARITY` options
--

This change affects users who modified the default `config.h` padding granularity
settings, i.e. enabled at least one of the options.

The `config.h` options `MBEDTLS_SSL_CID_PADDING_GRANULARITY` and
`MBEDTLS_SSL_TLS1_3_PADDING_GRANULARITY` were combined into one option because
they used exactly the same padding mechanism and hence their respective padding
granularities can be used in exactly the same way. This change simplifies the
code maintenance.

The new single option `MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY` can be used
for both DTLS-CID and TLS 1.3.
