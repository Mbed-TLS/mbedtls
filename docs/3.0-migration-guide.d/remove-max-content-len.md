Remove the `MBEDTLS_SSL_MAX_CONTENT_LEN` configuration option
-------------------------------------------------------------

This affects users who use the `MBEDTLS_SSL_MAX_CONTENT_LEN` option to
set the maximum length of incoming and outgoing plaintext fragments,
which can save memory by reducing the size of the TLS I/O buffers.

This option is replaced by the more fine-grained options
`MBEDTLS_SSL_IN_CONTENT_LEN` and `MBEDTLS_SSL_OUT_CONTENT_LEN` that set
the maximum incoming and outgoing plaintext fragment lengths, respectively.
