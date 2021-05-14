Remove the SSL API mbedtls_ssl_get_session_pointer()
-----------------------------------------------------------------

This affects two classes of users:

1. Users who manually inspect parts of the current session through
   direct structure field access.

2. Users of session resumption who query the current session
   via `mbedtls_ssl_get_session_pointer()` prior to saving or exporting
   it via `mbedtls_ssl_session_copy()` or `mbedtls_ssl_session_save()`,
   respectively.

Migration paths:

1. Mbed TLS 3.0 does not offer a migration path for the usecase 1: Like many
   other Mbed TLS structures, the structure of `mbedtls_ssl_session` is no
   longer part of the public API in Mbed TLS 3.0, and direct structure field
   access is no longer supported. Please see the corresponding migration guide.

2. Users should replace calls to `mbedtls_ssl_get_session_pointer()` by
   calls to `mbedtls_ssl_get_session()` as demonstrated in the example
   program `programs/ssl/ssl_client2.c`.
