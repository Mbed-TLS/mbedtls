Session Cache API Change
-----------------------------------------------------------------

This affects users who use `mbedtls_ssl_conf_session_cache()`
to configure a custom session cache implementation different
from the one Mbed TLS implements in `library/ssl_cache.c`.

Those users will need to modify the API of their session cache
implementation to that of a key-value store with keys being
session IDs and values being instances of `mbedtls_ssl_session`:

```
typedef int mbedtls_ssl_cache_get_t( void *data,
                                     unsigned char const *session_id,
                                     size_t session_id_len,
                                     mbedtls_ssl_session *session );
typedef int mbedtls_ssl_cache_set_t( void *data,
                                     unsigned char const *session_id,
                                     size_t session_id_len,
                                     const mbedtls_ssl_session *session );
```

Since the structure of `mbedtls_ssl_session` is no longer public from 3.0
onwards, portable session cache implementations must not access fields of
`mbedtls_ssl_session`. See the corresponding migration guide. Users that
find themselves unable to migrate their session cache functionality without
accessing fields of `mbedtls_ssl_session` should describe their usecase
on the Mbed TLS mailing list.
