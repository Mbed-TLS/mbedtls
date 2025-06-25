## Removal of deprecated functions

### Removal of deprecated X.509 functions

The deprecated function `mbedtls_x509write_crt_set_serial()` has been removed. The function was superseded by `mbedtls_x509write_crt_set_serial_raw()`.

### Removal of deprecated SSL functions

The deprecated function `mbedtls_ssl_conf_curves()` has been removed.
The function was superseded by `mbedtls_ssl_conf_groups()`.

### Removal of `compat-2.x.h`

The header `compat-2.x.h`, containing some definitions for backward compatibility with Mbed TLS 2.x, has been removed.
