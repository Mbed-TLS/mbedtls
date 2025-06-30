## OID module

The compilation option `MBEDTLS_OID_C` no longer exists. OID tables are included in the build automatically as needed for parsing and writing X.509 data.

Mbed TLS no longer offers interfaces to look up values by OID or OID by enum values (`mbedtls_oid_get_<thing>()` and `mbedtls_oid_get_oid_by_<thing>()`).

The header `<mbedtls/oid.h>` now only provides functions to convert between binary and dotted string OID representations. These functions are now part of `libmbedx509` rather than the crypto library. The function `mbedtls_oid_get_numeric_string()` is guarded by `MBEDTLS_X509_USE_C`, and `mbedtls_oid_from_numeric_string()` by `MBEDTLS_X509_CREATE_C`. The header also still defines macros for OID strings that are relevant to X.509.
